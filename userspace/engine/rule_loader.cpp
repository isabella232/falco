/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "rule_loader.h"
#include "falco_common.h"
#include <sstream>
#include <algorithm>

using namespace std;

// todo: create only one version of this
static string s_syscall_source = "syscall";

// todo: add YAML context too
void rule_loader::add_error(std::string e)
{
    m_errors.push_back(e);
}

void rule_loader::add_warning(std::string e)
{
    m_warnings.push_back(e);
}

std::vector<std::string>& rule_loader::errors()
{
    return m_errors;
}

std::vector<std::string>& rule_loader::warnings()
{
    return m_warnings;
}

void rule_loader::clear()
{
    m_required_plugin_versions.clear();
}

bool rule_loader::load(const std::string &rules_content)
{  
    // todo: grab these from parameters
    m_min_priority = falco_common::priority_type::PRIORITY_DEBUG;

    // todo: which of these is maintained at the next call to load()?
    m_last_id = 0;
    m_errors.clear();
    m_warnings.clear();
    m_macros.clear();
    m_lists.clear();
    m_rules.clear();

    // load yaml document
    YAML::Node document;
    try
    {
        document = YAML::Load(rules_content);
    }
    catch(const std::exception& e)
	{
        // todo: should we customize err msg?
        add_error(e.what());
		return false;
	}

    if(!document.IsDefined() || !document.IsSequence())
    {
        add_error("rules content is not yaml array of objects");
        return false;
    }

    // iterate through each sequence item
    for(const YAML::Node& item : document)
    {
        // todo: save original text context
        if (!item.IsMap())
        {
            add_error("unexpected element of type " + to_string(item.Type()) // todo: print the type with proper naming
                + ", each element should be a yaml associative array");
            return false;
        }

        // todo: add logic here (ensure that engine/plugin requirements are before rule/macro/lists, skip failed macros with warning...)
        bool parsed = false;
        if (!parse_required_engine_version(parsed, item)
            || !parse_required_plugin_versions(parsed, item)
            || !parse_macro(parsed, item)
            || !parse_list(parsed, item)
            || !parse_rule(parsed, item))
        {
            return false;
        }   
        if (!parsed)
        {
            add_warning("unknown top level object: xxx"); // todo: print the object in some way
        }
    }

    return true;
}

bool rule_loader::parse_required_engine_version(bool& parsed, const YAML::Node& item)
{
    if (!parsed && item["required_engine_version"].IsDefined())
    {
        parsed = true;
        uint32_t ver = 0;
        if (!YAML::convert<uint32_t>::decode(item["required_engine_version"], ver))
        {
            add_error("value of required_engine_version must be a number");
            return false;
        }
        // todo: do version check towards falco_engine
    }
    return true;
}

bool rule_loader::parse_required_plugin_versions(bool& parsed, const YAML::Node& item)
{
    if (!parsed && item["required_plugin_versions"].IsDefined())
    {
        parsed = true;
        if (!item["required_plugin_versions"].IsSequence())
        {
            add_error("value of required_plugin_versions must be a sequence");
            return false;
        }
        for(const YAML::Node& plugin : item["required_plugin_versions"])
        {
            string name, version;
            if(!plugin["name"].IsDefined()
                || !YAML::convert<string>::decode(plugin["name"], name)
                || name.empty())
            {
                add_error("required_plugin_versions item must have name property");
                return false;
            }
            if(!plugin["version"].IsDefined()
                || !YAML::convert<string>::decode(plugin["version"], version)
                || version.empty())
            {
                add_error("required_plugin_versions item must have version property");
                return false;
            }
            // todo: handle the case of multiple definitions
            m_required_plugin_versions[name] = version;
        }
        
        // todo: do version check towards falco_engine
    }
    return true;
}

bool rule_loader::parse_macro(bool& parsed, const YAML::Node& item)
{
    if (!parsed && item["macro"].IsDefined())
    {
        parsed = true;
        rule_macro m;
        if (!YAML::convert<string>::decode(item["macro"], m.name)
                || m.name.empty())
        {
            add_error("macro name is empty");
            return false;
        }

        if (!item["condition"].IsDefined()
                || !YAML::convert<string>::decode(item["condition"], m.condition)
                || m.condition.empty())
        {
            add_error("macro '" + m.name + "' has empty condition");
            return false;
        }

        if (!item["source"].IsDefined()
                || !YAML::convert<string>::decode(item["source"], m.source)
                || m.source.empty())
        {
            m.source = s_syscall_source;
        }

        if (false) // todo: check if macro source is valid using the engine (falco_rules.is_source_valid)
        {
            add_warning("macro '" + m.name
                + "': warning (unknown-source): unknown source '"
                + m.source + "', skipping");
            return true;
        }

        auto prev = find_macro(m.name);
        if (prev && prev->source != m.source)
        {
            add_error("macro '" + m.name + "' redefined with another source");
            return false;
        }

        bool append = false;
        if(item["append"].IsDefined()
                && !YAML::convert<bool>::decode(item["append"], append))
        {
            // todo: print a warning failed decoding of 'append'
        }

        if (append)
        {
            if (!prev)
            {
                add_error("macro '" + m.name 
                    + "' has 'append' key but no macro by that name already exists");
                return false;
            }
            // todo(jasondellaluce): consider doing AST concatenation in the future
            prev->condition += " ";
            prev->condition += m.condition;
            prev->id_override = m_last_id++;
            // todo: concatenate YAML context too
        }
        else
        {
            // store macro
            if (prev)
            {
                prev->condition = m.condition;
                prev->id_override = m_last_id++;
            }
            else
            {
                m.id = m_last_id++;
                m.id_override = m.id;
                add_macro(m);
            }
        }
    }
    return true;
}

bool rule_loader::parse_list(bool& parsed, const YAML::Node& item)
{
    if (!parsed && item["list"].IsDefined())
    {
        parsed = true;
        rule_list l;
        if (!YAML::convert<string>::decode(item["list"], l.name)
                || l.name.empty())
        {
            add_error("list name is empty");
            return false;
        }
        if (!item["items"].IsDefined() || !item["items"].IsSequence())
        {
            add_error("list items are not defined");
            return false;
        }

        string value;
        for(const YAML::Node& v : item["items"])
        {
            if (!v.IsScalar() || !YAML::convert<string>::decode(v, value))
            {
                add_error("can't decode list value");
                return false;
            }
            l.values.push_back(value);
        }

        bool append = false;
        if(item["append"].IsDefined()
                && !YAML::convert<bool>::decode(item["append"], append))
        {
            // todo: print a warning failed decoding of 'append'
        }

        auto prev = find_list(l.name);
        if (append)
        {
            if (!prev)
            {
                add_error("list '" + l.name 
                    + "' has 'append' key but no list by that name already exists");
                return false;
            }
            // todo(jasondellaluce): consider doing AST concatenation in the future
            prev->values.insert(prev->values.end(), l.values.begin(), l.values.end());
            prev->id_override = m_last_id++;
            // todo: concatenate YAML context too
        }
        else
        {
            // store list
            if (prev)
            {
                prev->id_override = m_last_id++;
                prev->values = l.values;
            }
            else
            {
                l.id = m_last_id++;
                l.id_override = l.id;
                add_list(l);
            }
        }

    }
    return true;
}

bool rule_loader::parse_rule(bool& parsed, const YAML::Node& item)
{
    if (!parsed && item["rule"].IsDefined())
    {
        parsed = true;
        rule r;
        if (!YAML::convert<string>::decode(item["rule"], r.name)
                || r.name.empty())
        {
            add_error("rule name is empty");
            return false;
        }

        r.skip_if_unknown_filter = false;
        if(item["skip-if-unknown-filter"].IsDefined()
                && !YAML::convert<bool>::decode(
                    item["skip-if-unknown-filter"], r.skip_if_unknown_filter))
        {
            // todo: print a warning failed decoding of 'append'
        }

        if (!item["source"].IsDefined()
                || !YAML::convert<string>::decode(item["source"], r.source)
                || r.source.empty())
        {
            r.source = s_syscall_source;
        }
        if (false) // todo: check if rule source is valid using the engine (falco_rules.is_source_valid)
        {
            add_warning("rule '" + r.name
                + "': warning (unknown-source): unknown source '"
                + r.source + "', skipping");
            return true;
        }

        auto prev = find_rule(r.name);
        if (prev && prev->source != r.source)
        {
            add_error("rule '" + r.name + "' redefined with another source");
            return false;
        }

        bool append = false;
        if(item["append"].IsDefined()
                && !YAML::convert<bool>::decode(item["append"], append))
        {
            // todo: print a warning failed decoding of 'append'
        }

        if (item["exceptions"].IsDefined())
        {
            // todo: implement exceptions validation
        }

        if (append)
        {
            if (!prev)
            {
                add_error("rule '" + r.name 
                    + "' has 'append' key but no rule by that name already exists");
                return false;
            }
            if (!item["condition"].IsDefined() && !item["exceptions"].IsDefined())
            {
                add_error("rule '" + r.name 
                    + "' appended rule must have 'exceptions' or 'condition' property");
            }
            
            if (item["exceptions"].IsDefined())
            {
                // todo: implement exception appending
            }

            if (item["condition"].IsDefined())
            {
                prev->condition += " ";
                prev->condition += r.condition;
            }

            prev->id_override = m_last_id++;
            // todo: concatenate context too
        }
        else
        {
            bool has_definitions = item["condition"].IsDefined()
                && item["output"].IsDefined()
                && item["desc"].IsDefined()
                && item["priority"].IsDefined();

            // check for enabled-only rule definitions
            if (!has_definitions)
            {
                if (!item["enabled"].IsDefined())
                {
                    add_error("rule '" + r.name 
                        + "' is missing one of 'condition', 'output', 'desc', or 'priority'");
                    return false;
                }
                if (!prev)
                {
                    add_error("rule '" + r.name 
                        + "' has 'enabled' key but no rule by that name already exists");
                    return false;
                }
                if(!YAML::convert<bool>::decode(item["enabled"], prev->enabled))
                {
                    // todo: print a warning failed decoding of 'enabled'
                }
            }
            else
            {
                string priority;
                if(!YAML::convert<string>::decode(item["priority"], priority)
                        || !parse_priority_name(priority, r.priority))
                {
                    add_error("rule '" + r.name + "' invalid priority");
                    return false;
                }
                r.enabled = true;
                r.skipped = r.priority <= m_min_priority; // note: we fixed a bug, because priority could not be overriden before
                if(!YAML::convert<string>::decode(item["condition"], r.condition))
                {
                    // todo: print a warning failed decoding
                }
                if(!YAML::convert<string>::decode(item["desc"], r.description))
                {
                    // todo: print a warning failed decoding
                }
                // todo: trim output
                if(!YAML::convert<string>::decode(item["output"], r.output))
                {
                    // todo: print a warning failed decoding
                }
                // todo: trim output
                if(item["enabled"].IsDefined() && !YAML::convert<bool>::decode(item["enabled"], r.enabled))
                {
                    // todo: print a warning failed decoding
                }
                if (item["tags"].IsDefined())
                {
                    string value;
                    for(const YAML::Node& v : item["tags"])
                    {
                        if (!v.IsScalar() || !YAML::convert<string>::decode(v, value))
                        {
                            add_error("rule '" + r.name + "' has an invalid tag'");
                            return false;
                        }
                        r.tags.insert(value);
                    }
                }

                // store rule
                if (prev)
                {
                    auto prev_id = prev->id;
                    r.id = prev->id;
                    r.id_override = m_last_id++;
                    *prev = r;
                }
                else
                {
                    r.id = m_last_id++;
                    r.id_override = r.id;
                    add_rule(r);
                }
            }
        }
    }
    return true;
}

// todo: move this in a common place
bool rule_loader::parse_priority_name(string v, falco_common::priority_type& out)
{
    std::transform(v.begin(), v.end(), v.begin(),
        [](unsigned char c){ return std::tolower(c); });
    if(v == "emergency")
    {
        out = falco_common::priority_type::PRIORITY_EMERGENCY;
    }
	else if(v == "alert")
    {
        out = falco_common::priority_type::PRIORITY_ALERT;
    }
	else if(v == "critical")
    {
        out = falco_common::priority_type::PRIORITY_CRITICAL;
    }
	else if(v == "error")
    {
        out = falco_common::priority_type::PRIORITY_ERROR;
    }
	else if(v == "warning")
    {
        out = falco_common::priority_type::PRIORITY_WARNING;
    }
	else if(v == "notice")
    {
        out = falco_common::priority_type::PRIORITY_NOTICE;
    }
	else if(v == "info" || v == "informational")
    {
        out = falco_common::priority_type::PRIORITY_INFORMATIONAL;
    }
	else if(v == "debug")
    {
        out = falco_common::priority_type::PRIORITY_DEBUG;
    }
    else
    {
        return false;
    }
    return true;
}

std::shared_ptr<libsinsp::filter::ast::expr> rule_loader::parse_condition(
        std::string condition)
{
    libsinsp::filter::parser p(condition);
	p.set_max_depth(1000);
	try
	{
        std::shared_ptr<libsinsp::filter::ast::expr> res_ptr(p.parse());
        return res_ptr;
	}
	catch (const sinsp_exception& e)
	{
        // todo: decide if this is the right place to place the error
        add_error(to_string(p.get_pos().col) + ": " + e.what());
        return nullptr;
	}
}

// todo(jasondellaluce): this is broken, specially towards value escaping.
// For now we need to keep resolving lists by text substitution to avoid
// introducing breaking changes. This is a 1-1 porting of the function
// we had in Lua.
bool rule_loader::expand_list_items(std::string& condition)
{
    static string blanks = " \t\n\r";
    static string delimiters = blanks + "(),=";
    string new_cond;
    size_t start, end;
    for (auto &list : m_lists)
    {
        start = condition.find(list.name);
        while (start != string::npos)
        {
            // the characters surrounding the name must be delimiters of beginning/end of string
            end = start + list.name.length();
            if ((start == 0 || delimiters.find(condition[start - 1]) != string::npos)
                    && (end >= condition.length() || delimiters.find(condition[end]) != string::npos))
            {
                // shift pointers to consume all whitespaces
                while (start > 0 && blanks.find(condition[start - 1]) != string::npos)
                {
                    start--;
                }
                while (end < condition.length() && blanks.find(condition[end]) != string::npos)
                {
                    end++;
                }
                
                // create substitution string by concatenating all values
                string sub = "";
                for (auto &v : list.values)
                {
                    if (!sub.empty())
                    {
                        sub += ", ";
                    }
                    sub += v;
                }

                // if substituted list is empty, we need to remove a comma from the left or the right
                if (list.values.empty())
                {
                    if (start > 0 && condition[start - 1] == ',')
                    {
                        start--;
                    }
                    else if (end < condition.length() && condition[end] == ',')
                    {
                        end++;
                    }
                }
                
                // compose new string with substitution
                new_cond = "";
                if (start > 0)
                {
                    new_cond += condition.substr(0, start);
                }
                new_cond += sub;
                if (end <= condition.length())
                {
                    new_cond += condition.substr(end);
                }
                condition = new_cond;
                start += sub.length();
            }
            start = condition.find(list.name, start + 1);
        }
    }
    return true;
}

// todo(jasondellaluce): this is the reason why escaping is totally broken
// in lists and exceptions. In this first refactor of the rule-loader, we
// keep this in order to not introduce breaking changes, but this needs
// to be changed in the future
void rule_loader::quote_item(std::string& item)
{
    if (item.find(" ") != std::string::npos)
    {
        if (item[0] != '"' && item[0] != '\'')
        {
            item = '"' + item + '"';
        }
    }
}

void rule_loader::add_macro(rule_macro& e)
{
    m_macros.push_back(e);
}

void rule_loader::add_list(rule_list& e)
{
    m_lists.push_back(e);
}

void rule_loader::add_rule(rule& e)
{
    m_rules.push_back(e);
}

rule_macro* rule_loader::find_macro(std::string& name)
{
    // todo: decide if we want to optimize linear search (maybe not)
    auto prev = std::find_if(m_macros.begin(), m_macros.end(),
        [&name](const rule_macro &r) { return r.name == name; });
    if (prev != m_macros.end())
    {
        return &*prev;
    }
    return nullptr;
}

rule_list* rule_loader::find_list(std::string& name)
{
    // todo: decide if we want to optimize linear search (maybe not)
    auto prev = std::find_if(m_lists.begin(), m_lists.end(),
        [&name](const rule_list &r) { return r.name == name; });
    if (prev != m_lists.end())
    {
        return &*prev;
    }
    return nullptr;
}

rule* rule_loader::find_rule(std::string& name)
{
    // todo: decide if we want to optimize linear search (maybe not)
    auto prev = std::find_if(m_rules.begin(), m_rules.end(),
        [&name](const rule &r) { return r.name == name; });
    if (prev != m_rules.end())
    {
        return &*prev;
    }
    return nullptr;
}
