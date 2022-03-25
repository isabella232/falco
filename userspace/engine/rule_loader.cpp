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
static string s_container_info_fmt = "%container.info";
static string s_container_info_default_extra_fmt = "%container.name (id=%container.id)";

static void string_replace_all(std::string& s, std::string o, std::string n)
{
    size_t pos = s.find(o);
    while(pos != std::string::npos)
    {
        s.replace(pos, o.size(), n);
        pos = s.find(o, pos + n.size());
    }
}

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

bool rule_loader::load(falco_engine* engine, const std::string &rules_content)
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
    m_engine = engine;

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

bool rule_loader::compile(falco_engine* engine, bool replace_container_info, string fmt_extra)
{
    string errstr;
    filter_macro_resolver macro_resolver;

    m_engine = engine;
    m_engine->clear_filters();

    // expand lists
    for (auto &l : m_lists)
    {
        vector<string> new_values;
        // note: this is O(L) with L being the # of lists,
        // because we achieve O(1) lookup in find_list()
        for (auto &v : l.values)
        {
            auto ref = find_list(v);
            // note: there is a visibility ordering between lists,
            // which means that lists can only use lists defined before them
            if (ref && ref->id < l.id_visibility)
            {
                ref->used = true;
                new_values.insert(new_values.end(), ref->values.begin(), ref->values.end());
            }
            else
            {
                new_values.push_back(v);
            }
        }
        for (auto &v: new_values)
        {
            quote_item(v);
        }
        l.values = new_values;
    }

    // parse all macros
    for (auto &m: m_macros)
    {
        // note: this is O(MxL) with M being the # of macros,
        // and L being the # of lists.
        for (auto &l : m_lists)
        {
            // note: there is no visibility ordering between macros,
            // and lists, which means that macros can use lists defined
            // after them.
            if (!resolve_list(m.condition, l))
            {
                // todo: print an error (this is not supposed to ever trigger tho)
                return false;
            }
        }
        m.condition_ast = parse_condition(m.condition, errstr);
        if (!m.condition_ast)
        {
            // todo: understand if we need to fail here or add a warning depending if macro is used or not
            add_error("compilation error when compiling macro '" + m.name + "': " + errstr);
            return false;
        }
    }

    // validate/expand all macros
    for (auto &m: m_macros)
    {
        // note: this is O(M^2) with M being the # of macros
        // note: there is a visibility ordering between macros,
        // which means that macros can only use macros defined before them
        for (auto &ref : m_macros)
        {
            if (ref.id != m.id && ref.id < m.id_visibility)
            {
                macro_resolver.set_macro(ref.name, ref.condition_ast);
            }
            else
            {
                macro_resolver.set_macro(ref.name, nullptr);
            }
        }
        macro_resolver.run(m.condition_ast);
        if(!macro_resolver.get_unknown_macros().empty())
        {
            // todo: understand if we need to fail here or add a warning depending if macro is used or not
            add_error("compilation error when compiling macro '"
                + m.name + "': undefined macro '"
                + *macro_resolver.get_unknown_macros().begin()
                + "' used in condition");
            return false;
        }
        for (auto &resolved : macro_resolver.get_resolved_macros())
        {
            find_macro(resolved)->used = true;
        }
    }

    // compile all rules and add them to engine
    uint32_t n_rules = 0;
    for (auto &r: m_rules)
    {
        if (r.skipped)
        {
            continue;
        }

        // todo: compile exception as ast here and add it to condition
        // we may beed to do it using string concat to not introduce
        // breaking changes
        string condition = r.condition;

        // note: this is O(RxL) with M being the # of rules,
        // and L being the # of lists.
        for (auto &l : m_lists)
        {
            // note: there is no visibility ordering between rules,
            // and lists, which means that rules can use lists defined
            // after them.
            if (!resolve_list(condition, l))
            {
                // todo: print an error (this is not supposed to ever trigger tho)
                return false;
            }
        }
        auto condition_ast = parse_condition(condition, errstr);
        if (!condition_ast)
        {
            add_error("compilation error when compiling rule '" + r.name + "': " + errstr);
            return false;
        }

        // note: this is O(R*M) with R being the # of rules,
        // and M being the # of macros
        for (auto &ref : m_macros)
        {
            // note: there is no visibility ordering between rules,
            // and macros, which means that rules can use macros defined
            // after them.
            macro_resolver.set_macro(ref.name, ref.condition_ast);
        }
        macro_resolver.run(condition_ast);
        if(!macro_resolver.get_unknown_macros().empty())
        {
            add_error("compilation error when compiling rule \'"
                + r.name + "': undefined macro '"
                + *macro_resolver.get_unknown_macros().begin()
                + "' used in condition");
            return false;
        }
        for (auto &resolved : macro_resolver.get_resolved_macros())
        {
            find_macro(resolved)->used = true;
        }

        // todo(jasondellaluce): simplify the logic here
        if (r.source == s_syscall_source)
        {
            if (r.output.find(s_container_info_fmt) != string::npos)
            {
                if (replace_container_info)
                {
                    string_replace_all(r.output, s_container_info_fmt, fmt_extra);
                }
                else
                {
                    string_replace_all(r.output, s_container_info_fmt, s_container_info_default_extra_fmt);
                    if (!fmt_extra.empty())
                    {
                        r.output += " ";
                        r.output += fmt_extra;
                    }
                }
            }
            else if (!fmt_extra.empty())
            {
                r.output += " ";
                r.output += fmt_extra;
            }
        }

        if (!is_format_valid(r.source, r.output, errstr))
        {
            add_error("rule '" + r.name +"' invalid output format: " + errstr);
            return false;
        }

        // compile rule
        uint32_t rule_id = n_rules++;
        auto filter = compile_condition(condition_ast.get(), r.source, rule_id, errstr);
        if (!filter)
        {
            if (r.skip_if_unknown_filter && errstr.find("nonexistent field") != string::npos)
            {
                add_warning("rule '" + r.name +"' warning (unknown-field): " + errstr);
            }
            else
            {
                add_error("rule '" + r.name +"' error: " + errstr);
                return false;
            }
        }
        else
        {
            collect_rule_filter(r, filter);
        }
    }

    // print info on any dangling lists or macros that were not used anywhere
    for (auto &m: m_lists)
    {
        if (!m.used)
        {
            add_warning("macro " + m.name + " not refered to by any rule/macro");
        }
    }
    for (auto &l: m_lists)
    {
        if (!l.used)
        {
            add_warning("list " + l.name + " not refered to by any rule/macro/list");
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
        if (m_engine->engine_version() < ver)
        {
            add_error("rules require engine version " + to_string(ver)
                    + ", but engine version is "
                    + to_string(m_engine->engine_version()));
            return false;
        }
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

        if (!m_engine->is_source_valid(m.source))
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
            prev->id_visibility = m_last_id++;
            // todo: concatenate YAML context too
        }
        else
        {
            // store macro
            if (prev)
            {
                prev->condition = m.condition;
                prev->id_visibility = m_last_id++;
            }
            else
            {
                m.id = m_last_id++;
                m.id_visibility = m.id;
                m.used = false;
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
            prev->id_visibility = m_last_id++;
            // todo: concatenate YAML context too
        }
        else
        {
            // store list
            if (prev)
            {
                prev->id_visibility = m_last_id++;
                prev->values = l.values;
            }
            else
            {
                l.id = m_last_id++;
                l.id_visibility = l.id;
                l.used = false;
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

        r.warn_evttypes = true;
        if(item["warn_evttypes"].IsDefined()
                && !YAML::convert<bool>::decode(
                    item["warn_evttypes"], r.warn_evttypes))
        {
            // todo: print a warning failed decoding of 'append'
        }

        if (!item["source"].IsDefined()
                || !YAML::convert<string>::decode(item["source"], r.source)
                || r.source.empty())
        {
            r.source = s_syscall_source;
        }

        if (!m_engine->is_source_valid(r.source))
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

            prev->id_visibility = m_last_id++;
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
                        || !falco_common::parse_priority_type(priority, r.priority))
                {
                    add_error("rule '" + r.name + "' invalid priority");
                    return false;
                }
                r.enabled = true;
                r.skipped = r.priority > m_min_priority; // note: we fixed a bug, because priority could not be overriden before
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
                    r.id = prev->id;
                    r.id_visibility = m_last_id++;
                    *prev = r;
                }
                else
                {
                    r.id = m_last_id++;
                    r.id_visibility = r.id;
                    add_rule(r);
                }
            }
        }
    }
    return true;
}

std::shared_ptr<libsinsp::filter::ast::expr> rule_loader::parse_condition(
        std::string condition,
        std::string& errstr)
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
        errstr = to_string(p.get_pos().col) + ": " + e.what();
        return nullptr;
	}
}

gen_event_filter* rule_loader::compile_condition(
        libsinsp::filter::ast::expr* condition,
        string source,
        uint32_t rule_id,
        std::string& errstr)
{
    try
    {
        auto factory = m_engine->get_filter_factory(source);
        sinsp_filter_compiler compiler(factory, condition);
        compiler.set_check_id(rule_id);
        return compiler.compile();
    }
    catch (const sinsp_exception& e)
    {
        errstr = e.what();
    }
    catch (const falco_exception& e)
    {
        errstr = e.what();
    }
    return nullptr;
}

// todo(jasondellaluce): this is broken, specially towards value escaping.
// For now we need to keep resolving lists by text substitution to avoid
// introducing breaking changes. This is a 1-1 porting of the function
// we had in Lua.
bool rule_loader::resolve_list(std::string& condition, rule_list& list)
{
    static string blanks = " \t\n\r";
    static string delimiters = blanks + "(),=";
    string new_cond;
    size_t start, end;

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

rule_macro* rule_loader::find_macro(const std::string& name)
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

rule_list* rule_loader::find_list(const std::string& name)
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

rule* rule_loader::find_rule(const std::string& name)
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

void rule_loader::collect_rule_filter(rule& rule, gen_event_filter* filter)
{
    // todo: implement this engine->add_filter()
    printf("ADDED RULE: %s\n", rule.name.c_str());
    if (rule.source == s_syscall_source)
    {
        auto evttypes = filter->evttypes();
        if (evttypes.size() == 0 || evttypes.size() > 100)
        {
            add_warning("rule '" + rule.name + "' warning (no-evttype):\n" +
                    + "         matches too many evt.type values.\n"
                    + "         This has a significant performance penalty.");
        }
    }

    // todo: enable rule in default ruleset engine->enable_rule()


}

// todo: decide what's passed by reference and what not... in all the methods :)
bool rule_loader::is_format_valid(std::string src, std::string fmt, std::string& errstr)
{
    try
	{
		std::shared_ptr<gen_event_formatter> formatter;
		formatter = m_engine->create_formatter(src, fmt);
        return true;
	}
	catch(exception &e)
	{
		errstr = e.what();
		return false;
	}
}