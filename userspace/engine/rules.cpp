/*
Copyright (C) 2019 The Falco Authors.

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

#include <sstream>

#include "rules.h"

#include "falco_engine.h"
#include "banned.h" // This raises a compilation error when certain functions are used

falco_rules::falco_rules(falco_engine *engine)
	: m_engine(engine)
{
}

void falco_rules::add_filter_factory(const std::string &source,
				     std::shared_ptr<gen_event_filter_factory> factory)
{
	m_filter_factories[source] = factory;
}

void falco_rules::clear_filters()
{
	m_engine->clear_filters();
}

std::shared_ptr<gen_event_filter_factory> falco_rules::get_filter_factory(const std::string &source)
{
	auto it = m_filter_factories.find(source);
	if(it == m_filter_factories.end())
	{
		throw falco_exception(string("unknown event source: ") + source);
	}
	return it->second;
}

void falco_rules::add_filter(std::shared_ptr<gen_event_filter> filter, string &rule, string &source, set<string> &tags)
{
	m_engine->add_filter(filter, rule, source, tags);
}

void falco_rules::enable_rule(string &rule, bool enabled)
{
	m_engine->enable_rule(rule, enabled);
}

bool falco_rules::is_source_valid(const std::string &source)
{
	return m_engine->is_source_valid(source);
}

bool falco_rules::is_format_valid(const std::string &source, const std::string &format, std::string &errstr)
{
	bool ret = true;

	try
	{
		std::shared_ptr<gen_event_formatter> formatter;

		formatter = m_engine->create_formatter(source, format);
	}
	catch(exception &e)
	{
		std::ostringstream os;

		os << "Invalid output format '"
		   << format
		   << "': '"
		   << e.what()
		   << "'";

		errstr = os.str();
		ret = false;
	}

	return ret;
}

bool falco_rules::is_defined_field(const std::string &source, const std::string &fldname)
{
	auto it = m_filter_factories.find(source);

	if(it == m_filter_factories.end())
	{
		return false;
	}

	auto *chk = it->second->new_filtercheck(fldname.c_str());

	if (chk == NULL)
	{
		return false;
	}

	delete(chk);

	return true;
}

void falco_rules::load_rules(const string &rules_content,
			     bool verbose, bool all_events,
			     string &extra, bool replace_container_info,
			     falco_common::priority_type min_priority,
			     uint64_t &required_engine_version,
			     std::map<std::string, std::list<std::string>> &required_plugin_versions)
{
	// lua_getglobal(m_ls, m_lua_load_rules.c_str());
	// if(lua_isfunction(m_ls, -1))
	// {
	// 	lua_pushstring(m_ls, rules_content.c_str());
	// 	lua_pushlightuserdata(m_ls, this);
	// 	lua_pushboolean(m_ls, (verbose ? 1 : 0));
	// 	lua_pushboolean(m_ls, (all_events ? 1 : 0));
	// 	lua_pushstring(m_ls, extra.c_str());
	// 	lua_pushboolean(m_ls, (replace_container_info ? 1 : 0));
	// 	lua_pushnumber(m_ls, min_priority);
	// 	if(lua_pcall(m_ls, 7, 5, 0) != 0)
	// 	{
	// 		const char* lerr = lua_tostring(m_ls, -1);

	// 		string err = "Error loading rules: " + string(lerr);

	// 		throw falco_exception(err);
	// 	}

	// 	// Returns:
	// 	// Load result: bool
	// 	// required engine version: will be nil when load result is false
	// 	// required_plugin_versions: will be nil when load result is false
	// 	// array of errors
	// 	// array of warnings
	// 	bool successful = lua_toboolean(m_ls, -5);
	// 	required_engine_version = lua_tonumber(m_ls, -4);
	// 	get_lua_table_list_values(m_ls, -3, required_plugin_versions);
	// 	std::list<std::string> errors = get_lua_table_values(m_ls, -2);
	// 	std::list<std::string> warnings = get_lua_table_values(m_ls, -1);

	// 	// Concatenate errors/warnings
	// 	std::ostringstream os;
	// 	if (errors.size() > 0)
	// 	{
	// 		os << errors.size() << " errors:" << std::endl;
	// 		for(auto err : errors)
	// 		{
	// 			os << err << std::endl;
	// 		}
	// 	}

	// 	if (warnings.size() > 0)
	// 	{
	// 		os << warnings.size() << " warnings:" << std::endl;
	// 		for(auto warn : warnings)
	// 		{
	// 			os << warn << std::endl;
	// 		}
	// 	}

	// 	if(!successful)
	// 	{
	// 		throw falco_exception(os.str());
	// 	}

	// 	if (verbose && os.str() != "") {
	// 		// We don't really have a logging callback
	// 		// from the falco engine, but this would be a
	// 		// good place to use it.
	// 		fprintf(stderr, "When reading rules content: %s", os.str().c_str());
	// 	}

	// 	lua_pop(m_ls, 4);

	// } else {
	// 	throw falco_exception("No function " + m_lua_load_rules + " found in lua rule module");
	// }
}

void falco_rules::describe_rule(std::string *rule)
{
	// lua_getglobal(m_ls, m_lua_describe_rule.c_str());
	// if(lua_isfunction(m_ls, -1))
	// {
	// 	if (rule == NULL)
	// 	{
	// 		lua_pushnil(m_ls);
	// 	} else {
	// 		lua_pushstring(m_ls, rule->c_str());
	// 	}

	// 	if(lua_pcall(m_ls, 1, 0, 0) != 0)
	// 	{
	// 		const char* lerr = lua_tostring(m_ls, -1);
	// 		string err = "Could not describe " + (rule == NULL ? "all rules" : "rule " + *rule) + ": " + string(lerr);
	// 		throw falco_exception(err);
	// 	}
	// } else {
	// 	throw falco_exception("No function " + m_lua_describe_rule + " found in lua rule module");
	// }
}


falco_rules::~falco_rules()
{
}
