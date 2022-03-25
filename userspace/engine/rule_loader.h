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

#pragma once

#include <string>
#include <vector>
#include <map>
#include <yaml-cpp/yaml.h>
#include <filter/parser.h>
#include "filter_macro_resolver.h"
#include "falco_common.h" // todo: define priority_type elsewhere

// todo: better naming & namespace
struct rule
{
    uint32_t id;
    uint32_t id_visibility;
    std::string name;
    std::string description;
    std::string output;
    std::string condition;
    std::string source;
	std::set<std::string> tags;
    // todo: exceptions
    falco_common::priority_type priority;
    bool skip_if_unknown_filter;
    bool warn_evttypes;
    bool enabled;
    bool skipped;
};

// todo: better naming & namespace
struct rule_macro
{
    uint32_t id;
    uint32_t id_visibility;
    std::string name;
    std::string condition;
    std::string source;
    std::shared_ptr<libsinsp::filter::ast::expr> condition_ast;
    bool used;
};

// todo: better naming & namespace
struct rule_list
{
    uint32_t id;
    uint32_t id_visibility;
    std::string name;
    std::vector<std::string> values;
    bool used;
};

class rule_loader
{
public:
    void clear();

    // todo: better naming
    // called for each ruleset file
    bool load(const std::string &rules_content);

    // todo: better naming
    // called once after all ruleset files are loaded
    bool compile();
    
    std::vector<std::string>& errors();

    std::vector<std::string>& warnings();

private:
    // error management helpers
    void add_error(std::string e);
    void add_warning(std::string e);

    // element helpers
    bool parse_required_engine_version(bool& parsed, const YAML::Node& item);
    bool parse_required_plugin_versions(bool& parsed, const YAML::Node& item);
    bool parse_macro(bool& parsed, const YAML::Node& item);
    bool parse_list(bool& parsed, const YAML::Node& item);
    bool parse_rule(bool& parsed, const YAML::Node& item);

    // condition helpers
    std::shared_ptr<libsinsp::filter::ast::expr> parse_condition(
        std::string condition,
        std::string& errstr);
    gen_event_filter* compile_condition(
        libsinsp::filter::ast::expr* condition,
        string source,
        uint32_t rule_id,
        std::string& errstr);
    
    // engine helpers
    void store_rule_filter(rule& rule, gen_event_filter* filter);

    // list helpers
    void quote_item(std::string& item);
    bool resolve_list(std::string& condition, rule_list& list);

    // state helpers
    void add_macro(rule_macro& e);
    void add_list(rule_list& e);
    void add_rule(rule& e);
    rule_macro* find_macro(const std::string& name);
    rule_list* find_list(const std::string& name);
    rule* find_rule(const std::string& name);

    // state variables
    uint32_t m_last_id;
    std::vector<std::string> m_errors;
    std::vector<std::string> m_warnings;
    falco_common::priority_type m_min_priority;
    std::vector<rule_macro> m_macros;
    std::vector<rule_list> m_lists;
    std::vector<rule> m_rules;
    std::map<std::string, std::string> m_required_plugin_versions;
};