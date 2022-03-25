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
#include "rule_collection.h"
#include "filter_macro_resolver.h"
#include "falco_common.h"

// todo(jasondellaluce): remove this cyclic dependency in the future
class falco_engine;

class rule_loader
{
public:
    void clear();

    // todo: better naming
    // called for each ruleset file
    bool load(
        falco_engine* engine,
        rule_collection* collection,
        const std::string &rules_content,
        falco_common::priority_type min_priority,
        bool replace_container_info,
        string fmt_extra);
    
    // of last load() call
    std::vector<std::string>& errors();

    // of last load() call
    std::vector<std::string>& warnings();

    // of last load() call
    uint32_t get_required_engine_version();

    // of last load() call
    std::map<std::string, std::string>& get_required_plugin_versions();

private:
    struct macro_info
    {
        uint32_t index;
        uint32_t index_visibility;
        std::string name;
        std::string condition;
        std::string source;
        std::shared_ptr<libsinsp::filter::ast::expr> condition_ast;
        bool used;
    };

    struct list_info
    {
        uint32_t index;
        uint32_t index_visibility;
        std::string name;
        std::vector<std::string> values;
        bool used;
    };

    // todo: make this use falco_rule
    struct rule_info
    {
        uint32_t index;
        uint32_t index_visibility;
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

    // stores rules in the engine
    bool compile(
        bool replace_container_info,
        string fmt_extra);

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
    std::shared_ptr<gen_event_filter> compile_condition(
        std::shared_ptr<libsinsp::filter::ast::expr> condition,
        string source,
        uint32_t rule_id,
        std::string& errstr);
    
    // engine helpers
    bool collect_rule(rule_info& rule, std::shared_ptr<libsinsp::filter::ast::expr> condition);
    bool is_format_valid(std::string src, std::string fmt, std::string& errstr);

    // list helpers
    void quote_item(std::string& item);
    bool resolve_list(std::string& condition, list_info& list);

    // state helpers
    void add_macro(macro_info& e);
    void add_list(list_info& e);
    void add_rule(rule_info& e);
    macro_info* find_macro(const std::string& name);
    list_info* find_list(const std::string& name);
    rule_info* find_rule(const std::string& name);

    // state variables
    uint32_t m_last_id;
    uint32_t m_required_engine_version;
    std::vector<std::string> m_errors;
    std::vector<std::string> m_warnings;
    std::vector<macro_info> m_macros;
    std::vector<list_info> m_lists;
    std::vector<rule_info> m_rules;
    std::map<std::string, std::string> m_required_plugin_versions;

    // used only during method exec
    falco_common::priority_type m_min_priority;
    falco_engine* m_engine;
    rule_collection* m_collection;
};