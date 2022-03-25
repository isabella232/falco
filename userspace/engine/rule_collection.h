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
#include "falco_common.h"

struct falco_rule
{
    uint32_t id;
    std::string source;
    std::string name;
    std::string output;
    std::string description;
	std::set<std::string> tags;
    falco_common::priority_type priority;
};

// todo: document this
class rule_collection
{
public:
    virtual inline uint32_t add(falco_rule& rule)
    {
        rule.id = m_rules.size();
        m_rules.push_back(rule);
        return rule.id;
    }

    virtual falco_rule* get(uint32_t id)
    {
        if (id >= m_rules.size())
        {
            return nullptr;
        }
        return &m_rules[id];
    }

    virtual inline void clear()
    {
        m_rules.clear();
    }

private:
    std::vector<falco_rule> m_rules;

};