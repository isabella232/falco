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

#include "falco_common.h"

std::vector<std::string> falco_common::priority_names = {
	"Emergency",
	"Alert",
	"Critical",
	"Error",
	"Warning",
	"Notice",
	"Informational",
	"Debug"
};

bool falco_common::parse_priority_type(std::string v, priority_type& out)
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

bool falco_common::format_priority_type(priority_type v, std::string& out)
{
	if ((size_t) v >= priority_names.size())
	{
		return false;
	}
	out = priority_names[(size_t) v];
	return true;
}
