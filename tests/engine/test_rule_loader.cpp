/*
Copyright (C) 2020 The Falco Authors.

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
#include <catch.hpp>
#include <fstream>
#include <sstream>
#include <string>

using namespace std;

TEST_CASE("RULE LOADER EXAMPLE", "[rule_loader]")
{
	rule_loader loader;
	std::ifstream file("/home/vagrant/dev/falcosecurity/falco/rules/falco_rules.yaml");
	std::stringstream buffer;
	buffer << file.rdbuf();

	sinsp inspector;
	falco_engine engine(true);
	std::shared_ptr<gen_event_filter_factory> syscall_filter_factory(new sinsp_filter_factory(&inspector));
	std::shared_ptr<gen_event_formatter_factory> syscall_formatter_factory(new sinsp_evt_formatter_factory(&inspector));
	engine.add_source("syscall", syscall_filter_factory, syscall_formatter_factory);

	if (loader.load(&engine, buffer.str()) && loader.compile(&engine, false, ""))
	{
		REQUIRE(true);
	}
	else
	{
		string err;
		err += "\n------ RULE LOADER DEBUG ------\n\n";
		err += "ERRORS:\n";
		for (auto &e : loader.errors()){
			err += "  - " + e + "\n";
		}
		err += "\nWARNINGS:\n";
		for (auto &e : loader.warnings()){
			err += "  - " + e + "\n";
		}
		err += "-------------------------------\n\n";
		fprintf(stdout, "%s", err.c_str());
	}
}
