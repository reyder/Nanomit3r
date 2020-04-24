//
//  JSONAnt.cpp
//  Nanomit3r
//
//  Created by Marek Kulik on 25/03/2020.
//  Copyright © 2020 Marek Kulik. All rights reserved.
//

#include "JSONAnt.hpp"


JSONAnt::JSONAnt() {}


// to avoid multiple allocations tell the string how big it needs to become before concatenating.
// DEPRACTED
void JSONAnt::emerge() {

    std::size_t size = 0;
    for(auto const& s: json_parts)
        size += s.size();

    json_raw.reserve(size);

    for(auto const& s: json_parts)
        json_raw += s;

	json_raw += " ]";
}

// it's 2020, we have corona virus but no format library, YaY
// but it's coming c++ 20
void JSONAnt::add(uint32_t offset, uint mnemonic, int32_t jmp_offset, int32_t next_inst_offset) {
	string template_json = "{\\\"offset\\\": " + std::to_string(offset) + ",\\\"mnemonic\\\": " + std::to_string(mnemonic) + ",\\\"jmp_offset\\\": " + std::to_string(jmp_offset) + ",\\\"next_inst_offset\\\": " + std::to_string(next_inst_offset) + " }";
    json_parts.emplace_back(template_json);
}

void JSONAnt::add_br(uint32_t offset) {
    bp_addr.emplace_back(offset);
}

void JSONAnt::to_file(string path) {
	std::ofstream fout(path);
	
	fout << JSON_START;
	

	string delim = "";

	for(auto const& x : json_parts) {
		fout << delim;
		fout << x;
		delim = JSON_DELIM;
	}
	
	fout << JSON_END;
}
