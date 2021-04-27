//
//  JSONAnt.hpp
//  Nanomit3r
//
//  Created by Marek Kulik on 25/03/2020.
//  Copyright © 2020 Marek Kulik. All rights reserved.
//

#ifndef JSONAnt_hpp
#define JSONAnt_hpp

#include <stdio.h>
#include <string>
#include <vector>
#include <fstream>


#define JSON_START  "\"[ ";
#define JSON_END    " ]\"";
#define JSON_DELIM    ",";

// Don't bring entire std namespace :-( but It's fine for this project.
using namespace std;

class JSONAnt {
public:
    JSONAnt();
	void add(uint32_t offset, uint mnemonic, int32_t jmp_offset, int32_t next_inst_offset);
	void emerge();  // DEPRACTED
	void to_file(string path);
	void add_br(uint32_t offset);  // TEMP
private:
	string json_raw;
	vector<string> json_parts;
public:
	vector<uint32_t> bp_addr;   // just to make it work TEMP

};

#endif /* JSONAnt_hpp */

