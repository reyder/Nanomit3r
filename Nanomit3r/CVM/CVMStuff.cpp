//
//  CVMStuff.cpp
//  Nanomite
//
//  Created by reyder on 21/02/2019.
//  Copyright © 2019 OleOle. All rights reserved.
//

#include "CVMStuff.hpp"
#include <cstdint>
#include <exception>
#include <fstream>
#include <sstream>
#include <string>


CVMStuff::CVMStuff(string path) {
	file_path = path;
}


void CVMStuff::loadFile() {
	// TODO: Better error handler.
	fs::path filepath(fs::absolute(fs::path(file_path)));
	
	#if DEBUG
		printf("[DEBUG] Starting loading content of a file: %s \n", filepath.c_str());
	#endif

	std::uintmax_t fsize;

	if (fs::exists(filepath)) {
		fsize = fs::file_size(filepath);
	} else {
		throw(std::invalid_argument("File not found: " + filepath.string()));
	}
	
	#if DEBUG
		printf("[DEBUG] File size: %lu bytes \n", fsize);
	#endif

	std::ifstream infile;
	infile.exceptions(std::ifstream::failbit | std::ifstream::badbit);
	
	try {
		infile.open(filepath, std::ios::in | std::ifstream::binary);
	} catch (...) {
		std::throw_with_nested(std::runtime_error("Can't open input file " + filepath.string()));
	}

	try {
		raw_data.resize(fsize);
	} catch (...) {
		std::stringstream err;
		err << "Can't resize to " << fsize << " bytes";
		std::throw_with_nested(std::runtime_error(err.str()));
	}

	infile.read(raw_data.data(), fsize);
	infile.close();
}

void CVMStuff::addSectionInfo(string segment, string section) {
	#if DEBUG
		printf("[DEBUG] Adding section | segment [%s] | [%s]...\n", segment.c_str(), section.c_str());
	#endif

    binary_sections.emplace_back(segment, section, NULL, 0, 0);
}

void CVMStuff::addNanomiteType(int type) {
    nanomite_types.emplace_back(type);
}

void CVMStuff::lookForSections() {
	#if DEBUG
		printf("[DEBUG] Start searching for sections and segments...\n");
	#endif

	const struct mach_header_64 *mh = (const struct mach_header_64*)raw_data.data();
	
	for (sections &section_data: binary_sections) {
		auto& [segment, section, address, size, perm, aslr] = section_data;
		const struct section_64 *section_o = getsectbynamefromheader_64(mh, segment.c_str(), section.c_str());
		
		if (section_o != NULL) {
			address = section_o->addr;
			size = section_o->size;
			
			#if DEBUG
			printf("[DEBUG] Found segment (%s) and section (%s), address = 0x%llx, size = %llu\n", segment.c_str(), section.c_str(), section_o->addr, section_o->size);
			#endif
		}
	}
}

bool CVMStuff::lookForNanomites(JSONAnt& ptr) {
	csh handle;
	size_t count;
	cs_insn *insn;
	
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false;
	
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	
	char *hack_and_magic;
	uint8_t *real_data;
	hack_and_magic = (char *)raw_data.data();

	#if DEBUG
		printf("[DEBUG] Start searching for potential nanomites.......\n");
	#endif
	
	for (sections section: binary_sections) {
		auto offset = get<2>(section) - BASE_ADDR;
		auto size = get<3>(section);
		real_data = (uint8_t *)(hack_and_magic+offset);
		
		#if DEBUG
		printf("[DEBUG] Size of section to search: %llu\n", size);
		#endif

		count = cs_disasm(handle, (uint8_t *)real_data, size, get<2>(section), 0, &insn);
		
		#if DEBUG
			printf("[DEBUG] Found [ %zu ] instruction !\n", count);
		#endif
		
		// For limitations.
		int added = 0;
		
		if (count > 0) {
			for (int j = 0; j < count; j++) {
				// Adding more than 6k instructions might result in
				// extending STACK memory
				// This is limitiation of method that attach JSON data file
				if (added > 6000) {
					break;
				}
				
				if (std::find(nanomite_types.begin(), nanomite_types.end(), insn[j].id) != nanomite_types.end()) {
					// check if its not jmp REG type of instruction
					string test_length = insn[j].op_str;
					if (test_length.length() < 6)
						continue;
					
					unsigned long pre_offset;
					unsigned long offset;
					
					// have no idea how to print offset here. detail object, ox x86 not found
					// workaround for now..
					try {
						pre_offset = std::stoul(insn[j].op_str, nullptr, 16);
						offset = pre_offset - insn[j].address;
					}
					catch(...) {
						continue;
						#if DEBUG
							printf("JMP not supported: %s \n", insn[j].op_str);
						#endif
					}

					// We need to know where is next instruction.
					// This is required for conditional jmps if jmp is not 'made'
					if (j + 1 >= count && insn[j].id != X86_INS_JMP && insn[j].id != X86_INS_CALL) {
						// That's should never heppend but it might theoretically
						printf("Exception 0x386");
						return false;
					}

					
					auto next_inst_offset = insn[j+1].address - insn[j].address;
					
					// Lets save space
					if (insn[j].id == X86_INS_JMP) {
						next_inst_offset = 0;
					}
					

					ptr.add_br(insn[j].address - BASE_ADDR);
					ptr.add(insn[j].address, insn[j].id, offset, next_inst_offset);

					#if DEBUG
						printf("0x%" PRIx64":\t%s\t\t%lld\t\t%lld\n", insn[j].address, insn[j].mnemonic, offset, next_inst_offset);
					#endif
					
					added++;
				}
			}
			cs_free(insn, count);
			
			#if DEBUG
				printf("[DEBUG] Found [ %i ] candidates !\n", added);
			#endif
		}

		cs_close(&handle);

	}
	return true;
}

void CVMStuff::createNanomiteBinary(JSONAnt& ptr, string path) {
	#if DEBUG
		printf("[DEBUG] Creating new binary with nanomites\n");
	#endif
	
	// that might have terrrible performance. it's ok for now. JMIW
	for (auto &offset: ptr.bp_addr) {
		raw_data.replace(offset, 2, "\xCC\x90"s);
	}
	
	std::ofstream fout(path);
	
	fout << raw_data;

}
