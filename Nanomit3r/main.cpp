/*
 
  _____  ___        __      _____  ___      ______   ___      ___   __  ___________  _______   _______
 (\"   \|"  \      /""\    (\"   \|"  \    /    " \ |"  \    /"  | |" \("     _   ")/" __   ) /"      \
 |.\\   \    |    /    \   |.\\   \    |  // ____  \ \   \  //   | ||  |)__/  \\__/(__/ _) ./|:        |
 |: \.   \\  |   /' /\  \  |: \.   \\  | /  /    ) :)/\\  \/.    | |:  |   \\_ /       /  // |_____/   )
 |.  \    \. |  //  __'  \ |.  \    \. |(: (____/ //|: \.        | |.  |   |.  |    __ \_ \\  //      /
 |    \    \ | /   /  \\  \|    \    \ | \        / |.  \    /:  | /\  |\  \:  |   (: \__) :\|:  __   \
  \___|\____\)(___/    \___)\___|\____\)  \"_____/  |___|\__/|___|(__\_|_)  \__|    \_______)|__|  \___)
																										 																 
											 ,_     _,
											   '._.'
										  '-,   (_)   ,-'
											'._ .:. _.'
											 _ '|Y|' _
										   ,` `>\ /<` `,
										  ` ,-`  I  `-, `
											|   /=\   |
										  ,-'   |=|   '-,
												)-(
												\_/
										 
 */

#include <iostream>
#include "CVM/CVMStuff.hpp"
#include "JSONAnt.hpp"
#include "argparse.hpp"

using namespace argparse;
using std::cout, std::endl, std::string;

int main(int argc, const char * argv[]) {
	
	ArgumentParser parser("Main parser");

	parser.add_argument()
		.names({"-f", "--file"})
		.description("Path to binary file that needs be analyzed")
		.required(true);
	
	parser.add_argument()
		.names({"-o", "--output"})
		.description("Path to JSON output file")
		.required(true);
	
	parser.add_argument()
		.names({"-o2", "--output2"})
		.description("Path to JSON output file")
		.required(true);
	
	parser.add_argument()
		.names({"-s", "--section"})
		.description("Binary section that needs be analyzed")
		.required(true);
	
	parser.add_argument()
		.names({"-g", "--segment"})
		.description("Binary segment that needs be analyzed")
		.required(true);

	parser.enable_help();

	auto err = parser.parse(argc, argv);

	if (err) {
		cout << err << endl;
		return -1;
	}

	if (parser.exists("help")) {
		parser.print_help();
		return 0;
	}
	
	
	// maps
	string path_binary = parser.get<std::string>("file");
	string path_output = parser.get<std::string>("output");
	string path_nanomite_output = parser.get<std::string>("output2");
	string segment_binary = parser.get<std::string>("segment");
	string section_binary = parser.get<std::string>("section");

	
	// Here are sections that we need and parser needs to find
	// For now as static
	// TODO: add multiple sections
    static const string section_types[1][2] = {
        { segment_binary, section_binary },
    };
	
	// Types of instruction to nanomite
	// TODO: look up, add non conditional short jmp, maybe calls
	static const int nanomites_types[19] = {
		X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JCXZ, X86_INS_JECXZ, X86_INS_JE, X86_INS_JGE, X86_INS_JG, X86_INS_JLE, X86_INS_JL,
		X86_INS_JNE, X86_INS_JNO, X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JRCXZ, X86_INS_JS
    };
	
	// Create G0d instance
	CVMStuff *the_god;
	the_god = new CVMStuff(path_binary);
	
	// add section info [ to be searched ]
    for (auto section : section_types) {
        the_god->addSectionInfo(section[0], section[1]);
    }
	
	// add nanomite types
	for (auto type : nanomites_types) {
        the_god->addNanomiteType(type);
    }
	
	// Load binary file
	the_god->loadFile();

	// Look for sections
    the_god->lookForSections();
	
	
	
	// Create Js0n instance
	JSONAnt *hello;
	hello = new JSONAnt();

	// Look for potential nanomites
	the_god->lookForNanomites(*hello);
	
	
	// Get final JSON file
	hello->to_file(path_output);
	//hello->emerge();
	//hello->print();
	
	// binary with nanomites
	the_god->createNanomiteBinary(*hello, path_nanomite_output);
	
	return 0;
}
