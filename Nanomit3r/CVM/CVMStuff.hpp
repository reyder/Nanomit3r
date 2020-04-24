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

#ifndef CVMStuff_hpp
#define CVMStuff_hpp

#include <tuple>                // add tuples
#include <string>               // add string
#include <bitset>               // add bitmask
#include <vector>               // add vectors
#include <mach/mach.h>          // mach_task_self_
#include <mach-o/dyld.h>        // _dyld_get_image_header
#include <mach/mach_vm.h>       // mach_vm_region_recurse()
#include <mach-o/getsect.h>     // getsectbynamefromheader_64
//#include <experimental/optional>
//#include <experimental/vector>
#include <filesystem>




/// CHECKED by me
#include <capstone/capstone.h>
#include "../JSONAnt.hpp"



using namespace std;
namespace fs = std::__fs::filesystem;


typedef tuple<string, string, mach_vm_address_t, uint64_t, uint8_t, intptr_t> sections;       // segment, section, address, size, bitmask of section, ASLR



/* ######################
 ######### MACROS #######
 ##################### */
#define BASE_ADDR 0x100000000
#define NANOMITE    "\xCC\x90";


#define SLAP_STACK_FRAME    asm("pop %rbp");
#define PUSH_REGISTERS      asm("push %%rdi;" "push %%rsi;" "push %%rdx;" "push %%rcx;" "push %%rbx;" "push %%r8;" "push %%r9;" "push %%r10;" "push %%r11;" "push %%r12;" "push %%r13;" "push %%r14;" ::);
#define POP_REGISTERS       asm("pop %%r14;" "pop %%r13;" "pop %%r12;" "pop %%r11;" "pop %%r10;" "pop %%r9;" "pop %%r8;" "pop %%rbx;" "pop %%rcx;" "pop %%rdx;" "pop %%rsi;" "pop %%rdi;" ::);

/*
    Here is struct that stores our Nanomites data
	For now we only target SHORT jmp-s
*/
struct nanomite {
	int8_t offset; 								// jmp-s offset
    mach_vm_address_t   addresses;              // Addresses aka offset in our case
};


class CVMStuff {
public:
    CVMStuff(const std::string name);
    void addSectionInfo(string segment, string section);
    void lookForSections();
	bool lookForNanomites(JSONAnt& ptr);
    void loadFile();
	void addNanomiteType(int type);
	void createNanomiteBinary(JSONAnt& ptr, string path);
	
	
    
protected:
#if defined (VM_REGION_SUBMAP_SHORT_INFO_COUNT_64)
    typedef vm_region_submap_short_info_data_64_t RegionInfo;
    enum { kRegionInfoSize = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 };
#else
    typedef vm_region_submap_info_data_64_t RegionInfo;
    enum { kRegionInfoSize = VM_REGION_SUBMAP_INFO_COUNT_64 };
#endif

    
private:
	string file_path;													// relative path to binary file
	string raw_data;													// here we store HUGE string with raw data. Most people got modern computers with a lot of ram. It's fine. . .. ☞◕ ͜ʖ◕☞

	vector<int>								nanomite_types;				// types of mnemonics to include in nanomites
    vector<nanomite>                        nanomites;           		// Final nanomites lookup
    vector<sections>                        binary_sections;            // binary sections to be searched

};



#endif /* CVMStuff_hpp */
