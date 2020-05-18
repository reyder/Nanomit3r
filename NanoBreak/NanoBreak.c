//
//  NanoBreak.c
//  NanoBreak
//
//  Created by Marek Kulik on 30/03/2019.
//  Copyright © 2019 OleOle. All rights reserved.
//

#include "NanoBreak.h"
#include "json.h"
#include <sys/time.h>
mach_port_t exception_port;


void install_debugger(void) __attribute__ ((constructor));

struct json_value_s* root;

uint64_t aslr;
uint64_t return_call_address;
uint64_t target_call_address;

#if DEBUG
	struct timespec start, end;
	int warunkowe = 0;
	double suma_czasu = 0;
#endif


// [ __attribute ((noinline)) ] prevents the compiler from optimization
__attribute ((noinline)) void exception_handler() {
	kern_return_t kr;
	exc_msg_t     msg_recv;
	reply_msg_t   msg_resp;
	
	// Add ASLR
	aslr = _dyld_get_image_vmaddr_slide(0);
	
	const char json[]  = {
	#include "ww.h"
	};
	
	root = json_parse(json, strlen(json));
	
	/// TEST
	
	
	msg_recv.Head.msgh_local_port = exception_port;
	msg_recv.Head.msgh_size = sizeof(msg_recv);
	
	kr = mach_msg(&(msg_recv.Head),				// message
				  MACH_RCV_MSG|MACH_RCV_LARGE,	// options
				  0,						    // send size (irrelevant here)
				  sizeof(msg_recv),				// receive limit
				  exception_port,				// port for receiving
				  100,							// no timeout
				  MACH_PORT_NULL);				// notify port (irrelevant here)
	
	
	// let's tak care of recived mach_msg here, now.
	
	x86_debug_state64_t debug;
	mach_msg_type_number_t count;
	thread_state_flavor_t flavor;
	
	flavor = x86_DEBUG_STATE64;
	count = x86_DEBUG_STATE64_COUNT;
	
	thread_act_port_array_t thread_list;
	mach_msg_type_number_t thread_count;
	
	
	task_threads(mach_task_self(), &thread_list, &thread_count);
	
	thread_get_state(thread_list[0], flavor, (thread_state_t)&debug, &count);
	
	mach_exc_server(&msg_recv.Head, &msg_resp.Head);
	
	kr = mach_msg(&(msg_resp.Head),			// message
			  MACH_SEND_MSG,			// options
			  msg_resp.Head.msgh_size,	// send size
			  0,						// receive limit (irrelevant here)
			  MACH_PORT_NULL,			// port for receiving (none)
			  100,						// no timeout
			  MACH_PORT_NULL);			// notify port (we don't want one)

}

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}


void call_trampoline() {
	SLAP_STACK_FRAME
	
	// We need to simulate Call instruction.
	// We probably should make changes
	// From execption level..
	// not after handling exception
	// aka RACE (this method might require mutex)
	// JMIW
	
	// we could make it static but it's "harder" to analyze
	// when it's dynamic (not right now ofc)
	
	
	asm("push %0" : : "r" (return_call_address));
	asm("push %0" : : "r" (target_call_address));
	asm("ret");
	
}

void better_call_handler(uint64_t *state_struct_address) {
	// Maybe to DO
	return;
}

uint64_t handle_nanomite_type(uint64_t address, uint64_t mnemonic, uint64_t offset, uint64_t jmp_offset, uint64_t flags) {
	#if DEBUG
		warunkowe++;
		printf("[Debug | Dylib] offset: %i, jmp_offset: %d \n",offset, jmp_offset);
	#endif
	
	uint8_t condition;
	
	switch( mnemonic ) {
		case X86_INS_CALL:
			return_call_address = address + jmp_offset;
			target_call_address = address + offset;

			return (uint64_t)&call_trampoline;
			break;
		case X86_INS_JMP:
			condition = 1;
			break;
		case X86_INS_JE:
			condition = (flags&ZERO_FLAG) ? 1 : 0;
			break;
		case X86_INS_JNE:
			condition = (flags&ZERO_FLAG) ? 0 : 1;
			break;
		case X86_INS_JS:
			condition = (flags&SIGN_FLAG) ? 1 : 0;
			break;
		case X86_INS_JNS:
			condition = (flags&SIGN_FLAG) ? 0 : 1;
			break;
		case X86_INS_JO:
			condition = (flags&OVFL_FLAG) ? 1 : 0;
			break;
		case X86_INS_JNP:
			condition = (flags&PART_FLAG) ? 0 : 1;
			break;
		case X86_INS_JNO:
			condition = (flags&PART_FLAG) ? 0 : 1;
			break;
		case X86_INS_JLE:
			condition = ((flags&ZERO_FLAG) || ((flags&SIGN_FLAG) != (flags&OVFL_FLAG))) ? 1 : 0;
			break;
		case X86_INS_JG:
			condition = ((flags&ZERO_FLAG) || ((flags&ZERO_FLAG) != (flags&OVFL_FLAG))) ? 0 : 1;
			break;
//			Jump short if RCX register is 0. ..................
//		case X86_INS_JRCXZ:
//			condition = (flags&SIGN_FLAG) ? 1 : 0;
//			break;
		case X86_INS_JL:
			condition = ((flags&SIGN_FLAG) != (flags&OVFL_FLAG)) ? 1 : 0;
			break;
		case X86_INS_JB:
			condition = (flags&CARR_FLAG) ? 1 : 0;
			break;
		case X86_INS_JBE:
			condition = ((flags&CARR_FLAG) || (flags&ZERO_FLAG)) ? 1 : 0;
			break;
		case X86_INS_JA:
			condition = ((flags&CARR_FLAG) || (flags&ZERO_FLAG)) ? 0 : 1;
			break;
		case X86_INS_JAE:
			condition = (flags&CARR_FLAG) ? 0 : 1;
			break;
			
		// case X86_INS_JGE: Not supported in 64-bit mode.
	   
		default:
			condition = 1;
			break;
	}
	
	if (condition)
		return address+offset;
	else
		return address+jmp_offset;
		
}

uint64_t nanomite_recognize(uint64_t address, uint64_t flags) {
	unsigned long long target_value = (address - aslr - BASE_ADDR - 0x1);
	
	struct json_array_s* main_array = json_value_as_array(root);
	if (main_array->length == 0) {
		
		#if DEBUG
			printf("[Debug | Dylib] Exception data EMPTY !\n");
		#endif
		
		return 0x00000000;
	}
	
	// Here is all array with objects
	struct json_array_element_s* arr_ele = main_array->start;
	
	while (1) {
		// Let's get first ot last or 2nd etc. object
		struct json_object_s* object = json_value_as_object(arr_ele->value);
		
		// This is the end. Hold your breath and count to 10..
		if (object == NULL) {
			#if DEBUG
				printf("[Debug | Dylib] Failed finding correct nanomite data\n");
			#endif
			
			return 0x00000000;
		}

		// First value of (1,2,3,4...) object in array
		struct json_object_element_s* a = object->start;
		struct json_number_s* value_1 = json_value_as_number(a->value);
		
		#if DEBUG
			printf("[Debug | Dylib] Checking data ... %p ?== %p \n", target_value, atoi(value_1->number));
		#endif
		
		// We found it.
		if (target_value == atoi(value_1->number)) {
			struct json_object_element_s* b = a->next;
			struct json_number_s* value_2 = json_value_as_number(b->value);
			
			struct json_object_element_s* c = b->next;
			struct json_number_s* value_3 = json_value_as_number(c->value);
			
			struct json_object_element_s* d = c->next;
			struct json_number_s* value_4 = json_value_as_number(d->value);
			
			#if DEBUG
				printf("[Debug | Dylib] Runniong handler <0><o> \n");
			#endif
			
			return handle_nanomite_type(address, atoi(value_2->number), atoi(value_3->number) - 0x1, atoi(value_4->number) - 0x1, flags);
		}
		
		// Go next
		arr_ele = arr_ele->next;
		
	}
	
}

void install_debugger() {
	
	kern_return_t kr;
	
	mach_port_t myself = mach_task_self();
	
	// we only want to catch exceptions coused by BREAKPOINT
	exception_mask_t mask = EXC_MASK_BREAKPOINT;
	
	// create a receive right in our task
	kr = mach_port_allocate(myself, MACH_PORT_RIGHT_RECEIVE, &exception_port);
	
	// insert a send right: we will now have combined receive/send rights
	kr = mach_port_insert_right(myself, exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	
	// add an exception port in our target
	// --> EXCEPTION_DEFAULT == Send a catch_exception_raise message including the thread identity
	// --> MACH_EXCEPTION_CODES == 64-bit safe exception messages
	kr = task_set_exception_ports(myself, mask, exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, x86_THREAD_STATE32);

	// start DGB
	pthread_t exception_thread = NULL;
	if	(pthread_create(&exception_thread,
						(pthread_attr_t *)0,					// "If attr is NULL, then the thread is created with default attributes."
						(void *(*)(void *))exception_handler,	// our start_routine
						(void *)0)
		)
	{
		perror("pthread_create"); // On success, pthread_create() returns 0
	}
	
	
	// FROM  Linux Programmer's Manual:
	// The detached attribute merely determines the behavior of the system when the thread terminates;
	// it does not prevent the thread from being terminated if the process terminates using exit(3)
	// (or equivalently, if the main thread returns).
	
	// To allow other threads to continue execution, the main thread should terminate
	// by calling pthread_exit() rather than exit(3).
	pthread_detach(exception_thread);
	
}


// Here is the magic!
// the code to be executed whenever an (correct) exception occurs
// the logic of dealing with different exceptions stays here ??  gdb uses EXC_MASK_ALL, we have different ports if the mask is different
kern_return_t catch_mach_exception_raise(mach_port_t            port,
										 mach_port_t            threadid,
										 mach_port_t            task,
										 exception_type_t       exception,
										 exception_data_t       code,
										 mach_msg_type_number_t code_count){
	
	#if DEBUG
		clock_gettime(CLOCK_MONOTONIC, &start);
	#endif
	
	kern_return_t kr;
	
	x86_thread_state64_t state;
	mach_msg_type_number_t count;
	thread_state_flavor_t flavor;
	
	flavor = x86_THREAD_STATE64;
	count = x86_THREAD_STATE64_COUNT;
	
	kr = thread_get_state(threadid, flavor, (thread_state_t)&state, &count);

	uint64_t rip = state.__rip;
	uint64_t flags = state.__rflags;
	
	#if DEBUG
		printf("[Debug | Dylib] Breakpoint exception with nanomite triggered !\n");
		printf("[Debug | Dylib] RIP: %p (No ASLR: %p), Flags: %llu\n", rip, rip-aslr, flags);
	#endif
		

	switch (exception) {
		case EXC_BREAKPOINT: {

			#if DEBUG
				printf("[Debug | Dylib] This is BreakPoinT, trying to find it in data...\n");
			#endif
			
			uint64_t final = nanomite_recognize(rip, flags);
			
			if (final) {
				#if DEBUG
					printf("[Debug | Dylib] FOUND ! Continuing.\n");
					printf("[Debug | Dylib] Setting RIP to %p (NO ALSR: %p).\n", final, final-aslr);
				#endif
				
				state.__rip = final;
				kr = thread_set_state(threadid, flavor, (thread_state_t)&state, count);
				install_debugger();
				
				#if DEBUG
					clock_gettime(CLOCK_MONOTONIC, &end);
					
					double time_taken;
					time_taken = (end.tv_sec - start.tv_sec) * 1e9;
					time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
					suma_czasu = suma_czasu + time_taken;
					printf("[Debug | Dylib] TIME %f \n", suma_czasu/warunkowe);
					printf("[Debug | Dylib] TIME %f \n", suma_czasu);
					printf("[Debug | Dylib] TIME %i \n", warunkowe);
				#endif
				
				return KERN_SUCCESS;
			}
			
			#if DEBUG
				printf("[Debug | Dylib] Data for current breakpint NOT found. Crash in 3..2..1..\n");
			#endif
			
			
			// Try to resume..
			return KERN_SUCCESS;
			
			break; // ....
		}
			
		default: {
			#if DEBUG
				printf("[Debug | Dylib] Wrong exception type. Bad things will happen\n");
			#endif
			
			exit(1);
		}
	}
	return(0);
}


///////////////////////////////////////////////////////////
// we need to put it here because of compiler complaints //
///////////////////////////////////////////////////////////

kern_return_t catch_mach_exception_raise_state (mach_port_t            port,
												mach_port_t            thread,
												mach_port_t            task,
												exception_type_t       exception,
												exception_data_t       code,
												mach_msg_type_number_t code_count){
	
	return(KERN_INVALID_ADDRESS);
}

kern_return_t catch_mach_exception_raise_state_identity (
														 mach_port_t             exception_port,
														 mach_port_t             thread,
														 mach_port_t             task,
														 exception_type_t        exception,
														 exception_data_t        code,
														 mach_msg_type_number_t  codeCnt,
														 int *                   flavor,
														 thread_state_t          old_state,
														 mach_msg_type_number_t  old_stateCnt,
														 thread_state_t          new_state,
														 mach_msg_type_number_t *new_stateCnt
														 ){
	return(KERN_INVALID_ADDRESS);
}
