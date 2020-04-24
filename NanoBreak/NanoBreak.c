//
//  NanoBreak.c
//  NanoBreak
//
//  Created by Marek Kulik on 30/03/2019.
//  Copyright © 2019 OleOle. All rights reserved.
//

#include "NanoBreak.h"
#include "json.h"
mach_port_t exception_port;

#define DEBUG 1

void install_debugger(void) __attribute__ ((constructor));

struct json_value_s* root;

uint64_t aslr;
uint64_t return_call_address;
uint64_t target_call_address;


// [ __attribute ((noinline)) ] prevents the compiler from optimization
__attribute ((noinline)) void exception_handler() {
	kern_return_t kr;
	exc_msg_t     msg_recv;
	reply_msg_t   msg_resp;
	
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

void call_trampoline() {
	SLAP_STACK_FRAME
	
	// We need to simulate Call instruction.
	// We probably should make changes
	// From execption level..
	// not after handling exception
	// aka RACE (this method might require mutex)
	// JMIW
	
	// we could make it static but it's "harder" to analyze
	// when it's dynamic
	
	
	asm("push %0" : : "r" (return_call_address));
	asm("push %0" : : "r" (target_call_address));
	asm("ret");
	
}

void better_call_handler(uint64_t *state_struct_address) {
	// Maybe to do
}

void handle_nanomite_type(uint64_t address, uint64_t mnemonic, uint64_t offset, uint64_t jmp_offset) {
	
}

void nanomite_recognize(uint64_t address) {
	unsigned long long target_value = (address - aslr - BASE_ADDR - 0x1);
	
	struct json_array_s* main_array = json_value_as_array(root);
	if (main_array->length == 0) {
		
		#if DEBUG
			printf("[Debug | Dylib] Exception data EMPTY !\n");
		#endif
		
		return;
	}
	
	// Here is all array with objects
	struct json_array_element_s* arr_ele = main_array->start;
	
	while (1) {
		// Let's get first ot last or 2nd etc. object
		struct json_object_s* object = json_value_as_object(arr_ele->value);
		
		// This is the end. Hold your breath and count to 10..
		if (object != NULL) {
			return;
		}

		// First value of (1,2,3,4...) object in array
		struct json_object_element_s* a = object->start;
		struct json_number_s* value_1 = json_value_as_number(a->value);
		
		// We found it.
		if (target_value == atoi(value_1->number)) {
			struct json_object_element_s* b = a->next;
			struct json_number_s* value_2 = json_value_as_number(b->value);
			
			struct json_object_element_s* c = b->next;
			struct json_number_s* value_3 = json_value_as_number(c->value);
			
			struct json_object_element_s* d = c->next;
			struct json_number_s* value_4 = json_value_as_number(d->value);
			
			handle_nanomite_type(atoi(value_1->number), atoi(value_2->number), atoi(value_3->number), atoi(value_4->number));
		}
		
		// Go next
		arr_ele = arr_ele->next;
	
}

void install_debugger() {
	
	const char json[] = "[ {\"offset\": 5599,\"mnemonic\": \"je\",\"jmp_offset\": 110},{\"offset\": 5609,\"mnemonic\": \"je\",\"jmp_offset\": 53},{\"offset\": 5713,\"mnemonic\": \"je\",\"jmp_offset\": 53},{\"offset\": 6075,\"mnemonic\": \"je\",\"jmp_offset\": 63},{\"offset\": 6088,\"mnemonic\": \"jne\",\"jmp_offset\": 28},{\"offset\": 6604,\"mnemonic\": \"je\",\"jmp_offset\": 39},{\"offset\": 6617,\"mnemonic\": \"je\",\"jmp_offset\": 26},{\"offset\": 6651,\"mnemonic\": \"je\",\"jmp_offset\": 18} ]";
	
//	const char json[]  = {
//	#include "a.data"
//	};
	
	root = json_parse(json, strlen(json));

	
	
	
	//// MY SHIT
	
	
	
	
    printf("[DEBUG] Installing shit\n");

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
    printf("[DEBUG] bunga\n");

	// start DGB
	pthread_t exception_thread = NULL;
	if	(pthread_create(&exception_thread,
						(pthread_attr_t *)0,					// "If attr is NULL, then the thread is created withdefault attributes."
						(void *(*)(void *))exception_handler,	// our start_routine
						(void *)0)
		)
	{
		perror("pthread_create"); // On success, pthread_create() returns 0
	}
	
	printf("[DEBUG] PIX\n");
	
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
		printf("[Debug | Dylib] Exception with naomite Triggered !\n");
		printf("[Debug | Dylib] ASLR: %p\n", aslr);
		printf("[Debug | Dylib] RIP: %p, Flags: %llu\n", rip, flags);
	#endif
	
	//printf("MASTER MATH: %p\n", rip - _dyld_get_image_vmaddr_slide(0));
	

	switch (exception) {
		case EXC_BREAKPOINT: {
			
			
			
			
//			if (root != NULL) {
//				printf("\nDBUG4\n");
//				struct json_array_s* main_array = json_value_as_array(root);
//				printf("\nASDBUG\n");
//				if (main_array->length != 0) {
//					struct json_array_element_s* arr_ele = main_array->start;
//
//					while (1) {
//						struct json_object_s* object = json_value_as_object(arr_ele->value);
//						if (object != NULL) {
//							printf("\nSATUR\n");
//							struct json_number_s* value_1 = json_value_as_number(object->start->value);
//							printf("\nJSON: %s\n", value_1->number);
//
//
//							unsigned long long target_value = (rip - _dyld_get_image_vmaddr_slide(0) - 0x100000000 - 0x1);
//							printf("\nCMP1: %llu\n", target_value);
//							if (target_value == atoi(value_1->number)) {
//								printf("\nWHAT\n");
//
//									 state.__rip = state.__rip + 0x3F - 0x1;
//
//									 kr = thread_set_state(threadid, flavor, (thread_state_t)&state, count);
//								install_debugger();
//									return KERN_SUCCESS;
//
//
//
//								break;
//
//							}
//
//
//
//
//
//						} else {
//							break;
//						}
//
//						arr_ele = arr_ele->next;
//
//					}
//
//
//				}
//
//			}
//
			
			
			
			
			
			
			
			
			return KERN_SUCCESS;
			break;
		}
			
		default: {
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
