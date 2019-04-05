//
//  debugger.c
//  debug
//
//  Created by Marek Kulik on 30/03/2019.
//  Copyright © 2019 OleOle. All rights reserved.
//

#include "debugger.h"
mach_port_t exception_port;

#define DEBUG 1


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
	
	/// Here after KERN_SUCCESS w will send reply MSG
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
						(pthread_attr_t *)0,					// "If attr is NULL, then the thread is created withdefault attributes."
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
// the logic of dealing with different exceptions stays here ??  gdb uses EXC_MASK_ALL,, we have different ports if the mask is different
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
	
	switch (exception) {
		// ONLY TEST (need to check ASLR)
		case EXC_BREAKPOINT: {
			printf("Here is address: %p\n", rip);
			
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
