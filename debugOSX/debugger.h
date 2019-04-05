//
//  debugger.h
//  debug
//
//  Created by Marek Kulik on 30/03/2019.
//  Copyright © 2019 OleOle. All rights reserved.
//

#ifndef debugger_h
#define debugger_h

#include <stdio.h>


#include <mach/mach.h>			// mach_task_self()
#include <pthread.h>			// pthread

/// CUSTOM MAKROS
#define EXIT_ON_MACH_ERROR(msg, retval) \
if (kr != KERN_SUCCESS) { mach_error(msg ":" , kr); exit((retval)); }


// exception message we will receive from the kernel
typedef struct exc_msg {
	mach_msg_header_t          Head;
	mach_msg_body_t            msgh_body; // start of kernel-processed data
	mach_msg_port_descriptor_t thread;    // victim thread
	mach_msg_port_descriptor_t task;      // end of kernel-processed data
	NDR_record_t               NDR;       // see osfmk/mach/ndr.h
	exception_type_t           exception;
	mach_msg_type_number_t     codeCnt;   // number of elements in code[]
	exception_data_t           code;      // an array of integer_t
	char                       pad[512];  // for avoiding MACH_MSG_RCV_TOO_LARGE
} exc_msg_t;

// reply message we will send to the kernel
typedef struct rep_msg {
	mach_msg_header_t          Head;
	NDR_record_t               NDR;       // see osfmk/mach/ndr.h
	kern_return_t              RetCode;   // indicates to the kernel what to do
} reply_msg_t;


// prototypes
void install_debugger(void);
__attribute ((noinline)) void exception_handler(void);

// external prototypes
extern boolean_t exc_server(mach_msg_header_t *request, mach_msg_header_t *reply);
extern boolean_t mach_exc_server(mach_msg_header_t *request,mach_msg_header_t *reply);


#endif /* debugger_h */