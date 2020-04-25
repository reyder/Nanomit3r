//
//  NanoBreak.hpp
//  NanoBreak
//
//  Created by Marek Kulik on 05/04/2020.
//  Copyright © 2020 Marek Kulik. All rights reserved.
//

#ifndef NanoBreak_
#define NanoBreak_



#include <stdio.h>


#include <mach/mach.h>			// mach_task_self()
#include <pthread.h>			// pthread

/// CUSTOM MAKROS
#define EXIT_ON_MACH_ERROR(msg, retval) \
if (kr != KERN_SUCCESS) { mach_error(msg ":" , kr); exit((retval)); }


// Macros
#define BASE_ADDR 0x100000000
#define ZERO_FLAG 0x0040
#define SLAP_STACK_FRAME    asm("pop %rbp");


// From capstone
#define X86_INS_CALL 56
#define X86_INS_JAE 253
#define X86_INS_JA 254
#define X86_INS_JBE 255
#define X86_INS_JB 256
#define X86_INS_JCXZ 257
#define X86_INS_JECXZ 258
#define X86_INS_JE 259
#define X86_INS_JGE 260
#define X86_INS_JG 261
#define X86_INS_JLE 262
#define X86_INS_JL 263
#define X86_INS_JMP 264
#define X86_INS_JNE 265
#define X86_INS_JNO 266
#define X86_INS_JNP 267
#define X86_INS_JNS 268
#define X86_INS_JO 269
#define X86_INS_JP 270
#define X86_INS_JRCXZ 271
#define X86_INS_JS 272

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




#endif

