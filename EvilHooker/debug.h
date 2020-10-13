#pragma once

#ifndef _EVIL_DEBUG_H_INCLUDED_
#define _EVIL_DEBUG_H_INCLUDED_

#include <wdm.h>

//
// set this to 1 if enable debug prints
//
#define DEBUG_ENABLE 1

#if DEBUG_ENABLE
#define KDBG(format, ...) DbgPrint(format, __VA_ARGS__)
#else
#define KDBG(format, ...) 
#endif

#define KDBG_ENTER_FUNCTION(_) KDBG("[Evil] ---> Entering %s ...\n", __FUNCTION__)
#define KDBG_LEAVE_FUNCTION(_) KDBG("[Evil] <--- Leaving %s\n", __FUNCTION__)

#endif