/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * Copyright (c) 2006-2012. QLogic Corporation. All rights reserved.
 * Copyright (c) 2003-2006, PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _IPATH_INTF_H
#define _IPATH_INTF_H

#include <sys/uio.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __inline__
#undef __inline__
#endif
#define __inline__ inline __attribute__((always_inline,unused))
#ifdef __unused__
#undef __unused__
#endif
#define __unused__ __attribute__((unused))

#include "sysdep.h"
#include "bit_ops.h"

/* these aren't implemented for user mode, which is OK until we multi-thread */
typedef struct _atomic {
	uint32_t counter;
} atomic_t;			/* no atomic_t type in user-land */
#define atomic_set(a,v) ((a)->counter = (v))
#define atomic_inc_return(a)  (++(a)->counter)

#if defined(__PATHCC__) && __PATHCC__ < 3
  #define likely(x)	(x)
  #define unlikely(x)	(x)
  #define if_pt(cond) if (cond)
  #define if_pf(cond) if (cond)
  #define _Pragma_unlikely _Pragma("mips_frequency_hint never")
  #define _Pragma_likely   _Pragma("mips_frequency_hint frequent")
#elif defined(__GNUC__) || (defined(__PATHCC__) && __PATHCC__ >= 3)
  #define likely(x)    __builtin_expect(!!(x), 1L)
  #define unlikely(x)  __builtin_expect(!!(x), 0L)
  #define if_pt(cond) if (likely(cond))
  #define if_pf(cond) if (unlikely(cond))
  #define _Pragma_unlikely
  #define _Pragma_likely
#else
  #error "Unsupported compiler"
#endif

#define yield() sched_yield()

/*
 * __fastpath is used to group routines in the fastpath, to reduce cache
 * misses and conflicts
 */
#define __fastpath __attribute__((section(".text.fastpath")))

/*
 * Move from using __fastpath to split __recvpath and __sendpath
 */
//#define __sendpath __attribute__((section(".text.sendpath")))
//#define __recvpath __attribute__((section(".text.recvpath")))
#define __sendpath __fastpath
#define __recvpath __fastpath

#endif				/* _IPATH_INTF_H */
