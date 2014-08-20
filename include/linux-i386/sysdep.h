/*
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

#ifndef _IPATH_i386_SYSDEP_H
#define _IPATH_i386_SYSDEP_H

static __inline__ uint64_t get_cycles(void)
{
    uint64_t v;
    uint32_t a,d;

    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    v = ((uint64_t)a) | (((uint64_t)d)<<32);

    return v;
}

#ifndef LOCK_PREFIX
#define LOCK_PREFIX "lock "
#endif

static __inline__ void ips_mb()
{
#ifdef __MIC__
    asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
    asm volatile("mfence" : : : "memory");
#endif
}

/* gcc-3.4 has a bug with this function body at -O0 */
static 
#if defined(__GNUC__) && !defined(__PATHCC__) && __GNUC__==3 && __GNUC_MINOR__==4
#else
__inline__ 
#endif
void ips_rmb()
{
#ifdef __MIC__
    asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
    asm volatile("" : : : "memory");
#endif
}

static __inline__ void ips_wmb()
{
#ifdef __MIC__
    asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
    asm volatile("sfence" : : : "memory");
#endif
}

static __inline__ void ips_sync_writes()
{
#ifdef __MIC__
    asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
    asm volatile("sfence" : : : "memory");
#endif
}

static __inline__ void ips_sync_reads()
{
#ifdef __MIC__
    asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
    asm volatile("lfence" : : : "memory");
#endif
}

static __inline__ uint32_t ips_cmpxchg(volatile uint32_t *ptr,
				       uint32_t old, uint32_t new)
{
    uint32_t prev;
    struct xchg_dummy { uint32_t a[100]; };

    asm volatile(LOCK_PREFIX "cmpxchgl %1,%2"
		 : "=a"(prev)
		 : "q"(new), "m"(*(struct xchg_dummy *)ptr), "0"(old)
		 : "memory");

    return prev;
}

typedef struct { volatile int32_t counter; } ips_atomic_t;

#define ips_atomic_set(v,i)		  (((v)->counter) = (i))
#define ips_atomic_cmpxchg(p,oval,nval)	  \
	    ips_cmpxchg((volatile uint32_t *) &((p)->counter),oval,nval)

#if 0
static __inline__ int32_t 
ips_cmpxchg(volatile int32_t *p, int32_t old_value, int32_t new_value)
{
  asm volatile ("lock cmpxchg %2, %0" :
                "+m" (*p), "+a" (old_value) :
                "r" (new_value) :
                "memory");
  return old_value;
}
#endif

#endif /* _IPATH_i386_SYSDEP_H */
