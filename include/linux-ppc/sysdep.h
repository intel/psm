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

#ifndef _IPATH_ppc64_SYSDEP_H
#define _IPATH_ppc64_SYSDEP_H

static __inline__ uint64_t get_cycles(void)
{
    uint64_t v;

#if __WORDSIZE == 64
    asm volatile("mftb %0" : "=r" (v) : );
#else
    uint32_t vu0, vu1, vl;
    do {
        asm volatile("mftbu %0" : "=r" (vu0) : );
        asm volatile("mftb %0"  : "=r" (vl) : );
        asm volatile("mftbu %0" : "=r" (vu1) : );
    } while ( vu0 != vu1 );

    v = vu1;
    v <<= 32;
    v |= vl;
#endif

    return v;
}

static __inline__ void ips_mb()
{
    asm volatile ("sync" : : : "memory");
}

static __inline__ void ips_rmb()
{
    asm volatile ("lwsync" : : : "memory");
}

static __inline__ void ips_wmb()
{
    asm volatile ("eieio" : : : "memory");
}

static __inline__ void ips_sync_writes()
{
    asm volatile("lwsync" : : : "memory");
}

static __inline__ void ips_sync_reads()
{
    asm volatile("isync" : : : "memory");
}

static __inline__ uint32_t ips_cmpxchg(volatile uint32_t *p, uint32_t old,
                                       uint32_t new)
{
    uint32_t prev;

    __asm__ __volatile__ ("\n\
1:  lwarx   %0,0,%2 \n\
    cmpw    0,%0,%3 \n\
    bne     2f \n\
    stwcx.  %4,0,%2 \n\
    bne-    1b\n\
    sync\n\
2:"
    : "=&r" (prev), "=m" (*p)
    : "r" (p), "r" (old), "r" (new), "m" (*p)
    : "cc", "memory");

    return prev;
}

#endif /* _IPATH_ppc64_SYSDEP_H */
