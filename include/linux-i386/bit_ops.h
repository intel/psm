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

#ifndef _IPATH_i386_BIT_OPS_H
#define _IPATH_i386_BIT_OPS_H

static __inline__ void ips_clear_bit(int nr, volatile unsigned long *addr)
{
    asm volatile(LOCK_PREFIX "btrl %1,%0" : "=m" (*addr) : "dIr"(nr));
}

static __inline__ void ips_change_bit(int nr, volatile unsigned long *addr)
{
    asm volatile(LOCK_PREFIX "btcl %1,%0" : "=m" (*addr) : "dIr"(nr));
}

static __inline__ int ips_test_and_set_bit(int nr, volatile unsigned long *addr)
{
    int oldbit;

    asm volatile(LOCK_PREFIX "btsl %2,%1\n\tsbbl %0,%0" : "=r" (oldbit),
		 "=m" (*addr) : "dIr" (nr) : "memory");
    return oldbit;
}

static __inline__ void ips___clear_bit(int nr, volatile unsigned long *addr)
{
    asm volatile("btrl %1,%0" : "=m" (*addr) : "dIr"(nr));
}

static __inline__ void ips___change_bit(int nr, volatile unsigned long *addr)
{
    asm volatile("btcl %1,%0" : "=m" (*addr) : "dIr"(nr));
}

static __inline__ int ips___test_and_set_bit(int nr,
					     volatile unsigned long *addr)
{
    int oldbit;

    asm volatile("btsl %2,%1\n\tsbbl %0,%0" : "=r" (oldbit),
		 "=m" (*addr) : "dIr" (nr) : "memory");
    return oldbit;
}

#endif /* _IPATH_i386_BIT_OPS_H */
