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

#ifndef _IPATH_ppc64_BIT_OPS_H
#define _IPATH_ppc64_BIT_OPS_H

#if defined(__powerpc64__)
#	define _NRMASK 63
#	define _NRSHIFT 6
#	define _NRSWIZZ 0
#	define _LLARX "ldarx "
#	define _STLCX "stdcx. "
#else
#	define _NRMASK 31
#	define _NRSHIFT 5
#	define _NRSWIZZ 1
#	define _LLARX "lwarx "
#	define _STLCX "stwcx. "
#endif

static __inline__ unsigned long ips___nrmask(int nr)
{
	return 1UL << (nr & _NRMASK);
}

static __inline__ int ips___nroffset(int nr)
{
	return (nr >> _NRSHIFT) ^ _NRSWIZZ;
}

static __inline__ void ips_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long old;
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);

	__asm__ __volatile__(
"1:"	_LLARX "%0,0,%3  \n"
	"andc   %0,%0,%2 \n"
	_STLCX "%0,0,%3  \n"
	"bne-   1b"
	: "=&r" (old), "=m" (*p)
	: "r" (mask), "r" (p), "m" (*p)
	: "cc");
}

static __inline__ void ips_change_bit(int nr, volatile unsigned long *addr)
{
	unsigned long old;
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);

	__asm__ __volatile__(
"1:"	_LLARX "%0,0,%3  \n"
	"xor    %0,%0,%2 \n"
	_STLCX "%0,0,%3  \n"
	"bne-   1b"
	: "=&r" (old), "=m" (*p)
	: "r" (mask), "r" (p), "m" (*p)
	: "cc");
}

static __inline__ int ips_test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long old, t;
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);

	__asm__ __volatile__(
	"eieio           \n"
"1:"	_LLARX "%0,0,%3  \n"
	"or     %1,%0,%2 \n"
	_STLCX "%1,0,%3  \n"
	"bne-   1b       \n"
	"sync"
	: "=&r" (old), "=&r" (t)
	: "r" (mask), "r" (p)
	: "cc", "memory");

	return (old & mask) != 0;
}

static __inline__ void ips___clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);

	*p &= ~mask;
}

static __inline__ void ips___change_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);

	*p ^= mask;
}

static __inline__ int ips___test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = ips___nrmask(nr);
	volatile unsigned long *p = addr + ips___nroffset(nr);
	unsigned long old = *p;

	*p = old | mask;
	return (old & mask) != 0;
}

#undef _NRMASK
#undef _NRSHIFT
#undef _NRSWIZZ
#undef _LLARX
#undef _STLCX

#endif /* _IPATH_ppc64_BIT_OPS_H */
