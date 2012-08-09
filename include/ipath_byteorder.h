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

#ifndef ipath_byteorder_h
#define ipath_byteorder_h

#ifdef __cplusplus
	extern "C" {
#endif

#include <sys/param.h>
#include <endian.h>

#ifndef __BYTE_ORDER
#	error "BYTE_ORDER undefined"
#endif

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

static __inline__ __u16 __ipath_fswab16(__u16) __attribute__ ((always_inline));
static __inline__ __u32 __ipath_fswab32(__u32) __attribute__ ((always_inline));
static __inline__ __u64 __ipath_fswab64(__u64) __attribute__ ((always_inline));

static __inline__ __u16 __ipath_fswab16(__u16 x)
{
	return    ((x & (__u16)0x00ffU) << 8)
		| ((x & (__u16)0xff00U) >> 8);
}

static __inline__ __u32 __ipath_fswab32(__u32 x)
{
	return    ((x & (__u32)0x000000ffUL) << 24)
		| ((x & (__u32)0x0000ff00UL) << 8)
		| ((x & (__u32)0x00ff0000UL) >> 8)
		| ((x & (__u32)0xff000000UL) >> 24);
}

static __inline__ __u64 __ipath_fswab64(__u64 x)
{
	return    ((x & (__u64)0x00000000000000ffULL) << 56)
		| ((x & (__u64)0x000000000000ff00ULL) << 40)
		| ((x & (__u64)0x0000000000ff0000ULL) << 24)
		| ((x & (__u64)0x00000000ff000000ULL) << 8)
		| ((x & (__u64)0x000000ff00000000ULL) >> 8)
		| ((x & (__u64)0x0000ff0000000000ULL) >> 24)
		| ((x & (__u64)0x00ff000000000000ULL) >> 40)
		| ((x & (__u64)0xff00000000000000ULL) >> 56);
}

static __inline__ __u16 __cpu_to_le16(__le16) __attribute__ ((always_inline));
static __inline__ __u32 __cpu_to_le32(__le32) __attribute__ ((always_inline));
static __inline__ __u64 __cpu_to_le64(__le64) __attribute__ ((always_inline));

static __inline__ __u16 __le16_to_cpu(__le16) __attribute__ ((always_inline));
static __inline__ __u32 __le32_to_cpu(__le32) __attribute__ ((always_inline));
static __inline__ __u64 __le64_to_cpu(__le64) __attribute__ ((always_inline));

static __inline__ __u16 __cpu_to_be16(__be16) __attribute__ ((always_inline));
static __inline__ __u32 __cpu_to_be32(__be32) __attribute__ ((always_inline));
static __inline__ __u64 __cpu_to_be64(__be64) __attribute__ ((always_inline));

static __inline__ __u16 __be16_to_cpu(__be16) __attribute__ ((always_inline));
static __inline__ __u32 __be32_to_cpu(__be32) __attribute__ ((always_inline));
static __inline__ __u64 __be64_to_cpu(__be64) __attribute__ ((always_inline));

#if __BYTE_ORDER == __LITTLE_ENDIAN

/*
 * __cpu_to_le* routines
 */
static __inline__ __le16 __cpu_to_le16(__u16 x)
{
	return x;
}

static __inline__ __le32 __cpu_to_le32(__u32 x)
{
	return x;
}

static __inline__ __le64 __cpu_to_le64(__u64 x)
{
	return x;
}

/*
 * __le*_to_cpu routines
 */
static __inline__ __u16 __le16_to_cpu(__le16 x)
{
	return x;
}

static __inline__ __u32 __le32_to_cpu(__le32 x)
{
	return x;
}

static __inline__ __u64 __le64_to_cpu(__le64 x)
{
	return x;
}

/*
 * __cpu_to_be* routines
 */
static __inline__ __be16 __cpu_to_be16(__u16 x)
{
	return __ipath_fswab16(x);
}

static __inline__ __be32 __cpu_to_be32(__u32 x)
{
	return __ipath_fswab32(x);
}

static __inline__ __be64 __cpu_to_be64(__u64 x)
{
	return __ipath_fswab64(x);
}

/*
 * __be*_to_cpu routines
 */
static __inline__ __u16 __be16_to_cpu(__be16 x)
{
	return __ipath_fswab16(x);
}

static __inline__ __u32 __be32_to_cpu(__be32 x)
{
	return __ipath_fswab32(x);
}

static __inline__ __u64 __be64_to_cpu(__be64 x)
{
	return __ipath_fswab64(x);
}

#elif __BYTE_ORDER == __BIG_ENDIAN

/*
 * __cpu_to_le* routines
 */
static __inline__ __le16 __cpu_to_le16(__u16 x)
{
	return __ipath_fswab16(x);
}

static __inline__ __le32 __cpu_to_le32(__u32 x)
{
	return __ipath_fswab32(x);
}

static __inline__ __le64 __cpu_to_le64(__u64 x)
{
	return __ipath_fswab64(x);
}

/*
 * __le*_to_cpu routines
 */
static __inline__ __u16 __le16_to_cpu(__le16 x)
{
	return __ipath_fswab16(x);
}

static __inline__ __u32 __le32_to_cpu(__le32 x)
{
	return __ipath_fswab32(x);
}

static __inline__ __u64 __le64_to_cpu(__le64 x)
{
	return __ipath_fswab64(x);
}

/*
 * __cpu_to_be* routines
 */
static __inline__ __be16 __cpu_to_be16(__u16 x)
{
	return x;
}

static __inline__ __be32 __cpu_to_be32(__u32 x)
{
	return x;
}

static __inline__ __be64 __cpu_to_be64(__u64 x)
{
	return x;
}

/*
 * __be*_to_cpu routines
 */
static __inline__ __u16 __be16_to_cpu(__be16 x)
{
	return x;
}

static __inline__ __u32 __be32_to_cpu(__be32 x)
{
	return x;
}

static __inline__ __u64 __be64_to_cpu(__be64 x)
{
	return x;
}

#else
#	error "unsupported BYTE_ORDER: " #BYTE_ORDER
#endif

#ifdef __cplusplus
	} // extern "C"
#endif

#endif // ipath_byteorder_h
