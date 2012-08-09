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

#include <stdint.h>

#if defined(__x86_64__)
#define ipath_dwordcpy ipath_dwordcpy_safe
#endif

void ipath_dwordcpy(uint32_t *dest, const uint32_t *src, uint32_t ndwords)
{
	uint_fast32_t ndw = ndwords;
        uint64_t *src64[4];
        uint64_t *dst64[4];
        src64[0] = (uint64_t *)src;
        dst64[0] = (uint64_t *)dest;

        while ( ndw >= 8 ) {
                *dst64[0] = *src64[0];
                src64[1]  = src64[0]+1;
                src64[2]  = src64[0]+2;
                src64[3]  = src64[0]+3;
                ndw -= 8;
                dst64[1]   = dst64[0]+1;
                dst64[2]  = dst64[0]+2;
                dst64[3]  = dst64[0]+3;
                *dst64[1]  = *src64[1];
                *dst64[2]  = *src64[2];
                *dst64[3]  = *src64[3];
                src64[0] += 4;
                dst64[0] += 4;
        }
        if ( ndw ) {
                src = (uint32_t *)src64[0];
                dest = (uint32_t *)dst64[0];

		switch ( ndw ) {
		case 7: *dest++ = *src++;
		case 6: *dest++ = *src++;
		case 5: *dest++ = *src++;
		case 4: *dest++ = *src++;
		case 3: *dest++ = *src++;
		case 2: *dest++ = *src++;
		case 1: *dest++ = *src++;
		}
		
        }
}
