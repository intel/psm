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

// This file contains the initialization functions used by the low
// level infinipath protocol code.

#include <sys/poll.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>

#include "ipserror.h"
#include "ipath_user.h"

#include <altivec.h>

union piovec {
	vector unsigned int	vec;
	uint32_t		dw[4];
};

/*
 * These pio copy routines are here so they can be used by test code, as well
 * as by MPI, and can change independently of MPI
*/

/*
 * for processors that may not write store buffers in the order filled,
 * and when the store buffer is not completely filled (partial at end, or
 * interrupted and flushed) may write the partial buffer in
 * "random" order.  requires additional serialization
*/
void ipath_write_pio_force_order(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
	union ipath_pbc buf = {.qword = 0};
	volatile uint32_t *dpiob = (volatile uint32_t *)piob;
	uint32_t *dhdr = hdr;
	uint32_t *ddata = bdata;
	uint32_t dlen = pioparm->length >> 2;
	union piovec vec;
	volatile vector unsigned int *vpiob;
	uint32_t cksum_len = pioparm->cksum_is_valid ? 
	  IPATH_CRC_SIZE_IN_BYTES : 0;
	
	buf.length =
	  __cpu_to_le16(((IPATH_MESSAGE_HDR_SIZE + cksum_len) >> 2) + dlen + 1);
	if(pioparm->port > 1)
		buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) | 
					     __PBC_IBPORT |
					     pioparm->rate);
	else
		buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
					     pioparm->rate);

	vpiob = (volatile vector unsigned int *)dpiob;

	vec.dw[0] = buf.dword;
	vec.dw[1] = 0;
	vec.dw[2] = *dhdr++;
	vec.dw[3] = *dhdr++;
	*vpiob++ = vec.vec;
	ips_wmb();

	vec.dw[0] = *dhdr++;
	vec.dw[1] = *dhdr++;
	vec.dw[2] = *dhdr++;
	vec.dw[3] = *dhdr++;
	*vpiob++ = vec.vec;

	vec.dw[0] = *dhdr++;
	vec.dw[1] = *dhdr++;
	vec.dw[2] = *dhdr++;
	vec.dw[3] = *dhdr++;
	*vpiob++ = vec.vec;

	vec.dw[0] = *dhdr++;
	vec.dw[1] = *dhdr++;
	vec.dw[2] = *dhdr++;
	vec.dw[3] = *dhdr;

	if ( !dlen ) {
		ips_wmb();
		*vpiob++ = vec.vec;
		dpiob = (volatile uint32_t *) vpiob;
	} else {
		*vpiob++ = vec.vec;

		while ( dlen > 4 ) {
			vec.dw[0] = *ddata++;
			vec.dw[1] = *ddata++;
			vec.dw[2] = *ddata++;
			vec.dw[3] = *ddata++;
			*vpiob++ = vec.vec;
			dlen -= 4;
		}

		switch ( dlen ) {

			case 4: {
				vec.dw[0] = *ddata++;
				vec.dw[1] = *ddata++;
				vec.dw[2] = *ddata++;
				vec.dw[3] = *ddata;
				ips_wmb();
				*vpiob++ = vec.vec;
				dpiob = (volatile uint32_t *) vpiob;
			} break;

			case 3: {
				dpiob = (volatile uint32_t *)vpiob;
				*dpiob++ = *ddata++;
				*dpiob++ = *ddata++;
				ips_wmb();
				*dpiob++ = *ddata;
			} break;

			case 2: {
				dpiob = (volatile uint32_t *)vpiob;
				*dpiob++ = *ddata++;
				ips_wmb();
				*dpiob++ = *ddata;
			} break;

			case 1: {
				dpiob = (volatile uint32_t *)vpiob;
				ips_wmb();
				*dpiob++ = *ddata;
			} break;
		}
	}

	/* If checksum is enabled insert CRC at end of packet */
	if_pf (pioparm->cksum_is_valid){
	  int nCRCopies = IPATH_CRC_SIZE_IN_BYTES >> 2;
	  int nCRC = 0;
	  
	  while (nCRC < (nCRCopies-1)) {
	    *dpiob = pioparm->cksum;
	    dpiob++;
	    nCRC++;
	  }
	  
	  asm volatile("" : : : "memory"); // prevent compiler reordering
	  *dpiob = pioparm->cksum;
	}
    
	ips_wmb();

	return;
}

/*
 * for processors that always write store buffers in the order filled,
 * and if store buffer not completely filled (partial at end, or
 * interrupted and flushed) always write the partial buffer in
 * address order.  Avoids serializing and flush instructions
 * where possible.
 */
void ipath_write_pio(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
	union ipath_pbc buf = {.qword = 0};
	volatile uint32_t *dpiob = piob;
	uint32_t *dhdr = hdr;
	uint32_t *ddata = bdata;
	uint32_t dlen = pioparm->length >> 2;
	uint32_t cksum_len = pioparm->cksum_is_valid ? 
	  IPATH_CRC_SIZE_IN_BYTES : 0;
	
	buf.length =
	  __cpu_to_le16(((IPATH_MESSAGE_HDR_SIZE + cksum_len) >> 2) + dlen + 1);
	if(pioparm->port > 1)
		buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) | 
					     __PBC_IBPORT | 
					     pioparm->rate);
	else
		buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
					     pioparm->rate);

	*dpiob++ = buf.dword;
	asm volatile("" : : : "memory");
	*dpiob++ = 0;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	*dpiob++ = *dhdr++;
	if ( !dlen ) {
		asm volatile("" : : : "memory");
		*dpiob++ = *dhdr;
	} else {
		*dpiob++ = *dhdr;

		while ( dlen > 1 ) {
			*dpiob++ = *ddata++;
			dlen -= 1;
		}

		asm volatile("" : : : "memory");
		*dpiob++ = *ddata;
	}
	
	/* If checksum is enabled insert CRC at end of packet */
	if_pf (pioparm->cksum_is_valid){
	  int nCRCopies = IPATH_CRC_SIZE_IN_BYTES >> 2;
	  int nCRC = 0;
	  
	  while (nCRC < (nCRCopies-1)) {
	    *dpiob = pioparm->cksum;
	    dpiob++;
	    nCRC++;
	  }
	  
	  asm volatile("" : : : "memory"); // prevent compiler reordering
	  *dpiob = pioparm->cksum;
	}
    
	ips_wmb();

	return;
}

void ipath_write_pio_special_trigger2k(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
	_IPATH_ERROR("no special trigger 2k support for ppc\n");
}

void ipath_write_pio_special_trigger4k(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
	_IPATH_ERROR("no special trigger 4k support for ppc\n");
}
