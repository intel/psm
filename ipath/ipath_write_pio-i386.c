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
    uint32_t cksum_len = pioparm->cksum_is_valid ? 
      IPATH_CRC_SIZE_IN_BYTES : 0;

    buf.length =
        __cpu_to_le16(((IPATH_MESSAGE_HDR_SIZE + cksum_len + pioparm->length) >> 2) + 1);
    if(pioparm->port > 1)
      buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT | 
				   __PBC_IBPORT |
				   pioparm->rate);
    else
      buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
				   pioparm->rate);

    *piob++ = buf.dword;
    // 32 bit programs require fence after first 32 bits of pbc write
    // Can't do as uint64_t store, or compiler could reorder
    ips_wmb();
    *piob++ = buf.pbcflags;

    if(!pioparm->length) {
        uint32_t *dhdr, dcpywords;
        dcpywords = (IPATH_MESSAGE_HDR_SIZE >> 2)-1;
        ipath_dwordcpy_safe(piob, hdr, dcpywords);
        ips_wmb();
        dhdr = hdr;
        piob += dcpywords;
        dhdr += dcpywords;
        *piob++ = *dhdr;
    } else {
        uint32_t *pay2 = bdata, j;
	uint32_t len = pioparm->length;

        ipath_dwordcpy_safe(piob, hdr,
            IPATH_MESSAGE_HDR_SIZE >> 2);
        piob += IPATH_MESSAGE_HDR_SIZE >> 2;

        len >>= 2;
        if(len>16) {
            uint32_t pay_words = 16*((len-1)/16);
            ipath_dwordcpy_safe(piob, pay2, pay_words);
            piob += pay_words;
            pay2 += pay_words;
            len -= pay_words;
        }
        // now write the final chunk a word at a time, fence before trigger
        for(j=0;j<(len-1);j++)
           *piob++ = *pay2++;
        ips_wmb(); // flush the buffer out now, so
        *piob++ = *pay2;
    }
    
    /* If checksum is enabled insert CRC at end of packet */
    if_pf (pioparm->cksum_is_valid){
      int nCRCopies = IPATH_CRC_SIZE_IN_BYTES >> 2;
      int nCRC = 0;
      
      while (nCRC < (nCRCopies-1)) {
	*piob = pioparm->cksum;
	piob++;
	nCRC++;
      }
      
      ips_wmb();
      *piob = pioparm->cksum;
    }

    /* send it on it's way, now, rather than waiting for processor to
     * get around to flushing it */
    ips_wmb();
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
    union ipath_pbc buf = {0};
    uint32_t cksum_len = pioparm->cksum_is_valid ? 
      IPATH_CRC_SIZE_IN_BYTES : 0;

    buf.length =
        __cpu_to_le16(((IPATH_MESSAGE_HDR_SIZE + cksum_len + pioparm->length) >> 2) + 1);
    if(pioparm->port > 1)
        buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) | 
				     __PBC_IBPORT |
				     pioparm->rate);
    else
        buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
				     pioparm->rate);
    
    *piob++ = buf.dword;
    // 32 bit programs needs compiler fence to prevent compiler reordering
    // the two 32 bit stores in a uint64_t, but on inorder wc systems, does not
    // need a memory fence.
    asm volatile("" : : : "memory");
    *piob++ = buf.pbcflags;

    ipath_dwordcpy_safe(piob, hdr,
        IPATH_MESSAGE_HDR_SIZE >> 2);
    piob += IPATH_MESSAGE_HDR_SIZE >> 2;
    asm volatile("" : : : "memory"); // prevent compiler reordering

    if(pioparm->length) 
        ipath_dwordcpy_safe(piob, (uint32_t*)bdata, pioparm->length>>2);
    
    /* If checksum is enabled insert CRC at end of packet */
    if_pf (pioparm->cksum_is_valid){
      int nCRCopies = IPATH_CRC_SIZE_IN_BYTES >> 2;
      int nCRC = 0;
      
      piob += pioparm->length >> 2;
      
      while (nCRC < (nCRCopies-1)) {
	*piob = pioparm->cksum;
	piob++;
	nCRC++;
      }
      
      asm volatile("" : : : "memory"); // prevent compiler reordering
      *piob = pioparm->cksum;
    }
    
    /* send it on it's way, now, rather than waiting for processor to
     * get around to flushing it */
    ips_wmb();
}

/*
 * for processors that always write store buffers in the order filled,
 * and if store buffer not completely filled (partial at end, or
 * interrupted and flushed) always write the partial buffer in
 * address order.  Avoids serializing and flush instructions
 * where possible.
 */
static inline void ipath_write_pio_special_trigger(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata,
	unsigned offset)
{
    union ipath_pbc buf = {0};
    volatile uint32_t *piobs = piob;
    uint32_t cksum_len = pioparm->cksum_is_valid ? 
      IPATH_CRC_SIZE_IN_BYTES : 0;

    buf.length =
        __cpu_to_le16(((IPATH_MESSAGE_HDR_SIZE + cksum_len + pioparm->length) >> 2) + 1);
    if(pioparm->port > 1)
        buf.pbcflags = __cpu_to_le32((pioparm->vl << __PBC_VLSHIFT) | 
				     __PBC_IBPORT |
				     pioparm->rate);
    else
        buf.pbcflags = __cpu_to_le32(pioparm->vl << __PBC_VLSHIFT |
				     pioparm->rate);

    *piob++ = buf.dword;
    // 32 bit programs needs compiler fence to prevent compiler reordering
    // the two 32 bit stores in a uint64_t, but on inorder wc systems, does not
    // need a memory fence.
    asm volatile("" : : : "memory");
    *piob++ = buf.pbcflags;

    ipath_dwordcpy_safe(piob, hdr,
        IPATH_MESSAGE_HDR_SIZE >> 2);
    piob += IPATH_MESSAGE_HDR_SIZE >> 2;
    asm volatile("" : : : "memory"); // prevent compiler reordering
    
    if (pioparm->length) 
      ipath_dwordcpy_safe(piob, (uint32_t*)bdata, pioparm->length>>2);
    
    /* If checksum is enabled insert CRC at end of packet */
    if_pf (pioparm->cksum_is_valid){
      int nCRCopies = IPATH_CRC_SIZE_IN_BYTES >> 2;
      int nCRC = 0;
      
      piob += pioparm->length >> 2;
      
      while (nCRC < (nCRCopies-1)) {
	*piob = pioparm->cksum;
	piob++;
	nCRC++;
      }
      
      asm volatile("" : : : "memory"); // prevent compiler reordering
      *piob = pioparm->cksum;
    }
    
    /* send it on it's way, now, rather than waiting for processor to
     * get around to flushing it */
    ips_wmb();
    *(piobs + offset) = IPATH_SPECIAL_TRIGGER_MAGIC;
    ips_wmb();
}

void ipath_write_pio_special_trigger2k(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
    ipath_write_pio_special_trigger(piob, pioparm, hdr, bdata, 1023);
}

void ipath_write_pio_special_trigger4k(volatile uint32_t *piob,
	const struct ipath_pio_params *pioparm, void *hdr, void *bdata)
{
    ipath_write_pio_special_trigger(piob, pioparm, hdr, bdata, 2047);
}

