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

#ifndef _IPS_RECVQ_H
#define _IPS_RECVQ_H

#include "psm_user.h"

struct ips_recvq_params {
    volatile __le32 *tail_register; /* location of tail */
    volatile __le32 *head_register; /* location of head */
    uint32_t	    *base_addr;	    /* base address of q */
    uint32_t	     elemsz;	    /* size of q elements (in words) */
    uint32_t	     elemcnt;	    /* num of q elements (in words) */
};

/*
 * Tables to map eager indexes into their buffer addresses
 *
 * If function returns NULL, no memory has been allocated and the error handler
 * has been executed on 'ep' and hence assume status PSM_NO_MEMORY.
 */
void **ips_recvq_egrbuf_table_alloc(psm_ep_t ep,
				    void *base, uint32_t chunksize, 
				    uint32_t bufnum, uint32_t bufsize);
void    ips_recvq_egrbuf_table_free(void **buftable);

/*
 * Accessor inlines for reading and writing to hdrq/egrq registers
 */
PSMI_ALWAYS_INLINE(
void *ips_recvq_egr_index_2_ptr(void **egrq_buftable, int index))
{
    return egrq_buftable[index];
}

PSMI_INLINE(
void ips_recvq_head_update(const struct ips_recvq_params *recvq, uint32_t newhead))
{
    *recvq->head_register = __cpu_to_le32(newhead);
    return;
}

PSMI_INLINE(
uint32_t ips_recvq_head_get(const struct ips_recvq_params *recvq))
{
    uint32_t res = __le32_to_cpu(*recvq->head_register);
    ips_rmb();
    return res;
}

PSMI_INLINE(
void ips_recvq_tail_update(const struct ips_recvq_params *recvq, uint32_t newtail))
{
    *recvq->tail_register = __cpu_to_le32(newtail);
    return;
}

PSMI_INLINE(
uint32_t ips_recvq_tail_get(const struct ips_recvq_params *recvq))
{
    uint32_t res = __le32_to_cpu(*recvq->tail_register);
    ips_rmb();
    return res;
}

#endif /* _IPS_RECVQ_H */
