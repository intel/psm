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

#include "ips_writehdrq.h"

psm_error_t
ips_writehdrq_init(const psmi_context_t *context,
                   const struct ips_recvq_params *hdrq_params,
                   const struct ips_recvq_params *egrq_params,
                   struct ips_writehdrq *writeq,
                   struct ips_writehdrq_state *state,
                   uint32_t runtime_flags)
{
    const struct ipath_base_info *base_info = &context->base_info;
    memset(writeq, 0, sizeof(*writeq));
    writeq->context = context;
    writeq->state = state;
    writeq->hdrq = *hdrq_params; /* deep copy */
    writeq->hdrq_elemlast = ((writeq->hdrq.elemcnt - 1) * writeq->hdrq.elemsz);
    writeq->egrq = *egrq_params; /* deep copy */
    writeq->egrq_buftable =
        ips_recvq_egrbuf_table_alloc(context->ep, writeq->egrq.base_addr,
                                     base_info->spi_rcv_egrchunksize,
                                     writeq->egrq.elemcnt,
				     writeq->egrq.elemsz);
    writeq->runtime_flags = runtime_flags;
    writeq->hdrq_rhf_off = base_info->spi_rhf_offset;
    if (writeq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
	writeq->state->hdrq_rhf_seq = 1; 
	/*
	 * We don't allow readers to see the RHF until the writer can
	 * atomically write an updated RHF.
	 */
	writeq->hdrq_hdr_copysz = (writeq->hdrq.elemsz - 2) * sizeof(uint32_t);
	/*
	 * Ensure 8-byte alignment of the RHF by looking at RHF of the second
	 * header, which is required for atomic RHF updates.
	 */
	psmi_assert_always(
	    !((uintptr_t)(writeq->hdrq.base_addr + 
			  writeq->hdrq.elemsz + writeq->hdrq_rhf_off) & 0x7));
    }
    else {
	writeq->hdrq_hdr_copysz = writeq->hdrq.elemsz * sizeof(uint32_t);
	writeq->state->hdrq_rhf_seq = 0; /* _seq is ignored */
    }
    writeq->state->enabled = 1;
    return PSM_OK;
}

psm_error_t
ips_writehdrq_fini(struct ips_writehdrq *writeq)
{
    ips_recvq_egrbuf_table_free(writeq->egrq_buftable);
    return PSM_OK;
}
