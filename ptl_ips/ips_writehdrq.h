/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
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

#ifndef _IPS_WRITEHDRQ_H
#define _IPS_WRITEHDRQ_H

#include "psm_user.h"
#include "ips_recvhdrq.h"
#include "ips_recvq.h"
#include "psm_mq_internal.h"

/*
 * Structure containing state for writehdrq writing. This is logically
 * part of ips_writehdrq but needs to be separated out for context
 * sharing so that it can be put in a shared memory page and hence
 * be available to all processes sharing the port. Generally, do not 
 * put pointers in here since the address map of each process can be 
 * different.  
 */
struct ips_writehdrq_state
{
    uint32_t		     hdrq_rhf_seq;	/* last seq */
    uint32_t		     enabled;		/* enables writing */
};

struct ips_writehdrq
{
    const psmi_context_t    *context;
    struct ips_writehdrq_state *state;
    struct ips_recvq_params  hdrq;
    uint32_t                 hdrq_elemlast;
    uint32_t		     hdrq_rhf_off;	/* rhf offset */
    uint32_t		     hdrq_hdr_copysz;
    struct ips_recvq_params  egrq;
    void	           **egrq_buftable; /* table of eager idx-to-ptr */
    uint32_t		     runtime_flags;
};

psm_error_t
ips_writehdrq_init(const psmi_context_t *context,
                   const struct ips_recvq_params *hdrq_params,
                   const struct ips_recvq_params *egrq_params,
                   struct ips_writehdrq *writeq,
                   struct ips_writehdrq_state *state,
                   uint32_t runtime_flags);

psm_error_t
ips_writehdrq_fini(struct ips_writehdrq *writeq);

PSMI_ALWAYS_INLINE(
void
ips_writehdrq_write_rhf_atomic(uint32_t *rhf_dest, uint32_t *rhf_src))
{
#if WORDSIZE == 64
    /*
     * In 64-bit mode, we check in init that the rhf will always be 8-byte
     * aligned
     */
    *((uint64_t *)rhf_dest) = *((uint64_t *)rhf_src);
#else
    /* 
     * In 32-bit mode, we ensure that word 0 always gets written before word 1
     */
    rhf_dest[0] = rhf_src[0];
    ips_wmb();
    rhf_dest[1] = rhf_src[1];
#endif
    return;
}

PSMI_INLINE(
int
ips_writehdrq_append(struct ips_writehdrq *writeq,
		     const struct ips_recvhdrq_event *rcv_ev))
{
    const uint32_t *rcv_hdr = rcv_ev->rcv_hdr;
    uint32_t write_hdr_head;
    uint32_t write_hdr_tail;
    uint32_t *write_hdr;
    uint32_t *write_rhf;
    char *write_payload = NULL;
    uint32_t next_write_hdr_tail;
    uint32_t rcv_paylen;
    union {
	uint32_t    u32[2];
	uint64_t    u64;
    } rhf;
    int result = IPS_RECVHDRQ_CONTINUE;

    /* Drop packet if write header queue is disabled */
    if (!writeq->state->enabled) {
        result = IPS_RECVHDRQ_BREAK;
        goto done;
    }

    write_hdr_head = ips_recvq_head_get(&writeq->hdrq);
    write_hdr_tail = ips_recvq_tail_get(&writeq->hdrq);
    write_hdr = writeq->hdrq.base_addr + write_hdr_tail;
    write_rhf = write_hdr + writeq->hdrq_rhf_off;

    /* Drop packet if write header queue is full */
    next_write_hdr_tail = write_hdr_tail + writeq->hdrq.elemsz;
    if (next_write_hdr_tail > writeq->hdrq_elemlast)
	next_write_hdr_tail = 0;
    if (next_write_hdr_tail == write_hdr_head) {
        result = IPS_RECVHDRQ_BREAK;
        goto done;
    }

    /* 
     * If NORDMA_TAIL, don't let consumer see RHF until it's ready.  We copy
     * the source rhf and operate on it until we are ready to atomically update
     * it for the reader.
     */
    if (writeq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
	write_rhf = &rhf.u32[0];
	rhf.u64 = *((uint64_t *) rcv_ev->rhf);
    }

    /* Copy the data if this is an eager packet */
    rcv_paylen = ips_recvhdrq_event_paylen(rcv_ev);
    rcv_paylen += (rcv_ev->has_cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
    
    if (rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER && rcv_paylen > 0)
    {
	uint32_t write_egr_tail = ips_recvq_tail_get(&writeq->egrq);
	uint32_t next_write_egr_tail;

	/* Drop packet if write eager queue is full */
	next_write_egr_tail = write_egr_tail + 1;
	if (next_write_egr_tail >= writeq->egrq.elemcnt)
	    next_write_egr_tail = 0;
	if (next_write_egr_tail == ips_recvq_head_get(&writeq->egrq)) {
            /* Copy the header to the subcontext's header queue */
            psmi_mq_mtucpy(write_hdr, rcv_hdr, writeq->hdrq_hdr_copysz);

	    /* Mark header with ETIDERR (eager overflow) */
	    ipath_hdrset_err_flags(write_rhf, INFINIPATH_RHF_H_TIDERR);

	    /* Fix up the header with current subcontext eager index */
	    ipath_hdrset_index(write_rhf, write_egr_tail);

            result = IPS_RECVHDRQ_BREAK;
	}
	else {
            if (rcv_paylen) {
	        const char *rcv_payload = ips_recvhdrq_event_payload(rcv_ev);

	        /* Use pre-calculated address from look-up table */
                write_payload = ips_recvq_egr_index_2_ptr(
                                    writeq->egrq_buftable, write_egr_tail);

	        psmi_mq_mtucpy(write_payload, rcv_payload, rcv_paylen);
	    }

            /* Copy the header to the subcontext's header queue */
            psmi_mq_mtucpy(write_hdr, rcv_hdr, writeq->hdrq_hdr_copysz);

	    /* Fix up the header with the subcontext's eager index */
	    ipath_hdrset_index((uint32_t *) write_rhf, write_egr_tail);

	    /* Update the eager buffer tail pointer */
            ips_recvq_tail_update(&writeq->egrq, next_write_egr_tail);
	}
    }
    else {
        /* Copy the header to the subcontext's header queue */
        psmi_mq_mtucpy(write_hdr, rcv_hdr, writeq->hdrq_hdr_copysz);

	/* Copy the value of the current egr tail, handles the
	 * eager-with-no-payload case */
	if (rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER)
	    ipath_hdrset_index((uint32_t *) write_rhf,
			   ips_recvq_tail_get(&writeq->egrq));
    }

    /* Ensure previous writes are visible before writing rhf seq or tail */
    ips_wmb();

    if (writeq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
	/* We accumulated a few changes to the RHF and now want to make it
	 * atomically visible for the reader.
	 */
        uint32_t rhf_seq = writeq->state->hdrq_rhf_seq;
        ipath_hdrset_seq((uint32_t *) write_rhf, rhf_seq);
        if (rhf_seq >= LAST_RHF_SEQNO)
            writeq->state->hdrq_rhf_seq = 1;
        else
            writeq->state->hdrq_rhf_seq = rhf_seq + 1;

	/* Now write the new rhf */
	ips_writehdrq_write_rhf_atomic(write_hdr + writeq->hdrq_rhf_off, write_rhf);
    }

    /* The tail must be updated regardless of IPATH_RUNTIME_NODMA_RTAIL
     * since this tail is also used to keep track of where 
     * ips_writehdrq_append will write to next. For subcontexts there is 
     * no separate shadow copy of the tail. */
    ips_recvq_tail_update(&writeq->hdrq, next_write_hdr_tail);

done:
    return result;
}

#endif /* _IPS_WRITEHDRQ_H */
