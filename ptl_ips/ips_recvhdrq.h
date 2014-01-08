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

#include "psm_user.h"
#include "ips_proto.h"
#include "ips_proto_header.h"
#include "ips_proto_params.h"
#include "ips_recvq.h"

#ifndef _IPS_RECVHDRQ_H
#define _IPS_RECVHDRQ_H

struct ips_recvhdrq;
struct ips_recvhdrq_state;
struct ips_epstate;

#define IPS_RECVHDRQ_CONTINUE   0
#define IPS_RECVHDRQ_BREAK      1
#define IPS_RECVHDRQ_OOO	2   /* out of order */
#define IPS_RECVHDRQ_ELEMSZ_MAX 32  /* 128 bytes */
#define LAST_RHF_SEQNO 13

/* CCA related receive events */
#define IPS_RECV_EVENT_FECN 0x1
#define IPS_RECV_EVENT_BECN 0x2

struct ips_recvhdrq_event {
    struct ips_proto	      *proto;
    const struct ips_recvhdrq *recvq;	    /* where message received */
    const uint32_t	      *rcv_hdr;	    /* rcv_hdr ptr */
    const __le32              *rhf;	    /* receive header flags */
    struct ips_message_header *p_hdr;	    /* protocol header in rcv_hdr */
    struct ptl_epaddr	      *ipsaddr;	    /* peer ipsaddr, if available */
    psm_epid_t                 epid;        /* peer epid */
    uint32_t		       error_flags; /* error flags */
    uint8_t                    has_cksum;   /* payload has cksum */
    uint8_t                    is_congested;/* Packet faced congestion */
    uint16_t		       ptype;	    /* packet type */
};

struct ips_recvhdrq_callbacks {
    int (*callback_packet_unknown)(const struct ips_recvhdrq_event *);
    int (*callback_subcontext)(const struct ips_recvhdrq_event *, uint32_t subcontext);
    int (*callback_error)(struct ips_recvhdrq_event *);
};

psm_error_t 
ips_recvhdrq_init(const psmi_context_t *context,
		  const struct ips_epstate *epstate,
		  const struct ips_proto *proto,
		  const struct ips_recvq_params *hdrq_params,
		  const struct ips_recvq_params *egrq_params,
		  const struct ips_recvhdrq_callbacks *callbacks,
		  uint32_t flags,
		  uint32_t subcontext,
		  struct ips_recvhdrq *recvq,
		  struct ips_recvhdrq_state *recvq_state);

psm_error_t
ips_recvhdrq_progress(struct ips_recvhdrq *recvq);

psm_error_t
ips_recvhdrq_fini(struct ips_recvhdrq *recvq);

/*
 * Structure containing state for recvhdrq reading. This is logically
 * part of ips_recvhdrq but needs to be separated out for context
 * sharing so that it can be put in a shared memory page and hence
 * be available to all processes sharing the context. Generally, do not 
 * put pointers in here since the address map of each process can be 
 * different.  
 */
#define NO_EAGER_UPDATE ~0U
struct ips_recvhdrq_state
{
  uint32_t hdrq_head;			/* software copy of head */
  uint32_t rcv_egr_index_head;          /* software copy of eager index head*/
  uint32_t hdrq_rhf_seq; 		/* QLE73XX/QLE72XX last seq */	     
  uint32_t head_update_interval;        /* Header update interval */
  uint32_t num_hdrq_done;               /* Num header queue done */
  uint32_t hdr_countdown;		/* for false-egr-full tracing */
};

/*
 * Structure to read from recvhdrq
 */
typedef psm_error_t (*ips_recvhdrq_progress_fn_t)(struct ips_recvhdrq *recvq);

struct ips_recvhdrq
{
    struct ips_proto  *proto;
    const psmi_context_t *context; /* error handling, epid id, etc. */
    ips_recvhdrq_progress_fn_t	progress_fn;
    struct ips_recvhdrq_state *state;
    uint32_t	       context_flags; /* derived from base_info.spi_runtime_flags */
    uint32_t	       subcontext;   /* messages that don't match subcontext call
				    * recv_callback_subcontext */

    /* Header queue handling */
    pthread_spinlock_t	     hdrq_lock;	    /* Lock for thread-safe polling */
    uint32_t		     hdrq_rhf_off;  /* QLE73XX/QLE72XX rhf offset */
    int			     hdrq_rhf_notail; /* rhf notail enabled */
    uint32_t		     hdrq_elemlast; /* last element precomputed */
    struct ips_recvq_params  hdrq;

    /* Eager queue handling */
    void		  **egrq_buftable;  /* table of eager idx-to-ptr */
    struct ips_recvq_params egrq;

    /* Lookup endpoints epid -> ptladdr (rank)) */
    const struct ips_epstate	*epstate;

    /* Callbacks to handle recvq events */
    struct ips_recvhdrq_callbacks recvq_callbacks;

    /* List of flows with pending acks for receive queue */
    SLIST_HEAD(pending_flows, ips_flow) pending_acks;

    uint32_t	      runtime_flags;
    volatile __u64   *spi_status; 
};

PSMI_INLINE(
int ips_recvhdrq_isempty(const struct ips_recvhdrq *recvq))
{
    if (recvq->hdrq_rhf_notail) /* use rhf-based reads */
	return recvq->state->hdrq_rhf_seq != 
	       ipath_hdrget_seq(
		    recvq->hdrq.base_addr + recvq->state->hdrq_head + 
		    recvq->hdrq_rhf_off);
    else
	return ips_recvq_tail_get(&recvq->hdrq) == recvq->state->hdrq_head;
}

PSMI_INLINE(
void *ips_recvhdrq_event_payload(const struct ips_recvhdrq_event *rcv_ev))
{
    /* XXX return NULL if no eager buffer allocated */
    return ips_recvq_egr_index_2_ptr(rcv_ev->recvq->egrq_buftable,
				     ipath_hdrget_index(rcv_ev->rhf));
}

PSMI_INLINE(
int ips_recvhdrq_trylock(struct ips_recvhdrq *recvq))
{
    int ret = pthread_spin_trylock(&recvq->hdrq_lock);
    return !ret;
}

PSMI_INLINE(
int ips_recvhdrq_lock(struct ips_recvhdrq *recvq))
{
    int ret = pthread_spin_lock(&recvq->hdrq_lock);
    return !ret;
}

PSMI_INLINE(
int ips_recvhdrq_unlock(struct ips_recvhdrq *recvq))
{
    int ret = pthread_spin_unlock(&recvq->hdrq_lock);
    return !ret;
}

PSMI_INLINE(
uint32_t ips_recvhdrq_event_paylen(const struct ips_recvhdrq_event *rcv_ev))
{
  uint32_t cksum_len = rcv_ev->has_cksum ? PSM_CRC_SIZE_IN_BYTES : 0;
  
  return ipath_hdrget_length_in_bytes(rcv_ev->rhf) -
    (sizeof(struct ips_message_header) + CRC_SIZE_IN_BYTES + cksum_len + 
     ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3)); /* padding */
}

#endif /* _IPS_RECVHDRQ_H */

