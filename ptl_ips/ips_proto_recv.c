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
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

#define PSM_STRAY_WARN_INTERVAL_DEFAULT_SECS	30
static void ips_report_strays(struct ips_proto *proto);

#define INC_TIME_SPEND(timer)

#define _desc_idx   u32w0
#define _desc_genc  u32w1

psm_error_t
ips_proto_recv_init(struct ips_proto *proto)
{
    uint32_t interval_secs;
    union psmi_envvar_val env_stray;

    psmi_getenv("PSM_STRAY_WARNINTERVAL", 
		"min secs between stray process warnings",
		PSMI_ENVVAR_LEVEL_HIDDEN, 
		PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) PSM_STRAY_WARN_INTERVAL_DEFAULT_SECS, 
		&env_stray);
    interval_secs = env_stray.e_uint;
    if (interval_secs > 0)
	proto->stray_warn_interval = sec_2_cycles(interval_secs);
    else
	proto->stray_warn_interval = 0;

    return PSM_OK;
}

psm_error_t
ips_proto_recv_fini(struct ips_proto *proto)
{
    ips_report_strays(proto);
    return PSM_OK;
}

#define cycles_to_sec_f(cycles)		    \
	(((double)cycles_to_nanosecs(cycles)) / 1000000000.0)

struct ips_stray_epid {
    psm_epid_t	epid;
    uint32_t	err_check_bad_sent;
    uint32_t	ipv4_addr;
    uint32_t	pid;
    uint32_t	num_messages;
    uint64_t	t_warn_next;
    uint64_t	t_first;
    uint64_t	t_last;
};

static
void
ips_report_strays(struct ips_proto *proto)
{
    struct ips_stray_epid *sepid;
    struct psmi_eptab_iterator itor;
    psmi_epid_itor_init(&itor, PSMI_EP_CROSSTALK);
    double t_runtime = cycles_to_sec_f(proto->t_fini - proto->t_init);

    while ((sepid = psmi_epid_itor_next(&itor))) {
	char ipbuf[INET_ADDRSTRLEN], *ip = NULL;
	char bufpid[32];
	uint32_t lid = psm_epid_nid(sepid->epid);
	double t_first = cycles_to_sec_f(sepid->t_first - proto->t_init);
	double t_last = cycles_to_sec_f(sepid->t_last - proto->t_init);
	if (sepid->ipv4_addr) 
	    ip = (char *) 
		inet_ntop(AF_INET, &sepid->ipv4_addr, ipbuf, sizeof ipbuf);
	if (!ip)
	    snprintf(ipbuf, sizeof ipbuf, "%d (%x)", lid, lid);

	if (sepid->pid)
	    snprintf(bufpid, sizeof bufpid, "PID=%d", sepid->pid);
	else
	    snprintf(bufpid, sizeof bufpid, "PID unknown");

	_IPATH_INFO("Process %s on host %s=%s sent %d stray message(s) and "
		    "was told so %d time(s) (first stray message at %.1fs "
		    "(%d%%), last at %.1fs (%d%%) into application run)\n",
		    bufpid, ip ? "IP" : "LID", ipbuf, sepid->num_messages,
		    sepid->err_check_bad_sent, t_first, 
		    (int) (t_first * 100.0 / t_runtime), t_last, 
		    (int) (t_last * 100.0 / t_runtime));

	psmi_epid_remove(PSMI_EP_CROSSTALK, sepid->epid);
	psmi_free(sepid);
    }
    psmi_epid_itor_fini(&itor);
    return;
}

/* New scbs now available.  If we have pending sends because we were out of
 * scbs, put the pendq on the timerq so it can be processed. */
void
ips_proto_rv_scbavail_callback(struct ips_scbctrl *scbc, void *context)
{
    struct ips_proto *proto = (struct ips_proto *) context;
    struct ips_pend_sreq *sreq = STAILQ_FIRST(&proto->pend_sends.pendq);
    if (sreq != NULL) 
	psmi_timer_request(proto->timerq, 
			  &proto->pend_sends.timer, PSMI_TIMER_PRIO_1);
    return;
}

psm_error_t __recvpath
ips_proto_timer_pendq_callback(struct psmi_timer *timer, uint64_t current)
{
    psm_error_t err = PSM_OK;
    struct ips_pend_sends *pend_sends = 
	(struct ips_pend_sends *) timer->context;
    struct ips_pendsendq *phead = &pend_sends->pendq;
    struct ips_proto *proto = (struct ips_proto *) pend_sends->proto;
    struct ips_pend_sreq *sreq;

    while (!STAILQ_EMPTY(phead)) {
	sreq = STAILQ_FIRST(phead);
	switch (sreq->type) {
	    case IPS_PENDSEND_EAGER_REQ:
		err = ips_proto_mq_push_eager_req(proto, sreq->req);
		break;
	    case IPS_PENDSEND_EAGER_DATA:
		err = ips_proto_mq_push_eager_data(proto, sreq->req);
		break;

	    default:
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		    "Unknown pendq state %d\n", sreq->type);
	}

	if (err == PSM_OK) {
	    STAILQ_REMOVE_HEAD(phead, next);
	    psmi_mpool_put(sreq);
	}
	else { /* out of scbs. wait for the next scb_avail callback */
	    //printf("!!!!! breaking out of pendq progress\n");
	    break;
	}
    }

    return err;
}

static 
int __recvpath 
_process_mq(struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    char   *payload = ips_recvhdrq_event_payload(rcv_ev);
    uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev);
    uint32_t msglen = paylen;
    uint16_t mode = p_hdr->mqhdr;
    psm_mq_req_t req;
    psmi_egrid_t egrid;
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
    psm_epaddr_t epaddr = ipsaddr->epaddr;
    psm_mq_t mq = rcv_ev->proto->mq; 
    ptl_arg_t *args;
    ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
    struct ips_flow *flow = &ipsaddr->flows[flowid];
    int ret = IPS_RECVHDRQ_CONTINUE;
    
    if (!ips_proto_is_expected_or_nak((struct ips_recvhdrq_event*) rcv_ev))
	goto skip_ack_req;
    
    _IPATH_VDBG("Rcvd ctrl packet %s length = %i, mode=%d, arg0=%llx arg1=%llx\n", 
	psmi_epaddr_get_name(epaddr->epid), 
	paylen, p_hdr->mqhdr, 
	(long long) p_hdr->data[0].u64, (long long) p_hdr->data[1].u64);
    
    if (mode <= MQ_MSG_RTS_WAIT) {
	ret = ips_proto_check_msg_order(epaddr, flow, p_hdr);
	if (ret == 0) return IPS_RECVHDRQ_OOO;

	if (mode <= MQ_MSG_LONG) {
	    egrid.egr_data = 0; 
	    if (mode == MQ_MSG_SHORT) {
		/* May have padded writes, account for it */
		paylen -= p_hdr->hdr_dlen;
		msglen = paylen;
	    }
	    else if (mode == MQ_MSG_TINY) {
		payload = (void *) &p_hdr->data[1];
		msglen = paylen = p_hdr->hdr_dlen;
	    }
	    else if (mode == MQ_MSG_LONG) {
		msglen = p_hdr->data[1].u32w1;
		if (ipsaddr->flags & SESS_FLAG_HAS_FLOWID) {
		    egrid.egr_data = p_hdr->data[1].u32w0;
		    _IPATH_VDBG("egrid-msglong is 0x%x\n", egrid.egr_data);
		}
	    }

	    if (ret == 1)
		psmi_mq_handle_envelope(
		    mq, mode, epaddr, p_hdr->data[0].u64, /* tag */
		    egrid, msglen, (void *) payload, paylen);
	    else
		psmi_mq_handle_envelope_outoforder(
		    mq, mode, epaddr, flow->msg_ooo_seqnum,
		    p_hdr->data[0].u64, /* tag */
		    egrid, msglen, (void *) payload, paylen);
	} else {
	    args = (ptl_arg_t *) p_hdr->data;
	    if (ret == 1)
		ips_proto_mq_handle_rts_envelope(mq, mode, epaddr, 
		    args[0].u64, args[1].u32w0, args[1].u32w1);
	    else
		ips_proto_mq_handle_rts_envelope_outoforder(mq, mode,
		    epaddr, flow->msg_ooo_seqnum,
		    args[0].u64, args[1].u32w0, args[1].u32w1);
	}

	if (ret == 1) {
	    if (epaddr->mctxt_master->outoforder_c) {
		psmi_mq_handle_outoforder_queue(epaddr->mctxt_master);
	    }
	    ret = IPS_RECVHDRQ_CONTINUE;
	} else {
	    ret = IPS_RECVHDRQ_BREAK;
	}
    } else if (mode == MQ_MSG_DATA || mode == MQ_MSG_DATA_BLK) {
	psm_mq_req_t req;

	req = STAILQ_FIRST(&epaddr->mctxt_master->egrlong);
	while (req) {
	    if (req->egrid.egr_data == p_hdr->data[1].u32w0) break;
	    req = STAILQ_NEXT(req, nextq);
	}

/*
 * Even with single context, since the header is sent via pio-flow,
 * and data is sent via sdma-flow, data could be received first,
 * thus causes req=NULL.
 */
	if (req == NULL) {
	    flow->msg_ooo_toggle = !flow->msg_ooo_toggle;
	    if (flow->msg_ooo_toggle) {
		flow->recv_seq_num.pkt -= 1;
		return IPS_RECVHDRQ_OOO;
	    }
	} else {
	    flow->msg_ooo_toggle = 0;
	}

	psmi_mq_handle_data(req, epaddr, p_hdr->data[1].u32w0,
		p_hdr->data[1].u32w1, payload, paylen);

	/* If checksum is enabled, this matches what is done for tid-sdma */
	/* if OOO and req is NULL, header is not received and we ignore chksum */
	if (rcv_ev->proto->flags & IPS_PROTO_FLAG_CKSUM &&
			mode == MQ_MSG_DATA_BLK &&
			req && req->state == MQ_STATE_COMPLETE) {
		uint32_t cksum = ips_crc_calculate(
			req->recv_msglen - p_hdr->data[0].u32w1,
			(uint8_t *)req->buf + p_hdr->data[0].u32w1, 
			0xffffffff);
		if (p_hdr->data[0].u32w0 != cksum) {
			psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			"ErrPkt: Checksum mismatch. Expected: 0x%08x, Received: 0x%08x Source LID: %i. Aborting! \n", p_hdr->data[0].u32w0, cksum, __be16_to_cpu(flow->path->epr_dlid));
			ips_proto_dump_data(req->buf, req->recv_msglen);
		}
	}

    } else if (mode == MQ_MSG_DATA_REQ || mode == MQ_MSG_DATA_REQ_BLK) {
	req = psmi_mpool_find_obj_by_index(mq->rreq_pool,
				     p_hdr->data[1].u32w0);
	if (!req) goto skip_ack_req;
	psmi_mq_handle_data(req, epaddr, p_hdr->data[1].u32w0,
		p_hdr->data[1].u32w1, (void *) payload, paylen);

	/* If checksum is enabled, this matches what is done for tid-sdma */
	if (rcv_ev->proto->flags & IPS_PROTO_FLAG_CKSUM &&
			mode == MQ_MSG_DATA_REQ_BLK &&
			req->state == MQ_STATE_COMPLETE) {
		uint32_t cksum = ips_crc_calculate(
			req->recv_msglen, req->buf, 0xffffffff);
		if (p_hdr->data[0].u32w0 != cksum) {
			psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			"ErrPkt: Checksum mismatch. Expected: 0x%08x, Received: 0x%08x Source LID: %i. Aborting! \n", p_hdr->data[0].u32w0, cksum, __be16_to_cpu(flow->path->epr_dlid));
			ips_proto_dump_data(req->buf, req->recv_msglen);
		}
	}

    } else if (mode == MQ_MSG_CTS_EGR) {
	args = p_hdr->data;
	ips_proto_mq_handle_cts(rcv_ev->proto, args);
    } else {
	psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		"Unknown frame mode %x", mode);
    }

    if ((p_hdr->flags & IPS_SEND_FLAG_ACK_REQ)  ||
	(flow->flags & IPS_FLOW_FLAG_GEN_BECN))
      ips_proto_send_ack((struct ips_recvhdrq *) rcv_ev->recvq, flow);
    
skip_ack_req:
    ips_proto_process_ack(rcv_ev);
    
    return ret; // skip
}

PSMI_INLINE(
int between(int first_seq, int last_seq, int seq))
{
  if (last_seq >= first_seq) {
    if (seq < first_seq || seq > last_seq) {
	return 0;
    }
  } else {
    if (seq > last_seq && seq < first_seq) {
	return 0;
    }
  }
  return 1;
}

PSMI_INLINE(
int pio_dma_ack_valid(struct ips_flow *flow, psmi_seqnum_t ack_seq_num, 
		      uint32_t ack_window))
{
  uint32_t first_pkt, last_pkt;
  struct ips_scb_unackedq *unackedq = &flow->scb_unacked;
  
  if (STAILQ_EMPTY(unackedq))
    return 0;
  
  first_pkt = flow->xmit_ack_num.pkt + 1;
  last_pkt = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num.pkt;
  return between(first_pkt, last_pkt, ack_seq_num.pkt);
}

PSMI_INLINE(
struct ips_flow* get_tidflow(ips_epaddr_t *ipsaddr, 
			     struct ips_message_header *p_hdr,
			     psmi_seqnum_t ack_seq_num, 
			     uint32_t ack_window))
{
  struct ips_flow *flow;
  struct ips_protoexp *protoexp = ipsaddr->proto->protoexp;
  struct ips_tid_send_desc *tidsendc;
  ptl_arg_t desc_id = p_hdr->data[0];
  ptl_arg_t desc_tidsendc;
  uint32_t first_seq, last_seq;
  struct ips_scb_unackedq *unackedq;
  
  tidsendc = (struct ips_tid_send_desc*)
    psmi_mpool_find_obj_by_index(protoexp->tid_desc_send_pool,
				 desc_id._desc_idx);
  if (tidsendc == NULL) {
    _IPATH_ERROR("OPCODE_ACK: Index %d is out of range in tidflow ack\n", desc_id._desc_idx);
    return NULL;
  }

  /* Ensure generation matches */
  psmi_mpool_get_obj_index_gen_count(tidsendc,
				     &desc_tidsendc._desc_idx,
				     &desc_tidsendc._desc_genc);
  if (desc_tidsendc.u64 != desc_id.u64)
    return NULL;
  
  /* Ensure ack is within window */
  flow = &tidsendc->tidflow;
  unackedq = &flow->scb_unacked;
  
  /* No unacked scbs */
  if (STAILQ_EMPTY(unackedq))
    return NULL;
  
  first_seq = flow->xmit_ack_num.seq + 1;
  last_seq = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num.seq;
  if (between(first_seq, last_seq, ack_seq_num.seq) == 0) {
    return NULL;
  }
   
  /* Generation for ack should match */
  if (STAILQ_FIRST(unackedq)->seq_num.gen != ack_seq_num.gen)
    return NULL;
    
  return flow;
}

/* NAK post process for tid flow */
void ips_tidflow_nak_post_process(struct ips_flow *flow, 
				  struct ips_message_header *p_hdr)
{
  
  ips_scb_t *scb;
  struct ips_scb_unackedq *unackedq = &flow->scb_unacked;
#ifdef PSM_DEBUG
  psmi_seqnum_t new_flowgenseq;
	
  new_flowgenseq.val = p_hdr->data[1].u32w0;
  /* Update any pending scb's to the new generation count.
   * Note: flow->xmit_seq_num was updated to the new generation when the
   * NAK was received. 
   */
  psmi_assert(STAILQ_FIRST(unackedq)->seq_num.flow==new_flowgenseq.flow);
  psmi_assert(STAILQ_FIRST(unackedq)->seq_num.gen != new_flowgenseq.gen);
  psmi_assert(STAILQ_FIRST(unackedq)->
	seq_num.seq-STAILQ_FIRST(unackedq)->nfrag+1 == new_flowgenseq.seq);
#endif

  /* Update unacked scb's to use the new flowgenseq */
  scb = STAILQ_FIRST(unackedq);
  while (scb) {
    scb->ips_lrh.bth[2] = __cpu_to_be32(flow->xmit_seq_num.psn);
    flow->xmit_seq_num.seq += scb->nfrag;
    scb->seq_num = flow->xmit_seq_num;
    scb->seq_num.seq--;
    scb = SLIST_NEXT(scb, next);
  }
  
}

// process an incoming ack message.  Separate function to allow
// for better optimization by compiler
void __recvpath
ips_proto_process_ack(struct ips_recvhdrq_event *rcv_ev)
{
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr; 
    struct ips_message_header *p_hdr = rcv_ev->p_hdr; 
    psmi_seqnum_t ack_seq_num, last_seq_num;
    ips_scb_t *scb;
    struct ips_proto *proto = ipsaddr->proto;    
    struct ips_flow *flow = NULL;
    struct ips_scb_unackedq *unackedq;
    struct ips_scb_pendlist *scb_pend;
    psm_protocol_type_t protocol;
    ptl_epaddr_flow_t flowid;
    
    ips_ptladdr_lock(ipsaddr);
    
    protocol = IPS_FLOWID_GET_PROTO(p_hdr->flowid);
    flowid = IPS_FLOWID_GET_INDEX(p_hdr->flowid);
    ack_seq_num.psn = p_hdr->ack_seq_num;

    switch(protocol){
    case PSM_PROTOCOL_GO_BACK_N:
      flow = &ipsaddr->flows[flowid];
      ack_seq_num.pkt -= 1;
      if (!pio_dma_ack_valid(flow, ack_seq_num, proto->scb_max_inflight))
	goto ret;
      flow->xmit_ack_num = ack_seq_num;
      break;
    case PSM_PROTOCOL_TIDFLOW:
      ack_seq_num.seq -= 1;
      flow = get_tidflow(ipsaddr, p_hdr, ack_seq_num, proto->scb_max_inflight);
      if (!flow) /* Invalid ack for flow */
        goto ret;
      flow->xmit_ack_num = ack_seq_num;
      break;
    default:
      _IPATH_ERROR("OPCODE_ACK: Unknown flow type %d in ACK\n", flowid);
      goto ret;
    }
    
    unackedq = &flow->scb_unacked;
    scb_pend = &flow->scb_pend;
    if (STAILQ_EMPTY(unackedq)) goto ret;  // only for Klockwork scan.
    last_seq_num = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num;
    
    INC_TIME_SPEND(TIME_SPEND_USER2);

    /* For tidflow, we want to match all flow/gen/seq,
       for gobackn, we only match pkt#, msg# is not known.
       msg# is the message envelope number in the stream,
       you don't know if the next packet has the old msg#
       or starts a new msg#.
    */
    /*  first release all xmit buffer that has been receveid   */
    while ((protocol==PSM_PROTOCOL_GO_BACK_N) ?
		between(STAILQ_FIRST(unackedq)->seq_num.pkt,
			last_seq_num.pkt, ack_seq_num.pkt) :
		between(STAILQ_FIRST(unackedq)->seq_num.psn,
			last_seq_num.psn, ack_seq_num.psn)
    ) {

        /* take it out of the xmit queue and ..  */
	scb = STAILQ_FIRST(unackedq);
	STAILQ_REMOVE_HEAD(unackedq, nextq);
	flow->scb_num_unacked--;
	flow->credits++;
	
	if (scb == SLIST_FIRST(scb_pend)) {
	    flow->scb_num_pending--;
	    SLIST_REMOVE_HEAD(scb_pend, next);
	}

	if (scb->flags & IPS_SEND_FLAG_WAIT_SDMA) 
	    ips_proto_dma_wait_until(proto, scb->dma_ctr);

        if (scb->callback)
            (*scb->callback) (scb->cb_param, scb->payload_size-scb->extra_bytes);

	if (!(scb->flags & IPS_SEND_FLAG_PERSISTENT))
	    ips_scbctrl_free(scb);

        /* set all index pointer to NULL if all frames have been
         * acked */
	if (STAILQ_EMPTY(unackedq)) {
            psmi_timer_cancel(proto->timerq, &flow->timer_ack);
	    psmi_timer_cancel(proto->timerq, &flow->timer_send);
	    SLIST_FIRST(scb_pend) = NULL;
	    psmi_assert(flow->scb_num_pending == 0);
	    /* Reset congestion window - all packets ACK'd */
	    flow->credits = flow->cwin = proto->flow_credits;
	    flow->ack_interval = max((flow->credits >> 2) - 1, 1);
	    flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
	    goto ret;
        }
    }
    
    /* CCA: If flow is congested adjust rate */
    if_pf (rcv_ev->is_congested & IPS_RECV_EVENT_BECN) {
      if ((flow->path->epr_ccti +
      proto->cace[flow->path->epr_sl].ccti_increase) <=
      proto->ccti_limit) {
	ips_cca_adjust_rate(flow->path,
		proto->cace[flow->path->epr_sl].ccti_increase);
	/* Clear congestion event */
	rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
      }
    }
    else {
      /* Increase congestion window if flow is not congested */
      if_pf (flow->cwin < proto->flow_credits) {
	flow->credits += 
	  min(flow->cwin << 1, proto->flow_credits) - flow->cwin;
	flow->cwin = min(flow->cwin << 1, proto->flow_credits);
	flow->ack_interval = max((flow->credits >> 2) - 1, 1);
      }
    }
    
    /* Reclaimed some credits - attempt to flush flow */
    flow->fn.xfer.flush(flow, NULL);
    
    /*
     * If the next packet has not even been put on the wire, cancel the
     * retransmission timer since we're still presumably waiting on free 
     * pio bufs
     */
    if (STAILQ_FIRST(unackedq)->abs_timeout == TIMEOUT_INFINITE)
       psmi_timer_cancel(proto->timerq, &flow->timer_ack);

ret:
    ips_ptladdr_unlock(ipsaddr);
    return;
}

// process an incoming nack message.  Separate function to allow
// for better optimization by compiler
static void 
_process_nak(struct ips_recvhdrq_event *rcv_ev)
{
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr; 
    psmi_seqnum_t ack_seq_num, last_seq_num;
    ips_scb_t *scb;
    struct ips_proto *proto = ipsaddr->proto;
    struct ips_flow *flow = NULL;
    struct ips_scb_unackedq *unackedq;
    struct ips_scb_pendlist *scb_pend;
    psm_protocol_type_t protocol;
    ptl_epaddr_flow_t flowid;
    int num_resent = 0;
    
    ips_ptladdr_lock(ipsaddr);
    
    protocol = IPS_FLOWID_GET_PROTO(p_hdr->flowid);
    flowid = IPS_FLOWID_GET_INDEX(p_hdr->flowid);

    INC_TIME_SPEND(TIME_SPEND_USER3);

    ack_seq_num.psn = p_hdr->ack_seq_num;
    
    switch(protocol){
    case PSM_PROTOCOL_GO_BACK_N:
      flow = &ipsaddr->flows[flowid];
      if (!pio_dma_ack_valid(flow, ack_seq_num, proto->scb_max_inflight)) 
	goto ret;
      ack_seq_num.pkt--;
      flow->xmit_ack_num = ack_seq_num;
      break;
    case PSM_PROTOCOL_TIDFLOW:
      flow = get_tidflow(ipsaddr, p_hdr, ack_seq_num, proto->scb_max_inflight);
      if (!flow)
	goto ret;  /* Invalid ack for flow */
      ack_seq_num.seq--;
      /* Update xmit seq num to the new flowgenseq */
      flow->xmit_seq_num = (psmi_seqnum_t)p_hdr->data[1].u32w0;
      flow->xmit_ack_num = flow->xmit_seq_num;
      flow->xmit_ack_num.seq--;
      break;
    default:
      _IPATH_ERROR("OPCODE_NAK: Unknown flow type %d in ACK\n", flowid);
      goto ret;
    }
    
    unackedq = &flow->scb_unacked;
    scb_pend = &flow->scb_pend;
    if (STAILQ_EMPTY(unackedq)) goto ret;  // only for Klockwork scan.
    last_seq_num = STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num;
        
    ipsaddr->stats.nak_recv++;

    _IPATH_VDBG("got a nack %d on flow %d, "
		"first is %d, last is %d\n", ack_seq_num.psn,
		flowid, STAILQ_EMPTY(unackedq)?-1:STAILQ_FIRST(unackedq)->seq_num.psn,
		STAILQ_EMPTY(unackedq)?-1:STAILQ_LAST(unackedq, ips_scb, nextq)->seq_num.psn);

    /* For tidflow, we want to match all flow/gen/seq,
       for gobackn, we only match pkt#, msg# is not known.
       msg# is the message envelope number in the stream,
       you don't know if the next packet has the old msg#
       or starts a new msg#.
    */
    /*  first release all xmit buffer that has been receveid   */
    while ((protocol==PSM_PROTOCOL_GO_BACK_N) ?
		between(STAILQ_FIRST(unackedq)->seq_num.pkt,
			last_seq_num.pkt, ack_seq_num.pkt) :
		between(STAILQ_FIRST(unackedq)->seq_num.psn,
			last_seq_num.psn, ack_seq_num.psn)
    ) {
        /* take it out of the xmit queue and ..  */
	scb = STAILQ_FIRST(unackedq);
	STAILQ_REMOVE_HEAD(unackedq, nextq);
	flow->scb_num_unacked--;
	
	if (scb->flags & IPS_SEND_FLAG_WAIT_SDMA) 
	    ips_proto_dma_wait_until(proto, scb->dma_ctr);

        if (scb->callback)
            (*scb->callback) (scb->cb_param, scb->payload_size-scb->extra_bytes);

	if (!(scb->flags & IPS_SEND_FLAG_PERSISTENT))
	    ips_scbctrl_free(scb);

        /* set all index pointer to NULL if all frames has been acked */
	if (STAILQ_EMPTY(unackedq)) {
            psmi_timer_cancel(proto->timerq, &flow->timer_ack);
	    psmi_timer_cancel(proto->timerq, &flow->timer_send);
	    SLIST_FIRST(scb_pend) = NULL;
	    psmi_assert(flow->scb_num_pending == 0);
	    /* Reset congestion window if all packets acknowledged */
	    flow->credits = flow->cwin = proto->flow_credits;
	    flow->ack_interval = max((flow->credits >> 2) - 1, 1);
	    flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
	    goto ret;
        }
    }

    psmi_assert(!STAILQ_EMPTY(unackedq)); /* sanity for above loop */

    if (flow->fn.protocol.nak_post_process)
      flow->fn.protocol.nak_post_process(flow, p_hdr);
    
    /* Always cancel ACK timer as we are going to restart the flow */
    psmi_timer_cancel(proto->timerq, &flow->timer_ack);
    
    /* What's now pending is all that was unacked */
    SLIST_FIRST(scb_pend) = STAILQ_FIRST(unackedq);
    flow->scb_num_pending = flow->scb_num_unacked;
    
    /* If NAK with congestion bit set - delay re-transmitting and THEN adjust
     * CCA rate.
     */
    if_pf (rcv_ev->is_congested & IPS_RECV_EVENT_BECN) {
      uint64_t offset;
      
      /* Clear congestion event and mark flow as congested */
      rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
      flow->flags |= IPS_FLOW_FLAG_CONGESTED;
      
      /* For congested flow use slow start i.e. reduce congestion window.
       * For TIDFLOW we cannot reduce congestion window as peer expects
       * header packets at regular intervals (protoexp->hdr_pkt_interval).
       */
      if (flow->protocol != PSM_PROTOCOL_TIDFLOW)
	flow->credits = flow->cwin = 1;
      else 
	flow->credits = flow->cwin;

      flow->ack_interval = max((flow->credits >> 2) - 1, 1);
      
      /* During congestion cancel send timer and delay retransmission by 
       * random interval 
       */
      psmi_timer_cancel(proto->timerq, &flow->timer_send);
      if (SLIST_FIRST(scb_pend)->ack_timeout != TIMEOUT_INFINITE)
	offset = (SLIST_FIRST(scb_pend)->ack_timeout >> 1);	    
      else
	offset = 0;
      psmi_timer_request(proto->timerq, &flow->timer_send,
			 (get_cycles() +
			  (uint64_t)(offset * (rand()/RAND_MAX + 1.0))));
    }
    else {
      /* Reclaim all credits upto congestion window only */
      flow->credits = flow->cwin;
      flow->ack_interval = max((flow->credits >> 2) - 1, 1);
      
      /* Flush pending scb's */
      flow->fn.xfer.flush(flow, &num_resent);
      ipsaddr->stats.send_rexmit += num_resent;
    }
    
ret:
    ips_ptladdr_unlock(ipsaddr);
    return;
}

static void 
_process_err_chk(struct ips_recvhdrq *recvq, ips_epaddr_t *ipsaddr, 
		 struct ips_message_header *p_hdr)
{
    psmi_seqnum_t seq_num;
    int16_t seq_off;
    ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
    struct ips_flow *flow = &ipsaddr->flows[flowid];
    
    INC_TIME_SPEND(TIME_SPEND_USER4);

    ipsaddr->stats.err_chk_recv++;

    seq_num.val = __be32_to_cpu(p_hdr->bth[2]);
    seq_off = (int16_t)(ipsaddr->flows[flowid].recv_seq_num.pkt - seq_num.pkt);

    if_pf (seq_off <= 0) {
      _IPATH_VDBG("naking for seq=%d, off=%d on flowid  %d\n",
		  seq_num.pkt, seq_off, flowid);
      
      if (seq_off < -flow->ack_interval) 
	flow->flags |= IPS_FLOW_FLAG_GEN_BECN;

      ips_proto_send_nak(recvq, flow);
      flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
    }
    else {
      ips_proto_send_ctrl_message(flow, OPCODE_ACK, 
				  &ipsaddr->ctrl_msg_queued, NULL);
    }
}

static void
_process_err_chk_gen(ips_epaddr_t *ipsaddr, struct ips_message_header *p_hdr)
{
  struct ips_protoexp *protoexp = ipsaddr->proto->protoexp;
  struct ips_tid_recv_desc *tidrecvc;
  psmi_seqnum_t err_seqnum;
  ptl_arg_t desc_id = p_hdr->data[0];
  ptl_arg_t send_desc_id = p_hdr->data[1];
  ptl_arg_t desc_tidrecvc;
  ptl_arg_t args[3] = {};
  int16_t seq_off;
  uint8_t ack_type;
  
  INC_TIME_SPEND(TIME_SPEND_USER4);

  ipsaddr->stats.err_chk_recv++;
  
  /* Get the flowgenseq for err chk gen */
  err_seqnum.val = __be32_to_cpu(p_hdr->bth[2]);

  ips_ptladdr_lock(ipsaddr);
  
  /* Get receive descriptor */
  tidrecvc = (struct ips_tid_recv_desc *)
    psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
                                 desc_id._desc_idx);
  
  if (tidrecvc == NULL) {
    _IPATH_DBG("ERR_CHK_GEN: invalid rendezvous handle\n");
    ips_ptladdr_unlock(ipsaddr);
    return;
  }
  psmi_mpool_get_obj_index_gen_count(tidrecvc,
                                     &desc_tidrecvc._desc_idx,
                                     &desc_tidrecvc._desc_genc);
  
  if (desc_id.u64 != desc_tidrecvc.u64) {
    /* Receive descriptor mismatch in time and space.
     * Stale err chk gen, drop packet
     */
    _IPATH_DBG("ERR_CHK_GEN: rendezvous handle generation mismatch. Pkt: 0x%08x, Current: 0x%08x\n", desc_id._desc_genc, desc_tidrecvc._desc_genc);
    ips_ptladdr_unlock(ipsaddr);
    return;
  }
  
  psmi_assert(tidrecvc->tidflow_idx == err_seqnum.flow);
  
  /* Note: Do not read the tidflow table to determine the sequence to restart
   * from. Always respond with the last known "good" packet that we received
   * which is updated in protoexp_data().
   */
  
  /* Either lost packets or lost ack */
  seq_off = (int16_t) (tidrecvc->tidflow_genseq.seq - err_seqnum.seq);

  if (seq_off <= 0) {
    ack_type = OPCODE_NAK;
    
    if (err_seqnum.gen == tidrecvc->tidflow_active_gen) {
      /* Swap generations */
      psm_error_t err;
      
      /* Allocate new generation for the flow. */
      err = ips_protoexp_flow_newgen(tidrecvc);
      if (err != PSM_OK) 
	return; /* Out of generation. Drop packet and we will recover later */
    }
  }
  else {
    ack_type = OPCODE_ACK;
    
    if (err_seqnum.gen != tidrecvc->tidflow_genseq.gen)
      ack_type = OPCODE_NAK; /* NAK without allocating a new generation */
  }

  args[0] = send_desc_id;
  args[1] = tidrecvc->tid_list.tsess_descid;
  args[2].u16w0 = err_seqnum.gen; /* If NAK, generation number */

  ips_ptladdr_unlock(ipsaddr);
  
  /* May want to generate a BECN if a lot of swapped generations */
  if_pf ((tidrecvc->tidflow_nswap_gen > 4) &&
	 (protoexp->proto->flags & IPS_PROTO_FLAG_CCA)) {
    _IPATH_CCADBG("ERR_CHK_GEN: Generating BECN. Number of swapped generations: %d.\n", tidrecvc->tidflow_nswap_gen);
    /* Mark flow to generate BECN in control packet */
    tidrecvc->ipsaddr->tidgr_flow.flags |= IPS_FLOW_FLAG_GEN_BECN;
    
    /* Update stats for congestion encountered */
    ipsaddr->stats.congestion_pkts++;
  }
  
  ips_proto_send_ctrl_message(&tidrecvc->ipsaddr->tidgr_flow, 
			      ack_type, &tidrecvc->ctrl_msg_queued, args);

  /* Update stats for expected window */
  tidrecvc->stats.nErrChkReceived++;
  if (ack_type == OPCODE_NAK)
    tidrecvc->stats.nReXmit++; /* Update stats for retransmit (Sent a NAK) */
}

static void 
parse_ip_or_lid(char *buf, size_t len, uint32_t ip, psm_epid_t epid)
{
    char ipbuf[INET_ADDRSTRLEN], *p;
    in_addr_t in_loop = inet_addr("127.0.0.1");
    in_addr_t in_any  = inet_addr("0.0.0.0");

    p = (char *) inet_ntop(AF_INET, (const void *) &ip, ipbuf, sizeof ipbuf);
    if (ip != in_loop && ip != in_any && p) 
	snprintf(buf, len-1, "IP %s", p);
    else
	snprintf(buf, len-1, "LID 0x%x", (int) psm_epid_nid(epid));
    buf[len-1] = '\0';
}

#define IPS_MAX_BOGUS_ERR_CHK_BAD   15

static void 
_process_err_chk_bad(ips_epaddr_t *ipsaddr, struct ips_message_header *p_hdr)
{
    uint32_t ipv4_addr = p_hdr->data[0].u32w0;
    uint32_t pid = __be32_to_cpu(p_hdr->data[0].u32w1);
    union psmi_envvar_val env_stray;
    char buf[32];
    psm_epid_t epid = ipsaddr->epaddr->epid;

    parse_ip_or_lid(buf, sizeof buf, ipv4_addr, epid);

    /* First make sure that we actually do have a connection to this lid+context,
     * if not, we just ignore the err_chk_bad message since it might be some
     * oddly timed packet */
    if (!ips_proto_isconnected(ipsaddr)) {
	int lid =  (int) psm_epid_nid(epid);
	int context = (int) psm_epid_context(epid);
	if (++ipsaddr->proto->num_bogus_warnings <= IPS_MAX_BOGUS_ERR_CHK_BAD)
	    psmi_syslog(ipsaddr->proto->ep, 1, LOG_INFO, 
		"PSM pid %d on host %s complains that I am a stray process but "
		"I'm not even connected to LID %d context %d (ignoring %s\n",
		pid, buf, lid, context, 
		ipsaddr->proto->num_bogus_warnings == IPS_MAX_BOGUS_ERR_CHK_BAD ? 
		"all future stray warning checks from unknown endpoints)." : 
		").");
	return;
    }

    /* At this point the bad error check is a real one, from a host we thought
     * we were connected to.  We only go through this path once.  If
     * PSM_STRAY_ENABLED=0, we'll print this warning once, if it's 1 we'll die.
    */
    if (ipsaddr->proto->done_once++)
	return;

    psmi_getenv("PSM_STRAY_ENABLED", "Enable stray process detection",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_YESNO,
		(union psmi_envvar_val) 1, /* yes by default */
		&env_stray);

    if (env_stray.e_uint)
	psmi_handle_error(PSMI_EP_NORETURN, PSM_EPID_NETWORK_ERROR, "PSM pid "
	    "%d on host %s has detected that I am a stray process, exiting.", 
	    pid, buf);
    else
	psmi_syslog(ipsaddr->proto->ep, 1, LOG_INFO, "PSM pid "
	    "%d on host %s has detected that I am a stray process, " 
	    "PSM_STRAY_ENABLED is off and future messages are ignored.");
    return;
}

static void ips_bad_opcode(uint8_t op_code, struct ips_message_header *proto)
{
    _IPATH_DBG("Discarding message with bad opcode 0x%x\n",
        op_code);

    if(infinipath_debug&__IPATH_DBG) {
        ips_proto_show_header(proto, "received bad opcode");
        ips_proto_dump_frame(proto, sizeof(struct ips_message_header),
            "Opcode error protocol header dump");
    }
}

static void 
_process_unknown_opcode(struct ips_proto *proto,
			struct ips_message_header *protocol_header)
{
    proto->stats.unknown_packets++;

    switch (protocol_header->sub_opcode) {
	/* A bunch of pre-PSM packets that we don't handle any more */
	case OPCODE_SEQ_DATA: 
        case OPCODE_SEQ_CTRL:
        case OPCODE_STARTUP:
        case OPCODE_STARTUP_EXT:
        case OPCODE_STARTUP_ACK:
        case OPCODE_STARTUP_ACK_EXT:
        case OPCODE_STARTUP_NAK:
        case OPCODE_STARTUP_NAK_EXT:
        case OPCODE_CLOSE:
        case OPCODE_ABORT:
        case OPCODE_CLOSE_ACK:
	    break;
	default:
	    ips_bad_opcode(protocol_header->sub_opcode, protocol_header);
	    break;
    }
}

PSMI_NEVER_INLINE(
int
_process_connect(const struct ips_recvhdrq_event *rcv_ev))
{
  const uint16_t lmc_mask = ~((1 << rcv_ev->proto->epinfo.ep_lmc) - 1);
  
  return ips_proto_process_connect(rcv_ev->proto, 
				   ips_epid_from_phdr(lmc_mask, rcv_ev->p_hdr), 
				   rcv_ev->p_hdr->sub_opcode, 
				   rcv_ev->p_hdr,
				   ips_recvhdrq_event_payload(rcv_ev),
				   ips_recvhdrq_event_paylen(rcv_ev));
}

// Return 1 if packet is ok.
// Return 0 if packet should be skipped
int
ips_proto_process_unknown(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    uint8_t ptype = rcv_ev->ptype;
    const uint64_t current_count = get_cycles();
    struct ips_stray_epid *sepid;
    struct ips_proto *proto = rcv_ev->proto;
    psm_ep_t ep_err;
    psm_epid_t epid;
    char *pkt_type;
    int opcode = (int) p_hdr->sub_opcode;
    double t_elapsed;
    ptl_epaddr_flow_t flowid = IPS_FLOWID_GET_INDEX(p_hdr->flowid);
    const uint16_t lmc_mask = ~((1 << rcv_ev->proto->epinfo.ep_lmc) - 1);

    /* 
     * If the protocol is disabled or not yet enabled, no processing happens
     * We set it t_init to 0 when disabling the protocol
     */
    if (proto->t_init == 0)
	return IPS_RECVHDRQ_CONTINUE;

    /*
     * If lid is 0, something bad happened in queue processing
     */
    epid = ips_epid_from_phdr(lmc_mask, p_hdr);
    if (psm_epid_nid(epid) == 0ULL) {
	proto->stats.lid_zero_errs++;
	_IPATH_DBG("Skipping stray packet processing with LID=0\n");
	return IPS_RECVHDRQ_CONTINUE;
    }

    /* Connect messages don't have to be from a known epaddr */
    switch (opcode) {
	case OPCODE_CONNECT_REQUEST:
	case OPCODE_CONNECT_REPLY:
	case OPCODE_DISCONNECT_REQUEST:
	case OPCODE_DISCONNECT_REPLY:
	    _process_connect(rcv_ev);
	    return IPS_RECVHDRQ_CONTINUE;
	case OPCODE_ERR_CHK_BAD: /* ignore, old opcode */
	    return IPS_RECVHDRQ_CONTINUE;
	default:
	    break;
    }
    
    /* Packet from "unknown" peer. Log the packet and payload if at appropriate
     * verbose level.
     */
    {
      char *payload = ips_recvhdrq_event_payload(rcv_ev);
      uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
	((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);
      
      ips_proto_dump_err_stats(proto);
      
      if(infinipath_debug & __IPATH_PKTDBG) {
	ips_proto_dump_frame(rcv_ev->p_hdr, IPATH_MESSAGE_HDR_SIZE, "header");
	if (paylen)
	  ips_proto_dump_frame(payload, paylen, "data");
      }
    }
    
    /* Other messages are definitely crosstalk. */
    /* out-of-context expected messages are always fatal */
    if (ptype == RCVHQ_RCV_TYPE_EXPECTED) {
	ep_err = PSMI_EP_NORETURN;
	pkt_type = "expected";
    }
    else if (ptype == RCVHQ_RCV_TYPE_EAGER) {
	ep_err = PSMI_EP_LOGEVENT;
	pkt_type = "eager";
    }
    else {
	ep_err = PSMI_EP_NORETURN;
	pkt_type = "unknown";
    }

    proto->stats.stray_packets++;

    /* If we have debug mode, print the complete packet every time */
    if (infinipath_debug & __IPATH_PKTDBG)
	ips_proto_show_header(p_hdr, "invalid commidx");
    t_elapsed = (double)
	cycles_to_nanosecs(get_cycles()-proto->t_init) / 1.0e9;

    sepid = (struct ips_stray_epid *) 
	psmi_epid_lookup(PSMI_EP_CROSSTALK, epid);
    if (sepid == NULL) {  /* Never seen crosstalk from this node, log it */
	sepid = (struct ips_stray_epid *) 
		psmi_calloc(proto->ep, UNDEFINED, 1, sizeof(struct ips_stray_epid));
	if (sepid == NULL) return 0; /* skip packet if no memory */ 
	psmi_epid_add(PSMI_EP_CROSSTALK, epid, (void *) sepid);
	sepid->epid = epid;
	if (proto->stray_warn_interval)
	    sepid->t_first = sepid->t_warn_next = current_count;
    }
    sepid->num_messages++;
    sepid->t_last = current_count;

    /* If we're not going to warn the user and if this not to be a fatal
     * packet, just skip it */
    if (sepid->t_warn_next > current_count && ep_err != PSMI_EP_NORETURN) 
	return 0;

    sepid->t_warn_next = current_count + proto->stray_warn_interval;

    if (p_hdr->sub_opcode == OPCODE_ERR_CHK) {
	/* With the new err_check, we can print out extra information */
	char ipbuf[INET_ADDRSTRLEN], *ip = NULL;
	sepid->ipv4_addr = p_hdr->data[0].u32w0;
	sepid->pid       = __be32_to_cpu(p_hdr->data[0].u32w1);
	ip = (char *) inet_ntop(AF_INET, &sepid->ipv4_addr, ipbuf, sizeof ipbuf);

	/* If the IP and PID make sense, go ahead and print useful info and
	 * even reply with ERR_CHK_BAD.  If not, fall through and print the
	 * generic bad error message
	 */
	if (ip != NULL && sepid->pid) {
	    /* Make up a fake ipsaddr and reply */
	    ips_epaddr_t ipsaddr_f;
	    psm_error_t err;
	    
	    /* debugging sanity, and catch bugs */
	    memset(&ipsaddr_f, 0, sizeof(ips_epaddr_t));
	    ipsaddr_f.epr.epr_context = IPS_HEADER_SRCCONTEXT_GET(p_hdr);
	    ipsaddr_f.epr.epr_subcontext = p_hdr->dst_subcontext;
	    ipsaddr_f.epr.epr_pkt_context = 
		ipsaddr_f.epr.epr_context & 0xf;
   
	    /* Get path record for peer */
	    err = proto->ibta.get_path_rec(proto, 
					   proto->epinfo.ep_base_lid, 
					   p_hdr->lrh[3], /* SLID */
					   PSMI_HCA_TYPE_QLE73XX,
					   3000, &ipsaddr_f);
	    if (err != PSM_OK)
	      goto fail;
	    
	    ipsaddr_f.epr.epr_qp = __be32_to_cpu(p_hdr->bth[1]);
	    ipsaddr_f.epr.epr_qp &= 0xffffff; /* QP is 24 bits */
	    ipsaddr_f.ptl = (ptl_t *) -1;
	    ipsaddr_f.proto = proto;
	    /* Pretend the ctrlmsg is already queued, so it doesn't get queued
	     * in this fake (stack-allocated) ptladdr */
	    ipsaddr_f.ctrl_msg_queued = ~0;
	    flowid = EP_FLOW_GO_BACK_N_PIO;
	    ips_flow_init(&ipsaddr_f.flows[flowid], NULL,
			  &ipsaddr_f, PSM_TRANSFER_PIO,
			  PSM_PROTOCOL_GO_BACK_N, IPS_PATH_LOW_PRIORITY, flowid);

	    if (!ips_proto_send_ctrl_message(&ipsaddr_f.flows[flowid],
					     OPCODE_ERR_CHK_BAD,
					     &ipsaddr_f.ctrl_msg_queued,NULL)){
		sepid->err_check_bad_sent++;
		_IPATH_VDBG("did reply with ERR_CHK_BAD\n");
	    }
	    else
		_IPATH_VDBG("did *NOT* reply with ERR_CHK_BAD\n");
	    
	fail:
	    psmi_handle_error(ep_err, PSM_EPID_NETWORK_ERROR, 
		"Received %d out-of-context %s message(s) from stray process "
		"PID=%d running on host %s (LID 0x%x, ptype=0x%x, subop=0x%x, "
		"elapsed=%.3fs) %s", 
		sepid->num_messages, pkt_type, sepid->pid, ip,
		(int) psm_epid_nid(epid), ptype, opcode, t_elapsed,
		(ep_err == PSMI_EP_NORETURN) ? "Aborting." : "");
	    return 0;
	}
    }

    /* At this point we either have a OPCODE_ERR_CHECK where we couldn't
     * extract a valid ip and pid OR some other opcode */
    psmi_handle_error(ep_err, PSM_EPID_NETWORK_ERROR, 
		"Received out-of-context %s message(s) from a stray process "
		"running on LID 0x%x ptype=0x%x subop=0x%x elapsed=%.3fs", 
		pkt_type, (int) psm_epid_nid(epid), ptype, opcode, t_elapsed);

    return 0; /* Always skip this packet unless the above call was a noreturn
	       * call */
}

/* get the error string as a number and a string */
static void rhf_errnum_string(char *msg, size_t msglen, long err)
{
    int len;
    char *errmsg;

    len = snprintf(msg, msglen, "RHFerror %lx: ", err);
    if(len > 0 && len < msglen) {
	    errmsg = msg + len;
	    msglen -= len;
    }
    else
	    errmsg = msg;
    *errmsg = 0;
    ips_proto_get_rhf_errstring(err, errmsg, msglen);
}

/*
 * Error handling
 */
int __recvpath
ips_proto_process_packet_error(struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_proto *proto = rcv_ev->proto;
    int pkt_verbose_err = infinipath_debug & __IPATH_PKTDBG;
    int tiderr = rcv_ev->error_flags & INFINIPATH_RHF_H_TIDERR;
    int tf_seqerr = rcv_ev->error_flags & INFINIPATH_RHF_H_TFSEQERR;
    int tf_generr = rcv_ev->error_flags & INFINIPATH_RHF_H_TFGENERR;
    int data_err = rcv_ev->error_flags & 
      (INFINIPATH_RHF_H_ICRCERR | INFINIPATH_RHF_H_VCRCERR | 
       INFINIPATH_RHF_H_PARITYERR | INFINIPATH_RHF_H_LENERR | 
       INFINIPATH_RHF_H_MTUERR | INFINIPATH_RHF_H_IHDRERR | 
       INFINIPATH_RHF_H_IBERR);
    char pktmsg[128];
    
    *pktmsg = 0;
    /*
     * Tid errors on eager pkts mean we get a headerq overflow, perfectly
     * safe.  Tid errors on expected or other packets means trouble.
     */
    if (tiderr && rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER) {
        struct ips_message_header *p_hdr = rcv_ev->p_hdr;
      
      
	/* Payload dropped - Determine flow for this header and see if
	 * we need to generate a NAK. 
	 *
	 * ALL PACKET DROPS IN THIS CATEGORY CAN BE FLAGGED AS DROPPED DUE TO
	 * CONGESTION AS THE EAGER BUFFER IS FULL.
	 *
	 * Possible eager packet type:
	 * 
	 * Ctrl Message - ignore
	 * MQ message - Can get flow and see if we need to NAK.
	 * AM message - Can get flow and see if we need to NAK.
	 */

	proto->stats.hdr_overflow++;
	if (data_err)
	  return 0;
	
	switch(p_hdr->sub_opcode) {
	case OPCODE_SEQ_MQ_HDR:
	case OPCODE_SEQ_MQ_CTRL:
	case OPCODE_AM_REQUEST:
	case OPCODE_AM_REQUEST_NOREPLY:
	case OPCODE_AM_REPLY:
	  {
	    ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
	    struct ips_epstate_entry *epstaddr;
	    struct ips_flow *flow;
	    psmi_seqnum_t sequence_num;
	    int16_t diff;
	    
	    /* Obtain ipsaddr for packet */
	    epstaddr = ips_epstate_lookup(rcv_ev->recvq->epstate, 
        rcv_ev->p_hdr->commidx +
        INFINIPATH_KPF_RESERVED_BITS(p_hdr->iph.pkt_flags));
	    if_pf (epstaddr == NULL || epstaddr->epid != rcv_ev->epid)
	      return 0; /* Unknown packet - drop */
	    
	    rcv_ev->ipsaddr = epstaddr->ipsaddr;	    
	    flow = &rcv_ev->ipsaddr->flows[flowid];
	    sequence_num.val = __be32_to_cpu(p_hdr->bth[2]);
	    diff = (int16_t) (sequence_num.pkt - flow->recv_seq_num.pkt);
	    
	    if (diff >= 0 && !(flow->flags & IPS_FLOW_FLAG_NAK_SEND)) {	      
	      /* Mark flow as congested and attempt to generate NAK */
	      flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
	      rcv_ev->ipsaddr->stats.congestion_pkts++;
	      flow->last_seq_num = sequence_num;
	      
	      flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
	      flow->cca_ooo_pkts = 0;
	      ips_proto_send_nak((struct ips_recvhdrq *) rcv_ev->recvq, flow);
	    }
	    
	    /* Safe to process ACKs from header */
	    ips_proto_process_ack(rcv_ev);
	  }
	  break;
	default:
	  break;
	}
    }
    else if (tiderr)  /* tid error, but not on an eager pkt */
    {
	psm_ep_t    ep_err = PSMI_EP_LOGEVENT;
	int	    many_tids = 0, many_epids = 0;
	uint32_t    context_tid_off = 
		      __le32_to_cpu(rcv_ev->p_hdr->iph.ver_context_tid_offset);
	uint16_t tid, offset;
	uint64_t t_now = get_cycles();

	proto->tiderr_cnt++;

	/* Whether and how we will be logging this event */
	if (proto->tiderr_max > 0 && proto->tiderr_cnt >= proto->tiderr_max)
	    ep_err = PSMI_EP_NORETURN;
	else if (proto->tiderr_warn_interval != UINT64_MAX &&
		 proto->tiderr_tnext <= t_now) 
	    proto->tiderr_tnext = get_cycles() + proto->tiderr_warn_interval;
	else 
	    ep_err = NULL;

	if (ep_err != NULL) {
	    if (proto->tiderr_context_tid_off != context_tid_off) { /* many tids */
		if (proto->tiderr_context_tid_off != 0)
		    many_tids = 1;
		proto->tiderr_context_tid_off = context_tid_off;
	    }

	    if (proto->tiderr_epid != rcv_ev->epid) { /* many epids */
		if (proto->tiderr_epid != 0) 
		    many_epids = 1;
		proto->tiderr_epid = rcv_ev->epid;
	    }

	    rhf_errnum_string(pktmsg, sizeof(pktmsg), rcv_ev->error_flags);

	    tid = (context_tid_off >> INFINIPATH_I_TID_SHIFT) & 
			INFINIPATH_I_TID_MASK;
	    offset = (context_tid_off>>INFINIPATH_I_OFFSET_SHIFT) & 
			INFINIPATH_I_OFFSET_MASK;

	    psmi_handle_error(ep_err, PSM_EP_DEVICE_FAILURE,
		"%s with tid=%d,offset=%d,count=%d "
		"from %s%s %s %s", 
		 many_tids ? "Multiple TID Errors" : "TID Error",
		 tid, offset, proto->tiderr_cnt, 
		 psmi_epaddr_get_name(rcv_ev->epid),
		 many_epids ? " (and other hosts)" : "",
		 pktmsg, ep_err == PSMI_EP_NORETURN ?
		 "(Terminating...)" : "");
	}

	if (proto->protoexp && rcv_ev->ptype == RCVHQ_RCV_TYPE_EXPECTED)
	    ips_protoexp_handle_tiderr(rcv_ev);
    }
    else if (tf_generr)
      ips_protoexp_handle_tf_generr(rcv_ev);
    else if (tf_seqerr)
      ips_protoexp_handle_tf_seqerr(rcv_ev);
    else if (data_err) {
      uint8_t op_code = __be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 24 & 0xFF;
      
      if (!pkt_verbose_err) {
	rhf_errnum_string(pktmsg, sizeof(pktmsg), rcv_ev->error_flags);
	_IPATH_DBG("Error %s pkt type opcode 0x%x at hd=0x%x %s\n",
		   (rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER) ? "eager" :
		   (rcv_ev->ptype == RCVHQ_RCV_TYPE_EXPECTED) ? "expected" :
		   (rcv_ev->ptype == RCVHQ_RCV_TYPE_NON_KD) ? "non-kd" : 
		   "<error>",
		   op_code, rcv_ev->recvq->state->hdrq_head, pktmsg);
      }
      
      if (proto->protoexp && rcv_ev->ptype == RCVHQ_RCV_TYPE_EXPECTED)
	ips_protoexp_handle_data_err(rcv_ev);
    }
    else { /* not a tid or data error -- some other error */
	uint8_t op_code = __be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 24 & 0xFF;

	if (!pkt_verbose_err)
	  rhf_errnum_string(pktmsg, sizeof(pktmsg), rcv_ev->error_flags);
	
	/* else RHFerr decode printed below */
	_IPATH_DBG("Error pkt type 0x%x opcode 0x%x at hd=0x%x %s\n",
		   rcv_ev->ptype, op_code, rcv_ev->recvq->state->hdrq_head, pktmsg);
    }
    if (pkt_verbose_err) {
	if(!*pktmsg)
	    rhf_errnum_string(pktmsg, sizeof(pktmsg), rcv_ev->error_flags);
	ips_proto_show_header(rcv_ev->p_hdr, pktmsg);
    }

    return 0;
}

/*
 * Only valid packets make it to this point.
 */
int __recvpath
ips_proto_process_packet_inner(struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
    int ret = IPS_RECVHDRQ_CONTINUE;

    /* NOTE: Fault injection will currently not work with hardware suppression
     * on QLE73XX. See TODO below for reason why as we currently do not update
     * the hardware tidflow table if FI is dropping the packet.
     *
     * TODO: We need to look into the packet before dropping it and
     * if it's an expected packet AND we have hardware suppression then we
     * need to update the hardware tidflow table and the associated tidrecvc
     * state to fake having received a packet uptil some point in the window
     * defined by the loss rate. This way the subsequent err chk will be NAKd
     * and we can resync the flow with the sender. 
     * 
     * Note: For real errors the hardware generates seq/gen errors which are
     * handled appropriately by the protocol.
     */

    if_pf (PSMI_FAULTINJ_ENABLED()) {
	PSMI_FAULTINJ_STATIC_DECL(fi_recv, "recvlost", 1, IPS_FAULTINJ_RECVLOST);
	if (psmi_faultinj_is_fault(fi_recv))
	    return ret;
    }

    switch (rcv_ev->ptype) {
        case RCVHQ_RCV_TYPE_EAGER:
   #if 0
	    _IPATH_VDBG("got packet from %d with opcode=%x, seqno=%d\n", 
		    p_hdr->commidx,
		    p_hdr->sub_opcode, 
		    __be32_to_cpu(p_hdr->bth[2]));
   #endif

            switch ( p_hdr->sub_opcode ) {
            case OPCODE_SEQ_MQ_HDR:
            case OPCODE_SEQ_MQ_CTRL:
		ret = _process_mq(rcv_ev);
                break;

            case OPCODE_ACK:
	        ips_proto_process_ack(rcv_ev);
                break;

            case OPCODE_NAK:
                _process_nak(rcv_ev);
                break;

	    case OPCODE_AM_REQUEST:
	    case OPCODE_AM_REQUEST_NOREPLY:
	    case OPCODE_AM_REPLY:
		ret = ips_proto_am(rcv_ev);
		break;
	    case OPCODE_FLOW_CCA_BECN:
	      {
		struct ips_proto *proto = ipsaddr->proto;
		struct ips_flow *flow = NULL;
		psm_protocol_type_t protocol;
		ptl_epaddr_flow_t flowid;

		protocol = IPS_FLOWID_GET_PROTO(p_hdr->flowid);
		flowid = IPS_FLOWID_GET_INDEX(p_hdr->flowid);
		psmi_assert_always(protocol == PSM_PROTOCOL_GO_BACK_N);
		flow = &ipsaddr->flows[flowid];
		
	        if ((flow->path->epr_ccti +
		proto->cace[flow->path->epr_sl].ccti_increase) <=
		proto->ccti_limit) {
		  ips_cca_adjust_rate(flow->path,
			proto->cace[flow->path->epr_sl].ccti_increase);
		  /* Clear congestion event */
		  rcv_ev->is_congested &= ~IPS_RECV_EVENT_BECN;
		}
	      }
	      break;
		
            case OPCODE_ERR_CHK:
            case OPCODE_ERR_CHK_OLD:
	      _process_err_chk((struct ips_recvhdrq *) rcv_ev->recvq, 
			       ipsaddr, p_hdr);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
                break;
		
            case OPCODE_ERR_CHK_GEN:
	        _process_err_chk_gen(ipsaddr, p_hdr);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
		break;

            case OPCODE_ERR_CHK_PLS:   /* skip for now  */
                break;

            case OPCODE_ERR_CHK_BAD: 
                _process_err_chk_bad(ipsaddr, p_hdr);
                break;

	    case OPCODE_TIDS_GRANT:
		ips_protoexp_tid_grant(rcv_ev);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
		break;

	    case OPCODE_TIDS_GRANT_ACK:
		ips_protoexp_tid_grant_ack(rcv_ev);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
		break;

            case OPCODE_TIDS_RELEASE:
		ret = ips_protoexp_tid_release(rcv_ev);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
                break;

            case OPCODE_TIDS_RELEASE_CONFIRM:
                ips_protoexp_tid_release_ack(rcv_ev);
		/* Ignore FECN bit since this is the control path */
		rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
                break;

	    case OPCODE_SEQ_MQ_EXPTID:
	        ips_protoexp_data(rcv_ev);
		break;
		
	    case OPCODE_SEQ_MQ_EXPTID_UNALIGNED:
		ips_protoexp_recv_unaligned_data(rcv_ev);
		break;
     
	    case OPCODE_CONNECT_REQUEST:
	    case OPCODE_CONNECT_REPLY:
	    case OPCODE_DISCONNECT_REQUEST:
	    case OPCODE_DISCONNECT_REPLY:
		_process_connect(rcv_ev);
		break;
		
            default:   /* skip unsupported opcodes  */
                _process_unknown_opcode(rcv_ev->proto, p_hdr);
                break;
            }   /* switch (op_code) */
            break;

        case RCVHQ_RCV_TYPE_EXPECTED:
	    ips_protoexp_data(rcv_ev);
            break;

        default:       /* unknown frame type */
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		"Unknown frame type %x", rcv_ev->ptype);
            break;
    }  /* switch (ptype)  */

    return ret;
}
