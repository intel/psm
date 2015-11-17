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

#ifndef _IPS_PROTO_HELP_H
#define _IPS_PROTO_HELP_H

#include "ips_recvhdrq.h"
#include "ips_proto.h"
#include "ipserror.h"
#include "psm_mq_internal.h" // psmi_mq_handle_tiny_envelope
#include "ptl_ips.h"
#include "ips_epstate.h"

/* Some tunable compile-time options */
#define IPS_TINY_PROCESS_MQTINY 1   /* whether mq processing of tiny pkts is
				       done separately from non-tiny packets */

PSMI_ALWAYS_INLINE(
uint8_t
ips_flow_gen_ackflags(ips_scb_t *scb, struct ips_flow *flow))
{
  uint32_t diff = (flow->protocol == PSM_PROTOCOL_TIDFLOW) ? 
    (flow->xmit_seq_num.seq - flow->xmit_ack_num.seq) :
    (flow->xmit_seq_num.pkt - flow->xmit_ack_num.pkt);
    
    /*
     * This is currently disabled pending more experimentation.  The goal
     * is to eventually use the FLAG_INTR to tighten the control loop
     * between two endpoints.
     */
#if 0
    /* At every 64, request ack w/ interrupt */
    if ((diff & 0x3f) == 0) 
	scb->flags |= IPS_SEND_FLAG_ACK_REQ |
		     (flow->ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD) ?
		     IPS_SEND_FLAG_INTR : 0;
    /* At every 16, request ack */
    else 
#endif
      if (((diff & flow->ack_interval) == 0) || (flow->credits == 1))
	scb->flags |= IPS_SEND_FLAG_ACK_REQ;

    /* Bottom 8 bits wind up in protocol header fields, other bits
     * control other aspects of packet composition */
    return (uint8_t) (scb->flags & IPS_SEND_FLAG_PROTO_OPTS);
}

PSMI_ALWAYS_INLINE(
ptl_epaddr_flow_t ips_proto_flowid(struct ips_message_header *p_hdr))
{
  ptl_epaddr_flow_t flowidx = IPS_FLOWID2INDEX(p_hdr->flowid);
  psmi_assert(flowidx < EP_FLOW_LAST);
  return flowidx;
}

PSMI_ALWAYS_INLINE(
void ips_kdeth_cksum(struct ips_message_header *p_hdr))
{
  /* Compute KDETH checksum */
  p_hdr->iph.chksum = __cpu_to_le16(
        (uint16_t) IPATH_LRH_BTH +
        (uint16_t) (__be16_to_cpu(p_hdr->lrh[2])) - 
        (uint16_t) ((__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)>>16) & 
		    LOWER_16_BITS) -
        (uint16_t) (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset) & 
		    LOWER_16_BITS) -
        (uint16_t) __le16_to_cpu(p_hdr->iph.pkt_flags));
}

PSMI_ALWAYS_INLINE(
int ips_do_cksum(struct ips_proto *proto,
		 struct ips_message_header *p_hdr,
		 void *payload,
		 uint32_t paylen,
		 uint32_t *cksum))
{

  if_pf ((proto->flags & IPS_PROTO_FLAG_CKSUM) && 
      (((__le32_to_cpu(p_hdr->iph.ver_context_tid_offset) >> INFINIPATH_I_TID_SHIFT) & INFINIPATH_I_TID_MASK) == IPATH_EAGER_TID_ID) && (p_hdr->mqhdr != MQ_MSG_DATA_BLK) && (p_hdr->mqhdr != MQ_MSG_DATA_REQ_BLK)) {
    
    uint16_t paywords;
        
    /* Update the payload words in header */
    paywords = (sizeof(struct ips_message_header) +
		paylen + PSM_CRC_SIZE_IN_BYTES) >> BYTE2WORD_SHIFT;
    p_hdr->lrh[2] = __cpu_to_be16(paywords + SIZE_OF_CRC);

    /* Need to regenerate KDETH checksum after updating payload length */
    ips_kdeth_cksum(p_hdr); 
      
    *cksum = 0xffffffff;
      
    /* Checksum header */
    *cksum = ips_crc_calculate(sizeof(struct ips_message_header), 
			       (uint8_t*) p_hdr, *cksum);
      
    /* Checksum payload (if any) */
    if (paylen) {
      psmi_assert_always(payload);
      *cksum = ips_crc_calculate(paylen, (uint8_t*) payload, 
				    *cksum);
    }
  }

  return 0;
}

/* Get pbc static rate value for flow for a given message length */
PSMI_ALWAYS_INLINE(
uint32_t ips_proto_pbc_static_rate(struct ips_flow *flow, uint32_t msgLen))
{
  uint32_t rate = 0;

  /* The PBC rate is based on which HCA type as QLE73XX/QLE72XX have different
   * mechanism for static rate control. QLE71XX does not even have static
   * rate control capability.
   */
  
  switch(flow->epinfo->ep_hca_type) {
  case PSMI_HCA_TYPE_QLE73XX: 
    {
      
      /* Rate = IPD * Time to transmit the packet. The rate value is
       * programmed into the PBC which counts down at a rate of 500 MHz the
       * TXE to IBC interface speed (Section 7.8.1). Since time to transmit
       * depends on our local link speed we need to convert that into the
       * clock frequency of the TXE in 500 MHz units. To transfer a message of
       * MSgLen bytes for various local link rates we obtain:
       *
       * Link Rate (LinWidth * LinkSpeed)       Cycle Count
       * SDR (10 Gbit/sec)                      (MsgLen >> 1)
       * DDR (20 Gbit/sec)                      (MsgLen >> 2)
       * QDR (40 Gbit/sec)                      (MsgLen >> 3)
       */
      static uint8_t qle73xx_rate_divisor[IBTA_RATE_120_GBPS + 1] = {
	[IBTA_RATE_2_5_GBPS] = 0,
	[IBTA_RATE_5_GBPS] = 0,
	[IBTA_RATE_10_GBPS] = 1,
	[IBTA_RATE_20_GBPS] = 2,
	[IBTA_RATE_30_GBPS] = 2,
	[IBTA_RATE_40_GBPS] = 3
      };

      uint32_t time_to_send = (msgLen >> 
			       qle73xx_rate_divisor[flow->epinfo->ep_link_rate]);
      /* IBTA CCA additionally has a shift_field for finer grained control
       * of IPD (This is bit [14:15] in the CCT entry. For static rate control
       * this value is always so.
       */
      rate = (time_to_send >> flow->path->epr_cca_divisor) * 
	     (flow->path->epr_active_ipd); 

      /* For QLE73XX the max rate is 0x3FF*/
      rate = min(rate, 0x3FFF);
    }
    break;
  case PSMI_HCA_TYPE_QLE72XX:
    /* TODO_CCA: Implement for QLE72XX to take into account the PREVIOUS
     * messages IPD for this flow/path.
     */
    rate = 0;
    break;
  default:
    rate = 0;
  }
  
  return rate;
}

/* This is only used for SDMA cases; pbc is really a pointer to
 * struct ips_pbc_header * or the equivalent un-named structure
 * in ips_scb */
PSMI_ALWAYS_INLINE(
void ips_proto_pbc_update(struct ips_proto *proto, 
			  struct ips_flow *flow, uint32_t isCtrlMsg,
			  union ipath_pbc *pbc, uint32_t hdrlen, 
			  void *payload, uint32_t paylen))
{
    struct ips_spio *ctrl = proto->spioc;
    struct ips_message_header *p_hdr = (struct ips_message_header*) &pbc[1];
    int vl = (__be16_to_cpu(p_hdr->lrh[0]) >> LRH_VL_SHIFT) & 0xf;
    uint32_t static_rate = 0;
    
    if_pf (!isCtrlMsg && flow->path->epr_active_ipd)
      static_rate = ips_proto_pbc_static_rate(flow, hdrlen + paylen);
    
    pbc->qword  = 0ULL;
    pbc->length =  __cpu_to_le16( ((hdrlen + paylen) >> 2) + 1);
    if (ctrl->portnum > 1)
      pbc->pbcflags |= __cpu_to_le32(vl << __PBC_VLSHIFT | 
				     __PBC_IBPORT | 
				     static_rate);
    else
      pbc->pbcflags |= __cpu_to_le32(vl << __PBC_VLSHIFT | 
				     static_rate);
    
    return;
}

/* 
 * Helpers to extract header information 
 */
/* With QLE73XX/QLE72XX, we put context 16 in src_context_ext */
#define IPS_HEADER_SRCCONTEXT_GET(msg_hdr)				\
	    (((msg_hdr)->src_context) | ((msg_hdr)->src_context_ext<<4))

#define IPS_HEADER_SRCCONTEXT_SET(msg_hdr,context)    do {	\
	    (msg_hdr)->src_context = (context) & 0xf;		\
	    (msg_hdr)->src_context_ext = (context>>4) & 0x3;	\
	} while (0)

PSMI_ALWAYS_INLINE(
uint32_t ips_proto_dest_context_from_header(struct ips_proto *proto,
					    struct ips_message_header *p_hdr))
{
  uint16_t hca_type;
  uint32_t dest_context;
  
  hca_type = PSMI_EPID_GET_HCATYPE(proto->ep->epid);
  
  dest_context = 
    (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset) >> INFINIPATH_I_CONTEXT_SHIFT) & INFINIPATH_I_CONTEXT_MASK;
  switch(hca_type) {
  case PSMI_HCA_TYPE_QLE73XX:
    dest_context |= ((__be32_to_cpu(p_hdr->bth[1]) & 1) << 4);
    break;
  case PSMI_HCA_TYPE_QLE72XX:
    /* Context 16 is special cased on QLE72XX */
    dest_context |= ((__be32_to_cpu(p_hdr->bth[1]) & 1) << 4);
    if (dest_context == 0x1f)
      dest_context = 16;
    break;
  case PSMI_HCA_TYPE_QLE71XX:
  default:
    /* This is a no-op. */
    break;
  }
  
  return dest_context;
}

PSMI_ALWAYS_INLINE(
void ips_proto_hdr(ips_scb_t *scb,
		   struct ips_epinfo *epinfo, 
		   struct ips_epinfo_remote *epr,
		   struct ips_flow *flow,
		   uint32_t paywords, 
		   uint32_t extra_bytes, 
		   uint16_t kpf_flags,
		   uint8_t flags))
{
    struct ips_message_header *p_hdr = &scb->ips_lrh;

    /*
     * This scb has been used by this connection last time,
     * so some of the header fields are already set.
     */
    if (scb->flow == flow && scb->epaddr == flow->ipsaddr) {
	p_hdr->bth[2]      = __cpu_to_be32(flow->xmit_seq_num.psn);
	p_hdr->flags       = flags;
	p_hdr->ack_seq_num = flow->recv_seq_num.psn;

	/* check if extra bytes is changed */
	if (scb->extra_bytes != extra_bytes) {
	    p_hdr->bth[0] =
		__cpu_to_be32((IPATH_OPCODE_USER1 << BTH_OPCODE_SHIFT) +
		(extra_bytes << BTH_EXTRA_BYTE_SHIFT) +
		flow->path->epr_pkey);
	    scb->extra_bytes = extra_bytes;
	}

	/* If header is exactly the same */
	if (scb->tid == IPATH_EAGER_TID_ID &&
		scb->pkt_flags == kpf_flags &&
		scb->payload_bytes == scb->payload_size) {
	    return;
	}

	/* context, version, and TID are already known to be in range, no
	 * masking needed; offset in low INFINIPATH_I_OFFSET_MASK  bits */
	p_hdr->iph.ver_context_tid_offset = __cpu_to_le32(
		(IPS_PROTO_VERSION << INFINIPATH_I_VERS_SHIFT) +
		(epr->epr_pkt_context << INFINIPATH_I_CONTEXT_SHIFT) +
		(scb->tid << INFINIPATH_I_TID_SHIFT) +
		(scb->offset >> 2)); // convert from byte to word offset

	p_hdr->lrh[2] = __cpu_to_be16(paywords + SIZE_OF_CRC);
	p_hdr->iph.pkt_flags = __cpu_to_le16(kpf_flags);

	ips_kdeth_cksum(p_hdr); // Generate KDETH checksum

	scb->pkt_flags = kpf_flags;
	scb->payload_bytes = scb->payload_size;

	return;
    }

    p_hdr->lrh[0] = 
    __cpu_to_be16(IPATH_LRH_BTH |
		  (flow->sl << 4) |  /* SL for flow */     
    /* VL for flow */ (flow->path->proto->sl2vl[flow->sl] << LRH_VL_SHIFT));
    p_hdr->lrh[1] = flow->path->epr_dlid;
    p_hdr->lrh[2] = __cpu_to_be16(paywords + SIZE_OF_CRC);
    p_hdr->lrh[3] = flow->path->epr_slid;

    p_hdr->bth[0] = 
	    __cpu_to_be32((IPATH_OPCODE_USER1 << BTH_OPCODE_SHIFT) +
                          (extra_bytes << BTH_EXTRA_BYTE_SHIFT) +
                          flow->path->epr_pkey);
    p_hdr->bth[1] = __cpu_to_be32(epr->epr_qp);
    p_hdr->bth[2] = __cpu_to_be32(flow->xmit_seq_num.psn);
    p_hdr->commidx = (uint16_t) epr->epr_commidx_to;

    /* context, version, and TID are already known to be in range, no
     * masking needed; offset in low INFINIPATH_I_OFFSET_MASK  bits */
    p_hdr->iph.ver_context_tid_offset = __cpu_to_le32(
        (IPS_PROTO_VERSION << INFINIPATH_I_VERS_SHIFT) +
        (epr->epr_pkt_context << INFINIPATH_I_CONTEXT_SHIFT) +
        (scb->tid << INFINIPATH_I_TID_SHIFT) +
        (scb->offset >> 2)); // convert from byte to word offset
    p_hdr->iph.pkt_flags = __cpu_to_le16(kpf_flags);
    
    ips_kdeth_cksum(p_hdr); // Generate KDETH checksum

    p_hdr->flags       = flags;
    p_hdr->flowid      = flow->flowid;
    p_hdr->ack_seq_num = flow->recv_seq_num.psn;
    IPS_HEADER_SRCCONTEXT_SET(p_hdr, epinfo->ep_context);
    p_hdr->src_subcontext = epinfo->ep_subcontext;
    p_hdr->dst_subcontext = epr->epr_subcontext;

    scb->extra_bytes   = extra_bytes;
    scb->pkt_flags     = kpf_flags;
    scb->payload_bytes = scb->payload_size;
    scb->flow          = flow;
    scb->epaddr        = flow->ipsaddr;

    return;
}

/* 
 * Assumes that the following fields are already set in scb:
 * payload
 * payload_size
 * flags
 */
PSMI_INLINE(
void
ips_scb_prepare_flow_inner(ips_scb_t *scb,
		     struct ips_epinfo *epinfo, 
		     struct ips_epinfo_remote *epr,
		     struct ips_flow *flow))
{
    uint32_t extra_bytes;
    uint32_t tot_paywords;
    uint16_t pkt_flags = IPS_EPSTATE_COMMIDX_PACK(epr->epr_commidx_to);
    
    extra_bytes = scb->payload_size & 3;
    if (extra_bytes) {
      extra_bytes = 4 - extra_bytes;
      scb->payload_size += extra_bytes;
    }
    tot_paywords = (sizeof(struct ips_message_header) + scb->payload_size) 
                    >> BYTE2WORD_SHIFT;
    pkt_flags |= (scb->flags & IPS_SEND_FLAG_INTR) ? INFINIPATH_KPF_INTR : 0;
    pkt_flags |= (scb->flags & IPS_SEND_FLAG_HDR_SUPPRESS) ?
      INFINIPATH_KPF_HDRSUPP : 0;
    
    ips_proto_hdr(scb, epinfo, epr, flow,
		  tot_paywords, extra_bytes,
		  pkt_flags, ips_flow_gen_ackflags(scb, flow));		  

    scb->ack_timeout = flow->path->epr_timeout_ack;
    scb->abs_timeout = TIMEOUT_INFINITE;
    scb->flags      |= IPS_SEND_FLAG_PENDING;

    if (flow->protocol == PSM_PROTOCOL_TIDFLOW) {
      flow->xmit_seq_num.seq += scb->nfrag;
      scb->seq_num = flow->xmit_seq_num;
      scb->seq_num.seq--;
    } else {
      flow->xmit_seq_num.pkt += scb->nfrag;
      scb->seq_num = flow->xmit_seq_num;
      scb->seq_num.pkt--;
    }

    return;
}

PSMI_ALWAYS_INLINE(
psm_epid_t
ips_epid_from_phdr(const uint16_t lmc_mask, 
		   const struct ips_message_header *p_hdr))
{
    uint16_t lid     = __be16_to_cpu(p_hdr->lrh[3]) & lmc_mask;
    uint16_t context    = (uint16_t) IPS_HEADER_SRCCONTEXT_GET(p_hdr);
    uint16_t subcontext = (uint16_t) p_hdr->src_subcontext;
 
    return PSMI_EPID_PACK(lid, context, subcontext);
}

PSMI_ALWAYS_INLINE(
void
ips_epaddr_stats_send(struct ptl_epaddr *ptladdr, uint8_t msgtype))
{
    switch (msgtype) {
	case OPCODE_ACK:
	    break;
	case OPCODE_TIDS_GRANT:
	    ptladdr->stats.tids_grant_send++;
	    break;
	case OPCODE_ERR_CHK:
        case OPCODE_ERR_CHK_GEN:
	    ptladdr->stats.err_chk_send++;
	    break;
	case OPCODE_NAK:
	    ptladdr->stats.nak_send++;
	    break;
	case OPCODE_CONNECT_REQUEST:
	    ptladdr->stats.connect_req++;
	    break;
	case OPCODE_DISCONNECT_REQUEST:
	    ptladdr->stats.disconnect_req++;
	    break;
	default:
	    break;
    }
    return;
}

/* 
 * Exported there solely for inlining is_expected_or_nak and mq_tiny handling
 */
extern
psm_error_t ips_proto_send_ctrl_message(struct ips_flow *flow, 
					uint8_t message_type,
					uint32_t *msg_queue_mask, 
					void *payload);

PSMI_ALWAYS_INLINE(
void 
ips_proto_send_ack(struct ips_recvhdrq *recvq, struct ips_flow *flow))
{
  if_pt (recvq->proto->flags & IPS_PROTO_FLAG_COALESCE_ACKS) {
    if (flow->flags & IPS_FLOW_FLAG_PENDING_NAK) {
      flow->flags &= ~IPS_FLOW_FLAG_PENDING_NAK; /* ACK clears NAK */
    }
    else if (!(flow->flags & IPS_FLOW_FLAG_PENDING_ACK)) {
      SLIST_INSERT_HEAD(&recvq->pending_acks, flow, next);
    }
    
    flow->flags |= IPS_FLOW_FLAG_PENDING_ACK;  
  }
  else {
    /* Coalesced ACKs disabled. Send ACK immediately */
    ips_proto_send_ctrl_message(flow, OPCODE_ACK, 
				&flow->ipsaddr->ctrl_msg_queued, NULL);
  }
}

PSMI_ALWAYS_INLINE(
void 
ips_proto_send_nak(struct ips_recvhdrq *recvq, struct ips_flow *flow))
{
  if_pt (recvq->proto->flags & IPS_PROTO_FLAG_COALESCE_ACKS) {
    if (flow->flags & IPS_FLOW_FLAG_PENDING_ACK) {
      flow->flags &= ~IPS_FLOW_FLAG_PENDING_ACK; /* NAK clears ACK */
    }
    else if (!(flow->flags & IPS_FLOW_FLAG_PENDING_NAK)) {
      SLIST_INSERT_HEAD(&recvq->pending_acks, flow, next);
    }
    
    flow->flags |= IPS_FLOW_FLAG_PENDING_NAK;  
  }
  else {
    /* Coalesced ACKs disabled. Send NAK immediately */
    ips_proto_send_ctrl_message(flow, OPCODE_NAK, 
				&flow->ipsaddr->ctrl_msg_queued, NULL);
  }
}

/* return 1 if packet is next expected in flow
 * return 0 if packet is not next expected in flow (and nak packet).
 */
PSMI_ALWAYS_INLINE(
int
ips_proto_is_expected_or_nak(struct ips_recvhdrq_event *rcv_ev))
{
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
    struct ips_flow *flow = &ipsaddr->flows[flowid];
    psmi_seqnum_t sequence_num;
    
    psmi_assert((flowid == EP_FLOW_GO_BACK_N_PIO) ||
		(flowid == EP_FLOW_GO_BACK_N_DMA) ||
		(flowid == EP_FLOW_GO_BACK_N_AM_REQ) ||
		(flowid == EP_FLOW_GO_BACK_N_AM_RSP)
		);
    
    /* If packet faced congestion generate BECN in NAK. */
    if_pf ((rcv_ev->is_congested & IPS_RECV_EVENT_FECN) &&
	   ((flow->cca_ooo_pkts & 0xf) == 0)) {
      /* Generate a BECN for every 16th OOO packet marked with a FECN. */
      flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
      flow->cca_ooo_pkts++;
      ipsaddr->stats.congestion_pkts++;
      rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN; /* Clear FECN event */
    }
    
    sequence_num.val = __be32_to_cpu(p_hdr->bth[2]);
    if_pf (flow->recv_seq_num.pkt != sequence_num.pkt) {
      int16_t diff = (int16_t) (sequence_num.pkt - flow->last_seq_num.pkt);
      
      if (diff < 0)
	return 0;

      flow->cca_ooo_pkts = diff;
      if (flow->cca_ooo_pkts > flow->ack_interval) {
	ipsaddr->stats.congestion_pkts++;
	flow->flags |= IPS_FLOW_FLAG_GEN_BECN;
	_IPATH_CCADBG("BECN Generation. Expected: %d, Got: %d.\n", flow->recv_seq_num.pkt, sequence_num.pkt);
      }
      flow->last_seq_num = sequence_num;
      
      if (!(flow->flags & IPS_FLOW_FLAG_NAK_SEND)) {	
	/* Queue/Send NAK to peer  */
	ips_proto_send_nak((struct ips_recvhdrq *) rcv_ev->recvq, flow);
	flow->flags |= IPS_FLOW_FLAG_NAK_SEND;
	flow->cca_ooo_pkts = 0;
      } 
      else if (flow->flags & IPS_FLOW_FLAG_GEN_BECN) {
	/* Send Control message to throttle flow. Will clear flow flag and
	 * reset cca_ooo_pkts. 
	 */
	ips_proto_send_ctrl_message(flow, OPCODE_FLOW_CCA_BECN, 
				    &flow->ipsaddr->ctrl_msg_queued, 
				    NULL);
      }
            
      return 0;
    }
    else {
      flow->flags &= ~IPS_FLOW_FLAG_NAK_SEND;
      
      flow->last_seq_num = sequence_num;
      flow->recv_seq_num.pkt += 1;
      flow->cca_ooo_pkts = 0;
      return 1;
    }
}

/*
 * Return value:
 *	1: in order message;
 *	0: out of order, no touch;
 *	-1: out of order, buffered in outoforder queue.
 */
PSMI_ALWAYS_INLINE(
int 
ips_proto_check_msg_order(psm_epaddr_t epaddr,
	struct ips_flow *flow, struct ips_message_header *p_hdr))
{
  uint16_t msg_seqnum = (uint16_t)(flow->last_seq_num.msg +
			((p_hdr->ack_seq_num>>8)&0xff00));

  if (msg_seqnum != epaddr->mctxt_master->mctxt_recv_seqnum) {
    flow->msg_ooo_toggle = !flow->msg_ooo_toggle;

    if (flow->msg_ooo_toggle) {
	flow->recv_seq_num.pkt -= 1;
	flow->msg_ooo_seqnum = msg_seqnum;
	return 0;
    }

    psmi_assert(msg_seqnum == flow->msg_ooo_seqnum);
    return -1;
  }

  flow->msg_ooo_toggle = 0;
  epaddr->mctxt_master->mctxt_recv_seqnum++;
  return 1;
}

#if IPS_TINY_PROCESS_MQTINY
PSMI_ALWAYS_INLINE(
int 
ips_proto_process_mq_tiny(const struct ips_recvhdrq_event *rcv_ev))
{
  ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
  psm_epaddr_t epaddr = ipsaddr->epaddr;
  struct ips_message_header *p_hdr = rcv_ev->p_hdr;
  ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
  struct ips_flow *flow = &ipsaddr->flows[flowid];
  int ret = IPS_RECVHDRQ_CONTINUE;
  
  if (ips_proto_is_expected_or_nak((struct ips_recvhdrq_event*) rcv_ev)) {
    ret = ips_proto_check_msg_order(epaddr, flow, p_hdr);
    if (ret == 0) return IPS_RECVHDRQ_OOO;
    if (ret == -1) {
	psmi_mq_handle_envelope_outoforder(ipsaddr->proto->mq,
		(uint16_t) p_hdr->mqhdr,
		epaddr, flow->msg_ooo_seqnum,
		p_hdr->data[0].u64, /* tag */
		epaddr->xmit_egrlong, /* place hold only */
		(uint32_t) p_hdr->hdr_dlen,
		(void *) &p_hdr->data[1],
		(uint32_t) p_hdr->hdr_dlen);
	ret = IPS_RECVHDRQ_BREAK;
    } else {
	psmi_mq_handle_tiny_envelope(
		ipsaddr->proto->mq,
		epaddr, p_hdr->data[0].u64, /* tag */
		(void *) &p_hdr->data[1], 
		(uint32_t) p_hdr->hdr_dlen);
	if (epaddr->mctxt_master->outoforder_c) {
	    psmi_mq_handle_outoforder_queue(epaddr->mctxt_master);
	}
	ret = IPS_RECVHDRQ_CONTINUE;
    }
    if ((p_hdr->flags & IPS_SEND_FLAG_ACK_REQ)  ||
	(flow->flags & IPS_FLOW_FLAG_GEN_BECN))
      ips_proto_send_ack((struct ips_recvhdrq *) rcv_ev->recvq, flow);
  }
  
  ips_proto_process_ack((struct ips_recvhdrq_event *) rcv_ev);
  return ret;
}
#endif

PSMI_INLINE(
int
ips_proto_process_packet(const struct ips_recvhdrq_event *rcv_ev))
{
#if IPS_TINY_PROCESS_MQTINY
    if (rcv_ev->p_hdr->sub_opcode == OPCODE_SEQ_MQ_HDR) {
	psmi_assert(rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER);
	return ips_proto_process_mq_tiny(rcv_ev);
    }
    else 
#endif
      return ips_proto_process_packet_inner((struct ips_recvhdrq_event *) rcv_ev);
}

#if PSMI_PLOCK_DISABLED
  #define ips_ptladdr_lock(ipsaddr)			\
	if (((ipsaddr)->flags & SESS_FLAG_LOCK_SESS))   \
	    pthread_mutex_lock(&(ipsaddr)->sesslock)

  #define ips_ptladdr_unlock(ipsaddr)			\
	if (((ipsaddr)->flags & SESS_FLAG_LOCK_SESS))   \
	    pthread_mutex_unlock(&(ipsaddr)->sesslock)
#else
  #define ips_ptladdr_lock(ipsaddr)
  #define ips_ptladdr_unlock(ipsaddr)
#endif

/*
 * Breaks header encapsulation but needed in mq sends so we can pay
 * "near-equal" attention to putting sends on the wire and servicing the
 * receive queue.
 */

PSMI_ALWAYS_INLINE(
psm_error_t
ips_recv_progress_if_busy(ptl_t *ptl, psm_error_t err))
{
    if (err == PSM_EP_NO_RESOURCES) {
	ptl->ctl->ep_poll(ptl, 0);
	return PSM_OK;
    }
    else 
	return err;
}

/* Find next lowest power of a two for a 32 bit number*/
PSMI_ALWAYS_INLINE(
unsigned int 
ips_next_low_pow2(unsigned int v))
{

  const unsigned int b[] = {0x2, 0xC, 0xF0, 0xFF00, 0xFFFF0000};
  const unsigned int S[] = {1, 2, 4, 8, 16};
  register unsigned int r = 1; 
  int i;

  for (i = 4; i >= 0; i--) 
    {
      if (v & b[i])
	{
	  v >>= S[i];
	  r <<= S[i];
	}
    }
  
  return r;
}

PSMI_ALWAYS_INLINE(
ips_path_rec_t *ips_select_path(struct ips_proto *proto, 
				ips_path_type_t path_type,
				ips_epaddr_t *ipsaddr))
{
  uint32_t path_idx;
  
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE) {
    /* If dispersive routes are configured then select the routes in round
     * robin order. We may want to use congestion information to select the
     * least lightly loaded path.
     */
    path_idx = ipsaddr->epr.epr_next_path[path_type];
    if (++ipsaddr->epr.epr_next_path[path_type] >=
	ipsaddr->epr.epr_num_paths[path_type])
      ipsaddr->epr.epr_next_path[path_type] = 0;
  }
  else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_DST)
    path_idx = /* Key on destination context */
      ipsaddr->epr.epr_context  % ipsaddr->epr.epr_num_paths[path_type];
  else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_SRC)
    path_idx = /* Key off src context */
      ipsaddr->proto->ep->context.base_info.spi_context % ipsaddr->epr.epr_num_paths[path_type];
  else /* Base LID routed - Default in Infinipath 2.5 (Oct 09). */
    path_idx = 0;
  
  return ipsaddr->epr.epr_path[path_type][path_idx];
}

#endif /* _IPS_PROTO_HELP_H */
