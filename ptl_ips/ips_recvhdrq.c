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

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_recvhdrq.h"

/*
 * TUNABLES TUNABLES TUNABLES
 */

/*
 * Receive Queue progress optimizations
 *
 * The recvhdrq_progress function supports 2 chip features, so can be written
 * to support 4 possible combinations in chip features (although only 3/4 are
 * currently implemented in our chips).
 *
 * We can either support recvhdrq_progress by implementing the function in 4
 * ways and calling it through a function pointer
 * (IPS_RCVHDRQ_THRU_FUNCTION_POINTER=1) or having one implementation that
 * covers all possible combinations (IPS_RCVHDRQ_THRU_FUNCTION_POINTER=0).
 */
#define IPS_RCVHDRQ_THRU_FUNCTION_POINTER 1

#if IPS_RCVHDRQ_THRU_FUNCTION_POINTER
static psm_error_t ips_recvhdrq_progress_none(struct ips_recvhdrq *recvq);
static psm_error_t ips_recvhdrq_progress_nortail(struct ips_recvhdrq *recvq);
#endif

 
psm_error_t 
ips_recvhdrq_init(const psmi_context_t *context,
		  const struct ips_epstate *epstate,
		  const struct ips_proto *proto,
		  const struct ips_recvq_params *hdrq_params,
		  const struct ips_recvq_params *egrq_params,
		  const struct ips_recvhdrq_callbacks *callbacks,
		  uint32_t runtime_flags,
		  uint32_t subcontext,
		  struct ips_recvhdrq *recvq,
		  struct ips_recvhdrq_state *recvq_state)
{
    const struct ipath_base_info *base_info = &context->base_info;
    psm_error_t err = PSM_OK;

    memset(recvq, 0, sizeof(*recvq));
    recvq->proto      = (struct ips_proto *) proto;
    recvq->state      = recvq_state;
    recvq->context       = context;
    recvq->subcontext    = subcontext;
    /* This runtime flags may be different from the context's runtime flags since
     * a receive queue may be initialised to represent a "software" receive
     * queue (shared contexts) or a hardware receive queue */
    recvq->runtime_flags = runtime_flags;
    recvq->hdrq = *hdrq_params; /* deep copy */
    pthread_spin_init(&recvq->hdrq_lock, PTHREAD_PROCESS_SHARED);
    recvq->hdrq_rhf_off = base_info->spi_rhf_offset;

    if (recvq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
	recvq->hdrq_rhf_notail = 1;
	recvq->state->hdrq_rhf_seq = 1; 
    }
    else {
	recvq->hdrq_rhf_notail = 0;
	recvq->state->hdrq_rhf_seq = 0; /* _seq is ignored */
    }
    recvq->hdrq_elemlast = ((recvq->hdrq.elemcnt - 1) * recvq->hdrq.elemsz);
    
    recvq->egrq = *egrq_params; /* deep copy */
    recvq->egrq_buftable = 
	ips_recvq_egrbuf_table_alloc(context->ep, recvq->egrq.base_addr, 
				     base_info->spi_rcv_egrchunksize,
				     recvq->egrq.elemcnt, recvq->egrq.elemsz);
    if (recvq->egrq_buftable == NULL) {
	err = psmi_handle_error(proto->ep, PSM_NO_MEMORY,
		    "Couldn't allocate memory for eager buffer index table");
	goto fail;
    }

    recvq->epstate = epstate;

    /* NOTE: We should document PSM_RCVHDRCOPY is not available with QIB? */

#if IPS_RCVHDRQ_THRU_FUNCTION_POINTER
    /* Only either have NODMA RTAIL (for QLE73XX/QLE72XX) or just the vanilla
       version for QLE71XX where RTAIL is DMA'd */
    if (recvq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL)
      recvq->progress_fn = ips_recvhdrq_progress_nortail;
    else
      recvq->progress_fn = ips_recvhdrq_progress_none;
#endif

    recvq->recvq_callbacks = *callbacks; /* deep copy */
    SLIST_INIT(&recvq->pending_acks); 

    recvq->state->hdrq_head = 0;
    recvq->state->rcv_egr_index_head = NO_EAGER_UPDATE;
    recvq->state->num_hdrq_done = 0;
    recvq->state->hdr_countdown = 0;
    
    {
      union psmi_envvar_val env_hdr_update;
      psmi_getenv("PSM_HEAD_UPDATE",
                  "header queue update interval (0 to update after all entries are processed). Default is 16",
                  PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
                  (union psmi_envvar_val) 16, &env_hdr_update);
      
      /* Cap max header update interval to size of header/eager queue */
      recvq->state->head_update_interval =
        min(env_hdr_update.e_uint,
            min(recvq->hdrq.elemcnt-1, recvq->egrq.elemcnt-1));
    }

fail:
    return err;
}

psm_error_t
ips_recvhdrq_fini(struct ips_recvhdrq *recvq)
{
    ips_recvq_egrbuf_table_free(recvq->egrq_buftable);
    return PSM_OK;
}

// flush the eager buffers, by setting the eager index head to eager index tail
// if eager buffer queue is full.
//
// Called when we had eager buffer overflows (ERR_TID/INFINIPATH_RHF_H_TIDERR
// was set in RHF errors), and no good eager packets were received, so
// that eager head wasn't advanced.
//

#if 0
static void ips_flush_egrq_if_required(struct ips_recvhdrq *recvq)
{
    const uint32_t tail = ips_recvq_tail_get(&recvq->egrq);
    const uint32_t head = ips_recvq_head_get(&recvq->egrq);
    uint32_t egr_cnt = recvq->egrq.elemcnt;

    if ((head % egr_cnt) == ((tail+1)%egr_cnt)) {
	_IPATH_DBG("eager array full after overflow, flushing "
		    "(head %llx, tail %llx)\n",
            (long long)head, (long long)tail);
	 recvq->proto->stats.egr_overflow++;
    }
    return;
}
#endif

/*
 * Helpers for ips_recvhdrq_progress.
 */

static __inline__ int 
_get_proto_subcontext(const struct ips_message_header *p_hdr)
{
  return p_hdr->dst_subcontext;
}

/* ipath_opcode is not the ips-level opcode. */
static __inline__ uint8_t 
_get_proto_ipath_opcode(const struct ips_message_header *p_hdr)
{
    return __be32_to_cpu(p_hdr->bth[0]) >> BTH_OPCODE_SHIFT & 0xFF;
}

/* Detrmine if FECN bit is set IBTA 1.2.1 CCA Annex A*/
static __inline__ uint8_t
_is_cca_fecn_set(const struct ips_message_header *p_hdr)
{
  return (__be32_to_cpu(p_hdr->bth[1]) >> BTH_FECN_SHIFT);
}

/* Detrmine if BECN bit is set IBTA 1.2.1 CCA Annex A*/
static __inline__ uint8_t
_is_cca_becn_set(const struct ips_message_header *p_hdr)
{
  return (__be32_to_cpu(p_hdr->bth[1]) >> BTH_BECN_SHIFT) & 0x1;
}

static __inline__ struct ips_message_header * 
_get_proto_hdr_from_rhf(const uint32_t *rcv_hdr, const __le32 *rhf)
{
    return (struct ips_message_header *) (rcv_hdr + ipath_hdrget_offset(rhf));
}

static __inline__ struct ips_message_header * 
_get_proto_hdr(const uint32_t *rcv_hdr)
{
    return (struct ips_message_header *) &rcv_hdr[2];
}

static __inline__ uint32_t
_get_rhf_seq(struct ips_recvhdrq *recvq, const __u32 *rcv_hdr)
{
    return ipath_hdrget_seq((const __le32 *) rcv_hdr + recvq->hdrq_rhf_off);
}

static __inline__ uint32_t
_get_rhf_len_in_bytes(struct ips_recvhdrq *recvq, const __u32 *rcv_hdr)
{
  return ipath_hdrget_length_in_bytes((const __le32*) rcv_hdr + recvq->hdrq_rhf_off);
}

static __inline__ void
_dump_invalid_pkt(struct ips_recvhdrq_event *rcv_ev)
{
  char *payload = ips_recvhdrq_event_payload(rcv_ev);
  uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);
  
  if(infinipath_debug & __IPATH_PKTDBG) {
    ips_proto_dump_frame(rcv_ev->p_hdr, IPATH_MESSAGE_HDR_SIZE, "header");
    if (paylen)
      ips_proto_dump_frame(payload, paylen, "data");
  }
  
}

static __inline__ void
_update_error_stats(struct ips_proto *proto, uint32_t err)
{

  if (err & INFINIPATH_RHF_H_ICRCERR)
    proto->error_stats.num_icrc_err++;
  if (err & INFINIPATH_RHF_H_VCRCERR)
    proto->error_stats.num_vcrc_err++;
  if (err & INFINIPATH_RHF_H_PARITYERR)
    proto->error_stats.num_ecc_err++;
  if (err & INFINIPATH_RHF_H_LENERR)
    proto->error_stats.num_len_err++;
  if (err & INFINIPATH_RHF_H_MTUERR)
    proto->error_stats.num_mtu_err++;
  if (err & INFINIPATH_RHF_H_IHDRERR)
    proto->error_stats.num_khdr_err++;
  if (err & INFINIPATH_RHF_H_TIDERR)
    proto->error_stats.num_tid_err++;
  if (err & INFINIPATH_RHF_H_MKERR)
    proto->error_stats.num_mk_err++;
  if (err & INFINIPATH_RHF_H_IBERR)
    proto->error_stats.num_ib_err++;
}

static int
_check_headers(struct ips_recvhdrq_event *rcv_ev)
{
  struct ips_recvhdrq *recvq = (struct ips_recvhdrq*) rcv_ev->recvq;
  struct ips_proto *proto = rcv_ev->proto;
  uint32_t *lrh = (uint32_t*) rcv_ev->p_hdr;
  const uint32_t *rcv_hdr = rcv_ev->rcv_hdr;
  uint32_t dest_context;
  const uint16_t pkt_dlid = __be16_to_cpu(rcv_ev->p_hdr->lrh[1]);
  const uint16_t base_dlid = __be16_to_cpu(recvq->proto->epinfo.ep_base_lid);

  /* Check that the receive header queue entry has a sane sequence number */
  if (_get_rhf_seq(recvq, rcv_hdr) > LAST_RHF_SEQNO) {         
    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		      "ErrPkt: Invalid header queue entry! RHF Sequence in Hdrq Seq: %d, Recvq State Seq: %d. LRH[0]: 0x%08x, LRH[1] (PktCount): 0x%08x\n", _get_rhf_seq(recvq, rcv_hdr), recvq->state->hdrq_rhf_seq, lrh[0], lrh[1]);
    return -1;
  }

  /* Verify that the packet was destined for our context */
  dest_context = ips_proto_dest_context_from_header(proto, rcv_ev->p_hdr);
  if_pf (dest_context != recvq->proto->epinfo.ep_context) {
    
    struct ips_recvhdrq_state *state = recvq->state;
    
    /* Packet not targetted at us. Drop packet and continue */
    ips_proto_dump_err_stats(proto);
    _dump_invalid_pkt(rcv_ev);
    
    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		       "ErrPkt: Received packet for context %d on context %d. Receive Header Queue offset: 0x%x. Exiting.\n", dest_context, recvq->proto->epinfo.ep_context, state->hdrq_head);
    
    return -1;
  }
  

  if_pf (rcv_ev->error_flags || 
	 (_get_proto_ipath_opcode(rcv_ev->p_hdr) != IPATH_OPCODE_USER1))  {
    
    return 0; /* Error flags are special case. Let main receive loop handle
	       * packet processing after we account for it. 
	       */
  }

  /* Verify that rhf packet length matches the length in LRH */
  if_pf (_get_rhf_len_in_bytes(recvq, rcv_hdr) != 
      (__be16_to_cpu(rcv_ev->p_hdr->lrh[2]) << 2)) {
    _IPATH_EPDBG("ErrPkt: RHF Packet Len (0x%x) does not match LRH (0x%x).\n", _get_rhf_len_in_bytes(recvq, rcv_hdr) >> 2, __be16_to_cpu(rcv_ev->p_hdr->lrh[2]));
    
    ips_proto_dump_err_stats(proto);
    _dump_invalid_pkt(rcv_ev);
    return -1;
  }

  /* Verify that the DLID matches our local LID. */
  if_pf (!((base_dlid <= pkt_dlid) && 
	   (pkt_dlid <= (base_dlid + (1 << recvq->proto->epinfo.ep_lmc))))) {
    _IPATH_EPDBG("ErrPkt: DLID in LRH (0x%04x) does not match local LID (0x%04x) Skipping packet!\n", rcv_ev->p_hdr->lrh[1], recvq->proto->epinfo.ep_base_lid);
    ips_proto_dump_err_stats(proto);
    _dump_invalid_pkt(rcv_ev);
    return -1;
  }

  return 0;
}

static __inline__ 
int
do_pkt_cksum(struct ips_recvhdrq_event *rcv_ev)
{
  char *payload = ips_recvhdrq_event_payload(rcv_ev);
  uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev) +
    ((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3);
  uint32_t *ckptr;
  uint32_t recv_cksum, cksum, dest_subcontext; 
  
  /* With checksum every packet has a payload */
  psmi_assert_always(payload);
  
  ckptr = (uint32_t*) (payload + paylen);
  recv_cksum = ckptr[0];
  
  /* Calculate checksum hdr + payload (includes any padding words) */
  cksum = 0xffffffff;
  cksum = ips_crc_calculate(IPATH_MESSAGE_HDR_SIZE,
			    (uint8_t*) rcv_ev->p_hdr,cksum);
  if (paylen)
    cksum = ips_crc_calculate(paylen, (uint8_t*) payload, cksum);
  
  if ((cksum != recv_cksum) || (ckptr[0] != ckptr[1])) {
    struct ips_epstate_entry *epstaddr;
    uint32_t lcontext;
    uint32_t hd, tl;
    
    epstaddr =
      ips_epstate_lookup(rcv_ev->recvq->epstate, rcv_ev->p_hdr->commidx +
          INFINIPATH_KPF_RESERVED_BITS(rcv_ev->p_hdr->iph.pkt_flags));
    epstaddr = (epstaddr && epstaddr->ipsaddr) ? epstaddr : NULL;
    
    lcontext = 
      epstaddr ? epstaddr->ipsaddr->proto->epinfo.ep_context : -1;
    
    hd = rcv_ev->recvq->context->ctrl->__ipath_rcvhdrhead[0];
    tl = rcv_ev->recvq->context->ctrl->__ipath_rcvhdrhead[-2];
    
    dest_subcontext = _get_proto_subcontext(rcv_ev->p_hdr);
    
    _IPATH_ERROR("ErrPkt: SharedContext: %s. Local Context: %i, Checksum mismatch from LID %d! Received Checksum: 0x%08x, Expected: 0x%08x & 0x%08x. Opcode: 0x%08x, Error Flag: 0x%08x. hdrq hd 0x%x tl 0x%x rhf 0x%x,%x, rhfseq 0x%x\n", (dest_subcontext != rcv_ev->recvq->subcontext) ? "Yes" : "No", lcontext, epstaddr ? __be16_to_cpu(epstaddr->ipsaddr->epr.epr_base_lid) : -1, cksum, ckptr[0], ckptr[1], rcv_ev->p_hdr->sub_opcode, rcv_ev->error_flags,hd, tl, rcv_ev->rhf[0], rcv_ev->rhf[1], _get_rhf_seq((struct ips_recvhdrq *) rcv_ev->recvq, rcv_ev->rcv_hdr));
    
    /* Dump packet */
    _dump_invalid_pkt(rcv_ev);
    return 0; /* Packet checksum error */
  }
  
  return 1;
}

PSMI_ALWAYS_INLINE(
void
process_pending_acks(struct ips_recvhdrq *recvq))
{
  /* If any pending acks, dispatch them now */
  while (!SLIST_EMPTY(&recvq->pending_acks)) {
    struct ips_flow *flow = SLIST_FIRST(&recvq->pending_acks);
    
    SLIST_REMOVE_HEAD(&recvq->pending_acks, next);
    SLIST_NEXT(flow, next) = NULL;

    if (flow->flags & IPS_FLOW_FLAG_PENDING_ACK) {
      psmi_assert_always((flow->flags & IPS_FLOW_FLAG_PENDING_NAK) == 0);
      
      flow->flags &= ~IPS_FLOW_FLAG_PENDING_ACK;
      ips_proto_send_ctrl_message(flow, OPCODE_ACK, 
					&flow->ipsaddr->ctrl_msg_queued, NULL);
    }
    else {
      psmi_assert_always(flow->flags & IPS_FLOW_FLAG_PENDING_NAK);
      
      flow->flags &= ~IPS_FLOW_FLAG_PENDING_NAK;
      ips_proto_send_ctrl_message(flow, OPCODE_NAK, 
					&flow->ipsaddr->ctrl_msg_queued, NULL);
    }
    
  }
  
}
    
/*
 * Core receive progress function
 *
 * recvhdrq_progress is the core function that services the receive header
 * queue and optionally, the eager queue.  At the lowest level, it identifies
 * packets marked with errors by the chip and also detects and corrects when
 * eager overflow conditions occur.  At the highest level, it queries the
 * 'epstate' interface to classify packets from "known" and "unknown"
 * endpoints.  In order to support shared contexts, it can also handle packets
 * destined for other contexts (or "subcontexts").
 */

#if IPS_RCVHDRQ_THRU_FUNCTION_POINTER
PSMI_ALWAYS_INLINE(
psm_error_t 
ips_recvhdrq_progress_inner(struct ips_recvhdrq *recvq,
			    const int has_no_rtail))
#else
psm_error_t __recvpath
ips_recvhdrq_progress(struct ips_recvhdrq *recvq)
#endif
{
    struct ips_recvhdrq_state *state = recvq->state;
    const __le32 *rhf;
    PSMI_CACHEALIGN struct ips_recvhdrq_event rcv_ev = { .proto = recvq->proto,
							 .recvq = recvq };

    uint32_t num_hdrq_done = 0;
    const int num_hdrq_todo = recvq->hdrq.elemcnt;
    const uint32_t hdrq_elemsz = recvq->hdrq.elemsz;
    uint32_t dest_subcontext;

    int ret = IPS_RECVHDRQ_CONTINUE;
    int done = 0;
    int do_hdr_update = 0;
    const uint16_t lmc_mask = ~((1 << recvq->proto->epinfo.ep_lmc) - 1);

    /* Chip features */
#if !IPS_RCVHDRQ_THRU_FUNCTION_POINTER
    const int has_no_rtail = recvq->runtime_flags & IPATH_RUNTIME_NODMA_RTAIL;
#endif
    
    /* Both optional_eager and no_rtail features are in the same chip rev */
#define has_optional_eagerbuf recvq->hdrq_rhf_off

    /* Returns whether the currently set 'rcv_hdr'/head is a readable entry */
#define next_hdrq_is_ready()						     \
	(has_no_rtail ? \
            recvq->state->hdrq_rhf_seq == _get_rhf_seq(recvq, rcv_hdr)  \
	  : state->hdrq_head != hdrq_tail)

    const uint32_t hdrq_tail = has_no_rtail ? 0
					    : ips_recvq_tail_get(&recvq->hdrq);
    const uint32_t *rcv_hdr = 
	    (const uint32_t *) recvq->hdrq.base_addr + state->hdrq_head;
    uint32_t tmp_hdrq_head;
    
    done = !next_hdrq_is_ready();

    while (!done)
    {
      
	rhf = (const __le32 *) rcv_hdr + recvq->hdrq_rhf_off;
        rcv_ev.error_flags = ipath_hdrget_err_flags(rhf);
        rcv_ev.ptype  = ipath_hdrget_rcv_type(rhf);
	rcv_ev.rhf    = rhf;
	rcv_ev.rcv_hdr= rcv_hdr;
	rcv_ev.p_hdr  = recvq->hdrq_rhf_off ? _get_proto_hdr_from_rhf(rcv_hdr, rhf)
				     : _get_proto_hdr(rcv_hdr); 
	rcv_ev.epid   = ips_epid_from_phdr(lmc_mask, rcv_ev.p_hdr);
	rcv_ev.has_cksum = 
	  ((recvq->proto->flags & IPS_PROTO_FLAG_CKSUM) &&
	   (rcv_ev.ptype == RCVHQ_RCV_TYPE_EAGER) &&
	   (rcv_ev.p_hdr->mqhdr != MQ_MSG_DATA_BLK) &&
	   (rcv_ev.p_hdr->mqhdr != MQ_MSG_DATA_REQ_BLK));
	
	if_pt (recvq->proto->flags & IPS_PROTO_FLAG_CCA) {
	  /* IBTA CCA handling:
	   * If FECN bit set handle IBTA CCA protocol. For the flow that 
	   * suffered congestion we flag it to generate a control packet with
	   * the BECN bit set - This is currently an unsolicited ACK. 
	   *
	   * For all MQ packets the FECN processing/BECN generation is done
	   * in the is_expected_or_nak function as each eager packet is
	   * inspected there. 
	   *
	   * For TIDFLOW/Expected data transfers the FECN bit/BECN generation
	   * is done in protoexp_data. Since header suppression can result
	   * in even FECN packets being suppressed the expected protocol
	   * generated addiional BECN packets if a "large" number of generations
	   * are swapped without progress being made for receive. "Large" is
	   * set empirically to 4.
	   *
	   * FECN packets are ignored for all control messages (except ACKs
	   * and NAKs) since they indicate congestion on the control path which
	   * is not rate controlled. The CCA specification allows FECN on
	   * ACKs to be disregarded as well.
	   */
	  rcv_ev.is_congested = 
	  _is_cca_fecn_set(rcv_ev.p_hdr) & IPS_RECV_EVENT_FECN;
	  rcv_ev.is_congested |= 
	    (_is_cca_becn_set(rcv_ev.p_hdr) << (IPS_RECV_EVENT_BECN - 1));
	}
	else
	  rcv_ev.is_congested = 0;

	dest_subcontext  = _get_proto_subcontext(rcv_ev.p_hdr);

	if_pf (_check_headers(&rcv_ev))
	  goto skip_packet;

        if_pf (rcv_ev.error_flags || 
	       (_get_proto_ipath_opcode(rcv_ev.p_hdr) != IPATH_OPCODE_USER1)) 
	{
	  
	  _update_error_stats(recvq->proto, rcv_ev.error_flags);
	  
	  if ((rcv_ev.error_flags & INFINIPATH_RHF_H_TIDERR) || 
	      (rcv_ev.error_flags & INFINIPATH_RHF_H_TFSEQERR) ||
	      (rcv_ev.error_flags & INFINIPATH_RHF_H_TFGENERR)) {
		/* Subcontexts need to see expected tid errors */
		if (rcv_ev.ptype == RCVHQ_RCV_TYPE_EXPECTED &&
		    dest_subcontext != recvq->subcontext)
			goto subcontext_packet;

		recvq->recvq_callbacks.callback_error(&rcv_ev);

		if (rcv_ev.ptype == RCVHQ_RCV_TYPE_EAGER) {
		    /* tiderr and eager, don't consider updating egr head */
		    if (state->hdr_countdown == 0 &&
				state->rcv_egr_index_head == NO_EAGER_UPDATE) {
			/* eager-full is not currently under tracing. */
			uint32_t egr_cnt = recvq->egrq.elemcnt;
			const uint32_t etail = ips_recvq_tail_get(&recvq->egrq);
			const uint32_t ehead = ips_recvq_head_get(&recvq->egrq);

			if (ehead == ((etail+1)%egr_cnt)) {
			    /* eager is full, trace existing header entries */
			    uint32_t hdr_size = recvq->hdrq_elemlast + hdrq_elemsz;
			    const uint32_t htail = ips_recvq_tail_get(&recvq->hdrq);
			    const uint32_t hhead = state->hdrq_head;

			    state->hdr_countdown = (htail > hhead) ?
				(htail - hhead) : (htail + hdr_size - hhead);
			}
		    }
		    goto skip_packet_no_egr_update;
		}
	    }
	    else
		recvq->recvq_callbacks.callback_error(&rcv_ev);
	    goto skip_packet;
        }

	/* If checksum is enabled, verify that it is valid */
	if_pf (rcv_ev.has_cksum && !do_pkt_cksum(&rcv_ev))
	  goto skip_packet;
	
	if (dest_subcontext == recvq->subcontext) {
	    /* Classify packet from a known or unknown endpoint */
	    struct ips_epstate_entry *epstaddr;

      epstaddr =
        ips_epstate_lookup(recvq->epstate, rcv_ev.p_hdr->commidx +
            INFINIPATH_KPF_RESERVED_BITS(rcv_ev.p_hdr->iph.pkt_flags));
	    if_pf (epstaddr == NULL || epstaddr->epid != rcv_ev.epid) {
	        rcv_ev.ipsaddr = NULL;
		recvq->recvq_callbacks.callback_packet_unknown(&rcv_ev);
	    }
	    else {   
	        rcv_ev.ipsaddr = epstaddr->ipsaddr;
		ret = ips_proto_process_packet(&rcv_ev);
		if (ret == IPS_RECVHDRQ_OOO) return PSM_OK_NO_PROGRESS;
	    }
	}
	else {
subcontext_packet:
	    /* If the destination is not our subcontext, process message
	     * as a subcontext message (shared contexts) */
	    rcv_ev.ipsaddr = NULL;

	    ret = recvq->recvq_callbacks.callback_subcontext(&rcv_ev,
							     dest_subcontext);
	}

skip_packet:
	/* 
	 * important to update rcv_egr_index_head iff
	 * 1. Packet was of type eager
	 * 2. Packet actually consumed an eagerbuf (post QLE72XX)
	 * 3. Packet was *not* an eager header with RHF_H_TIDERR to mark
	 *    an eager overflow
	 */
	if (has_optional_eagerbuf ? ipath_hdrget_use_egr_buf(rhf)
			          : (rcv_ev.ptype == RCVHQ_RCV_TYPE_EAGER)) {
	    state->rcv_egr_index_head = ipath_hdrget_index(rhf);
	    /* a header entry is using an eager entry, stop tracing. */
	    state->hdr_countdown = 0;
	}

skip_packet_no_egr_update:
        /* Note that state->hdrq_head is sampled speculatively by the code
         * in ips_ptl_shared_poll() when context sharing, so it is not safe
         * for this shared variable to temporarily exceed the last element. */
        tmp_hdrq_head = state->hdrq_head + hdrq_elemsz;
	if_pt (tmp_hdrq_head <= recvq->hdrq_elemlast)
          state->hdrq_head = tmp_hdrq_head;
        else
	  state->hdrq_head = 0;
	
	if_pf (has_no_rtail && ++recvq->state->hdrq_rhf_seq > LAST_RHF_SEQNO)
	  recvq->state->hdrq_rhf_seq = 1;
	
	state->num_hdrq_done++;
	num_hdrq_done++;
	rcv_hdr = (const uint32_t *) recvq->hdrq.base_addr + state->hdrq_head;
	done = (!next_hdrq_is_ready() || (ret == IPS_RECVHDRQ_BREAK) ||
	        (num_hdrq_done == num_hdrq_todo));

	do_hdr_update = (state->head_update_interval ?
			 (state->num_hdrq_done == state->head_update_interval) : done);
	if (do_hdr_update) {
	    ips_recvq_head_update(&recvq->hdrq, state->hdrq_head);

	    /* Lazy update of egrq */
	    if (state->rcv_egr_index_head != NO_EAGER_UPDATE) {
	      ips_recvq_head_update(&recvq->egrq, state->rcv_egr_index_head);
	      state->rcv_egr_index_head = NO_EAGER_UPDATE;
	    }

	    /* Process any pending acks while updated eager/headq queue */
	    process_pending_acks(recvq);

	    /* Reset header queue entries processed */
	    state->num_hdrq_done = 0;
	}

	if (state->hdr_countdown > 0) {
	    /* a header entry is consumed. */
	    state->hdr_countdown -= hdrq_elemsz;
	    if (state->hdr_countdown == 0) {
		/* header entry count reaches zero. */
		const uint32_t tail = ips_recvq_tail_get(&recvq->egrq);
		const uint32_t head = ips_recvq_head_get(&recvq->egrq);
		uint32_t egr_cnt = recvq->egrq.elemcnt;

		/* Checks eager-full again. This is a real false-egr-full */
		if (head == ((tail+1)%egr_cnt)) {
		    ips_recvq_head_update(&recvq->egrq, tail);
		    _IPATH_DBG("eager array full after overflow, flushing "
				"(head %llx, tail %llx)\n",
				(long long)head, (long long)tail);
		    recvq->proto->stats.egr_overflow++;
		} else
		    _IPATH_ERROR("PSM BUG: EgrOverflow: eager queue is not full\n");
	    }
	}
    }
    /* while (hdrq_entries_to_read) */

    /* Process any pending acks before exiting */
    process_pending_acks(recvq);
    
    return num_hdrq_done ? PSM_OK : PSM_OK_NO_PROGRESS;
}

#if IPS_RCVHDRQ_THRU_FUNCTION_POINTER
/*
 * QLE71XX
 */
static
psm_error_t __recvpath
ips_recvhdrq_progress_none(struct ips_recvhdrq *recvq)
{
    const int has_no_rtail = 0;
    return ips_recvhdrq_progress_inner(recvq, has_no_rtail);
}

/* 
 * QLE72XX+ 
 */
static
psm_error_t __recvpath
ips_recvhdrq_progress_nortail(struct ips_recvhdrq *recvq)
{
    const int has_no_rtail = 1;
    return ips_recvhdrq_progress_inner(recvq, has_no_rtail);
}

psm_error_t __recvpath
ips_recvhdrq_progress(struct ips_recvhdrq *recvq)
{
  /* Call the progress function with the right chip features. */
  return recvq->progress_fn(recvq);
}
#endif
