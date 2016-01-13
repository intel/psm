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
#include "psm_am.h"
#include "psm_am_internal.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

#define IPS_AMFLAG_ISTINY 1

struct ips_am_token { 
    struct psmi_am_token    tok;
  
    /* ptl-specific token stuff */
    struct ips_proto_am *proto_am;
};

psm_error_t
ips_proto_am_init(struct ips_proto *proto,
		  int num_of_send_bufs, int num_of_send_desc,
		  uint32_t imm_size, struct ips_proto_am *proto_am)
{
    psm_error_t err = PSM_OK;
    int send_buf_size = proto->scb_bufsize;

    proto_am->proto = proto;
    proto_am->scbc_request = &proto->scbc_egr;

    if ((err = ips_scbctrl_init(&proto->ep->context, num_of_send_desc,
				num_of_send_bufs, imm_size, send_buf_size,
				NULL, NULL, &proto_am->scbc_reply)))
	goto fail;
fail:
    return err;
}

psm_error_t
ips_proto_am_fini(struct ips_proto_am *proto_am)
{
    return PSM_OK;
}

static
psm_error_t
am_short_reqrep(struct ips_proto_am *proto_am, ips_scb_t *scb,
		struct ptl_epaddr *ipsaddr,
		psm_amarg_t *args, int nargs, uint8_t sub_opcode,
		void *src, size_t len, int flags, int pad_bytes)
		    
{
    int i, hdr_qwords = PSM_AM_HDR_QWORDS;
    ptl_epaddr_flow_t flowid = ((sub_opcode == OPCODE_AM_REQUEST) || 
				(sub_opcode == OPCODE_AM_REQUEST_NOREPLY)) ?
      EP_FLOW_GO_BACK_N_AM_REQ : EP_FLOW_GO_BACK_N_AM_RSP;
    struct ips_flow *flow = &ipsaddr->flows[flowid];

    _IPATH_VDBG("%s src=%p len=%d, nargs=%d\n", 
		((sub_opcode == OPCODE_AM_REQUEST) ||
		 (sub_opcode == OPCODE_AM_REQUEST_NOREPLY)) ? "req" : "rep",
		src, (int) len, nargs); 

    if (nargs == 1) {	/* fastpath */
	scb->ips_lrh.data[0].u64w0 = args[0].u64w0;
	hdr_qwords--;
    }
    else if (nargs > 1) {
	/* Easily unrollable but leave as is in case we can increase qwords
	 * on the chip in the near future */
	for (i = 0; i < PSM_AM_HDR_QWORDS; i++, hdr_qwords--)
	    scb->ips_lrh.data[i].u64w0 = args[i].u64w0;

	if (nargs > PSM_AM_HDR_QWORDS) {
	    /* Slow case -- we don't have iovec and not enough space in the
	     * message header, so we have to copy the user's arguments even if
	     * the payload is marked ASYNC */
	    uintptr_t bufp = (uintptr_t) scb->payload;
	    psmi_mq_mtucpy((void *) bufp, &args[PSM_AM_HDR_QWORDS], 
		   sizeof(psm_amarg_t) * (nargs - PSM_AM_HDR_QWORDS));
	    bufp += sizeof(psm_amarg_t) * (nargs - PSM_AM_HDR_QWORDS);
	    scb->payload_size = sizeof(psm_amarg_t) * (nargs-PSM_AM_HDR_QWORDS);
	    if (src != NULL && len > 0) {
		psmi_mq_mtucpy((void *) bufp, src, len);
		scb->payload_size += len;
	    }
	    scb->payload_size += pad_bytes;
	    scb->ips_lrh.hdr_dlen = pad_bytes;
	    goto send_scb;
	}
    }

    /*
     * If small enough, try to stuff the message in a header only
     */
    if (len <= (hdr_qwords<<3)) { /* can handle len == 0 */
	psmi_mq_mtucpy(&scb->ips_lrh.data[PSM_AM_HDR_QWORDS-hdr_qwords], src, len);
	scb->payload_size = 0;
	scb->ips_lrh.hdr_dlen = len;
	scb->ips_lrh.amhdr_flags |=  IPS_AMFLAG_ISTINY;
    }
    else { /* Whatever's left requires a separate payload */
	if (scb->payload == NULL) {    /* Just attach the buffer */
	    scb->payload = src;
	}
	else { /* May need to re-xmit user data, keep it around */
	  psmi_mq_mtucpy(scb->payload, src, len);
	}
	scb->payload_size = len + pad_bytes;
	scb->ips_lrh.hdr_dlen = pad_bytes;
    }

send_scb:
    scb->ips_lrh.sub_opcode = sub_opcode;
    flow->fn.xfer.enqueue(flow, scb);
    flow->fn.xfer.flush(flow, NULL);
    return PSM_OK;
}

static inline int 
calculate_pad_bytes (struct ips_proto_am *proto_am, int nargs, size_t len)
{
  if ((nargs <= PSM_AM_HDR_QWORDS) && 
      (len <= ((PSM_AM_HDR_QWORDS - nargs) << 3)))
    return 0;
  else {
    size_t arg_overflow = (nargs > PSM_AM_HDR_QWORDS) ?
      (sizeof(psm_amarg_t) * (nargs - PSM_AM_HDR_QWORDS)) : 0;
    size_t cache_aligned_len = (len + arg_overflow + PSM_CACHE_LINE_BYTES-1) & 
      ~(PSM_CACHE_LINE_BYTES - 1);
    if (cache_aligned_len <= proto_am->proto->scb_bufsize)
      return cache_aligned_len - (len + arg_overflow);
    else
      return 0;
  }
}

static inline
void
ips_am_scb_init(ips_scb_t *scb, uint8_t handler, int nargs, 
		int pad_bytes,
		psm_am_completion_fn_t completion_fn,
		void *completion_ctxt)
{
    scb->completion_am = completion_fn;
    scb->cb_param = completion_ctxt;
    scb->ips_lrh.amhdr_hidx = handler;
    scb->ips_lrh.hdr_dlen = pad_bytes;
    scb->ips_lrh.amhdr_nargs = nargs;
    scb->ips_lrh.amhdr_flags = 0;
    if (completion_fn)
      scb->flags |= IPS_SEND_FLAG_ACK_REQ;
    return;
}

psm_error_t
ips_am_short_request(psm_epaddr_t epaddr, 
                     psm_handler_t handler, psm_amarg_t *args, int nargs,
		     void *src, size_t len, int flags, 
		     psm_am_completion_fn_t completion_fn, 
		     void *completion_ctxt)
{
    struct ips_proto_am *proto_am = &epaddr->ptl->proto.proto_am;
    psm_error_t err;
    ips_scb_t *scb;
    int pad_bytes = calculate_pad_bytes(proto_am, nargs, len);
    int payload_sz = (nargs << 3) + pad_bytes;
    
    if_pt (!(flags & PSM_AM_FLAG_ASYNC))
      payload_sz += len;
    
    if (payload_sz > (PSM_AM_HDR_QWORDS << 3)) {
      /* Payload can't fit in header - allocate buffer to carry data */
      int arg_sz = (nargs > PSM_AM_HDR_QWORDS) ? 
	((nargs - PSM_AM_HDR_QWORDS) << 3) : 0;
      
      /* len + pad_bytes + overflow_args */
      PSMI_BLOCKUNTIL(epaddr->ep,err,
	((scb = ips_scbctrl_alloc(proto_am->scbc_request, 1, 
				  len + pad_bytes + arg_sz,
				  IPS_SCB_FLAG_ADD_BUFFER)) != NULL));
    }
    else {
      PSMI_BLOCKUNTIL(epaddr->ep,err,
	   ((scb = ips_scbctrl_alloc_tiny(proto_am->scbc_request)) != NULL));
    }

    psmi_assert_always(scb != NULL);
    ips_am_scb_init(scb, handler, nargs, pad_bytes,
		    completion_fn, completion_ctxt);

    return am_short_reqrep(proto_am, scb, epaddr->ptladdr, args, nargs, 
			   (flags & PSM_AM_FLAG_NOREPLY) ?
			   OPCODE_AM_REQUEST_NOREPLY : OPCODE_AM_REQUEST, 
			   src, len, flags, pad_bytes);
}

psm_error_t
ips_am_short_reply(psm_am_token_t tok,
                   psm_handler_t handler, psm_amarg_t *args, int nargs,
		   void *src, size_t len, int flags, 
		   psm_am_completion_fn_t completion_fn, 
		   void *completion_ctxt)
{
    ips_scb_t *scb;
    struct ips_am_token *token = (struct ips_am_token *) tok;
    struct ips_proto_am *proto_am = token->proto_am;
    struct ptl_epaddr *ipsaddr = token->tok.epaddr_from->ptladdr;
    int scb_flags = 0;
    int pad_bytes = calculate_pad_bytes(proto_am, nargs, len);
    
    if (!token->tok.can_reply) {
      /* Trying to reply for an AM request that did not expect a reply */
      _IPATH_ERROR("Invalid AM reply for request!");
      return PSM_AM_INVALID_REPLY;
    }
    
    psmi_assert_always(ips_scbctrl_avail(&proto_am->scbc_reply));

    if ((nargs<<3) + len <= (PSM_AM_HDR_QWORDS<<3)) {
      psmi_assert_always(pad_bytes == 0);
      scb = ips_scbctrl_alloc_tiny(&proto_am->scbc_reply);
    }
    else {
      int payload_sz = (nargs << 3) + pad_bytes;
      
      payload_sz += (flags & PSM_AM_FLAG_ASYNC) ? 0 : len;
      scb_flags |= (payload_sz > (PSM_AM_HDR_QWORDS << 3)) ? 
	IPS_SCB_FLAG_ADD_BUFFER : 0;
      
      scb = ips_scbctrl_alloc(&proto_am->scbc_reply, 1, payload_sz, scb_flags);
    }
    
    psmi_assert_always(scb != NULL);
    ips_am_scb_init(scb, handler, nargs, pad_bytes,
		    completion_fn, completion_ctxt);
    am_short_reqrep(proto_am, scb, ipsaddr, args, nargs, OPCODE_AM_REPLY,
		    src, len, flags, pad_bytes);
    return PSM_OK;
}

/* Prepares and runs a handler from a receive event. */
static int
ips_am_run_handler(struct ips_am_token *tok,
		   const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    struct ips_proto_am *proto_am = &rcv_ev->proto->proto_am;
    psm_am_handler_fn_t hfn;

    int nargs = p_hdr->amhdr_nargs;
    tok->tok.flags = p_hdr->amhdr_flags;
    tok->tok.epaddr_from = rcv_ev->ipsaddr->epaddr;
    tok->tok.can_reply = (p_hdr->sub_opcode == OPCODE_AM_REQUEST);
    tok->proto_am = proto_am;

    hfn = psm_am_get_handler_function(rcv_ev->proto->ep, 
				      p_hdr->amhdr_hidx);
    _IPATH_VDBG("amhdr_len=%d, amhdr_flags=%x, amhdr_nargs=%d, p_hdr=%p\n",
	p_hdr->hdr_dlen, p_hdr->amhdr_flags, p_hdr->amhdr_nargs, p_hdr);

    /* Fast path: everything fits only in a header */
    if (tok->tok.flags & IPS_AMFLAG_ISTINY) {
        return hfn(tok, tok->tok.epaddr_from,
		   (psm_amarg_t *) &p_hdr->data[0].u64, nargs,
		   &p_hdr->data[nargs].u64, p_hdr->hdr_dlen);
    }
    else {
	/* Arguments and payload may split across header/eager_payload
	 * boundaries. */
	psm_amarg_t args[8] = {};
	int i;
	uint64_t *payload = (uint64_t *) ips_recvhdrq_event_payload(rcv_ev);
	uint32_t paylen = ips_recvhdrq_event_paylen(rcv_ev);
	for (i = 0; i < nargs; i++) {
	    if (i < PSM_AM_HDR_QWORDS)
		args[i].u64 = p_hdr->data[i].u64;
	    else {
		args[i].u64 = *payload++;
		paylen -= 8;
	    }
	}
	
	paylen -= p_hdr->hdr_dlen;
	return hfn(tok, tok->tok.epaddr_from, args, nargs, payload, paylen);
    }
}

int
ips_proto_am(struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_am_token token;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    struct ptl_epaddr *ipsaddr = rcv_ev->ipsaddr;
    struct ips_proto_am *proto_am = &rcv_ev->proto->proto_am;
    ptl_epaddr_flow_t flowid = ips_proto_flowid(p_hdr);
    struct ips_flow *flow = &ipsaddr->flows[flowid];
    int ret = IPS_RECVHDRQ_CONTINUE;
    
/*
 * Based on AM request/reply traffic pattern, if we don't have
 * a reply scb slot then we can't process the request packet,
 * we just silently drop it. Otherwise, it will be a deadlock.
 * note: ips_proto_is_expected_or_nak() can not be called in this case.
 */
    if (p_hdr->sub_opcode == OPCODE_AM_REQUEST &&
		!ips_scbctrl_avail(&proto_am->scbc_reply)) {
	proto_am->amreply_nobufs++;
	return ret;
    }

    if (ips_proto_is_expected_or_nak((struct ips_recvhdrq_event*) rcv_ev)) {
	/* run handler */
	if (ips_am_run_handler(&token, rcv_ev))
	    ret = IPS_RECVHDRQ_BREAK;

	/* Look if the handler replied, if it didn't, ack the request */    
	if ((p_hdr->flags & IPS_SEND_FLAG_ACK_REQ)  ||
			(flow->flags & IPS_FLOW_FLAG_GEN_BECN))
	    ips_proto_send_ack((struct ips_recvhdrq *) rcv_ev->recvq, flow);
    }

    ips_proto_process_ack(rcv_ev);
    return ret;
}
