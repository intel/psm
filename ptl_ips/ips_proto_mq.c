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

#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

#define MQ_NUM_MTUS(size,mtu)	(((size) + (mtu) - 1) / (mtu))
#define MQ_EGRLONG_ENABLE_MULTIFLOW 0

PSMI_NEVER_INLINE(
ips_scb_t * __sendpath
ips_poll_scb(struct ips_proto *proto,
	     int npkts, int len, uint32_t flags, int istiny))
{
    ips_scb_t *scb = NULL;
    psmi_assert(npkts > 0);
    psm_error_t err;

    proto->stats.scb_egr_unavail_cnt++;

    PSMI_BLOCKUNTIL(proto->ep,err,
	((scb = istiny ? 
	  ips_scbctrl_alloc_tiny(&proto->scbc_egr) :
	  ips_scbctrl_alloc(&proto->scbc_egr, npkts, len, flags)) != NULL));
    return scb;
}

PSMI_ALWAYS_INLINE(
ips_scb_t * 
mq_alloc_tiny(struct ips_proto *proto))
{
    ips_scb_t* scb = ips_scbctrl_alloc_tiny(&proto->scbc_egr);
    // common case should branch right through
    if_pt (scb != NULL) 
        return scb;
    else 
       return ips_poll_scb(proto, 1, 0, 0, 1);
}

PSMI_ALWAYS_INLINE(
ips_scb_t * 
mq_alloc_pkts(struct ips_proto *proto, int npkts, int len, uint32_t flags))
{
    psmi_assert(npkts > 0);
    ips_scb_t* scb = ips_scbctrl_alloc(&proto->scbc_egr, npkts, len, flags);
    if_pt (scb != NULL) {
        return scb;
    }
    else {
        return ips_poll_scb(proto, npkts, len, flags, 0 /* not tiny scb */);
    }
}

static
int __recvpath
ips_proto_mq_eager_complete(void *reqp)
{
    psm_mq_req_t req = (psm_mq_req_t)reqp;
    
    req->state = MQ_STATE_COMPLETE;
    mq_qq_append(&req->mq->completed_q, req);
    return IPS_RECVHDRQ_CONTINUE;
}

static
int __recvpath
ips_proto_mq_rv_complete(void *reqp)
{
    psm_mq_req_t req = (psm_mq_req_t) reqp;
    psmi_mq_handle_rts_complete(req);

    return IPS_RECVHDRQ_CONTINUE;
}

static
void __recvpath
ips_proto_mq_rv_complete_exp(void *reqp)
{
    ips_proto_mq_rv_complete(reqp);
    return;
}

extern psm_error_t ips_ptl_poll(ptl_t *ptl, int _ignored);

/*
 * Mechanism to capture PIO-ing or DMA-ing the MQ message envelope
 *
 * Recoverable errors:
 * PSM_OK: If PIO, envelope is sent. 
 *	   If DMA, all queued up packets on flow were flushed.
 *
 * Recoverable errors converted to PSM_OK just before return:
 * PSM_OK_NO_PROGRESS: DMA-only, flushed 1 but not all queued packets.
 * PSM_EP_NO_RESOURCES:
 *	   If PIO, no pio available or cable currently pulled.
 *	   If DMA, can be that no scb's available to handle unaligned packets
 *	           or writev returned a recoverable error (no mem for
 *	           descriptors, dma interrupted or no space left in dma queue).
 *
 * Unrecoverable errors (PIO or DMA).
 * PSM_EP_DEVICE_FAILURE: Unexpected error calling writev(), chip failure,
 *			  rxe/txe parity error.
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 */
PSMI_ALWAYS_INLINE(
psm_error_t
ips_mq_send_envelope(ptl_t *ptl, struct ips_proto *proto, 
		     ips_epaddr_t *ipsaddr, struct ips_scb *scb, int do_flush))
{
    psm_error_t err = PSM_OK;
    struct ips_flow *flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
    
    if_pf (proto->flags & IPS_PROTO_FLAG_MQ_ENVELOPE_SDMA) {
      flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
      
      if_pt (ips_scb_length(scb)) /* For DMA envelope need local completion */
    	ips_scb_flags(scb) |= IPS_SEND_FLAG_WAIT_SDMA;
    }
    
    flow->fn.xfer.enqueue(flow, scb);

    if ((flow->transfer == PSM_TRANSFER_PIO) ||
	(flow->transfer == PSM_TRANSFER_DMA && do_flush))
      err = flow->fn.xfer.flush(flow, NULL);
   
    if (do_flush)
	err = ips_recv_progress_if_busy(ptl, err);

    /* As per the PSM error model (or lack thereof), PSM clients expect to see
     * only PSM_OK as a recoverable error */
    if (err == PSM_EP_NO_RESOURCES || err == PSM_OK_NO_PROGRESS)
	err = PSM_OK;
    return err;
}

void __sendpath
ips_mq_send_payload(ptl_t *ptl, ips_epaddr_t *ipsaddr, psmi_egrid_t egrid,
		    void *ubuf, uint32_t len, psm_mq_req_t req,
		    uint32_t flags)
{
    psm_error_t err;

    ips_scb_t *scb;
    uintptr_t buf = (uintptr_t) ubuf;
    uintptr_t pagesz = PSMI_PAGESIZE;
    uint32_t nbytes_left = len;
    uint32_t pktlen;
    struct ips_proto *proto = ipsaddr->proto;
    int is_blocking = !!(req == NULL);
    ptl_epaddr_flow_t flowid = 
      (flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA) ?
      EP_FLOW_GO_BACK_N_DMA : EP_FLOW_GO_BACK_N_PIO;
    struct ips_flow *flow = &ipsaddr->flows[flowid];
    uint16_t frag_size = flow->frag_size;

    psmi_assert(len > 0);
    
    do {
	scb = mq_alloc_pkts(proto, MQ_NUM_MTUS(nbytes_left, frag_size),
			    nbytes_left, 
			    is_blocking ? IPS_SCB_FLAG_ADD_BUFFER : 0);
	ips_scb_t *curscb = scb;

	do {
	    pktlen = min(frag_size, nbytes_left);
	    /* If DMA, make sure we don't cross page boundaries */
	    if (flow->transfer == PSM_TRANSFER_DMA && !is_blocking)
	      pktlen = min(pktlen, pagesz - (buf & (pagesz-1)));
	    ips_scb_length(curscb) = pktlen;
	    ips_scb_mqhdr(curscb) = MQ_MSG_DATA;
	    ips_scb_mqparam(curscb).u32w0 = egrid.egr_data;
	    ips_scb_subopcode(curscb) = OPCODE_SEQ_MQ_CTRL;
	    ips_scb_epaddr(curscb) = ipsaddr;
	    nbytes_left -= pktlen;

	    _IPATH_VDBG("payload=%p, thislen=%d, frag_size=%d, nbytes_left=%d\n",
		(void *) buf, pktlen, frag_size, nbytes_left);

	    if (!is_blocking) /* non-blocking, send from user's buffer */
		ips_scb_buffer(curscb) = (void *) buf;
	    else /* blocking, copy to bounce buffer */
		psmi_mq_mtucpy(ips_scb_buffer(curscb), (void *) buf, pktlen);

	    /* Make sure we don't cross page boundaries with DMA. */
	    if (flow->transfer == PSM_TRANSFER_DMA)
		psmi_assert(
		    PSMI_ALIGNDOWN(ips_scb_buffer(curscb), PSMI_PAGESIZE) ==
		    PSMI_ALIGNDOWN(ips_scb_buffer(curscb)+pktlen-1, PSMI_PAGESIZE));

	    if (nbytes_left == 0) { /* last packet */
		if (!is_blocking) {
		    /* non-blocking mode, need completion */
		    ips_scb_cb(curscb) = ips_proto_mq_eager_complete;
		    ips_scb_cb_param(curscb) = req;
		}
		ips_scb_flags(curscb) |= IPS_SEND_FLAG_ACK_REQ;
	    }
	    buf += pktlen;
	    scb = curscb;
	    curscb = SLIST_NEXT(curscb, next);

	    flow->fn.xfer.enqueue(flow, scb);

	    if (flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA) 
	      ips_scb_flags(scb) |= IPS_SEND_FLAG_WAIT_SDMA;

	    /* if not sdma, or sdma but running out of scb,
	     * we need to flush the pending queue */
	    if (!(flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA) ||
	    !ips_scbctrl_avail(scb->scbc)) {
	        err = flow->fn.xfer.flush(flow, NULL);
	        err = ips_recv_progress_if_busy(ipsaddr->ptl, err);
	    }
	} while (curscb != NULL);

	if (flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA) {
	    err = flow->fn.xfer.flush(flow, NULL);
	    if (err == PSM_EP_NO_RESOURCES || err == PSM_OK_NO_PROGRESS) 
		err = ips_recv_progress_if_busy(ptl, PSM_EP_NO_RESOURCES);
	}
    }
    while (nbytes_left);

    return;
}


PSMI_ALWAYS_INLINE(
void
ips_shortcpy(void* vdest, const void* vsrc, uint32_t nchars)
)
{
    unsigned char *dest = vdest;
    const unsigned char *src = vsrc;

    if(nchars>>2)
        ipath_dwordcpy((uint32_t*)dest, (uint32_t*)src, nchars>>2);
    dest += (nchars>>2)<<2;
    src += (nchars>>2)<<2;
    switch (nchars&0x03) {
        case 3: *dest++ = *src++;
        case 2: *dest++ = *src++;
        case 1: *dest++ = *src++;
    }
    return;
}

static __sendpath
psm_error_t
ips_ptl_mq_rndv(ptl_t *ptl, psm_mq_req_t req, ips_epaddr_t *ipsaddr, 
		const void *buf, uint32_t len)
{
    ips_scb_t *scb;
    psm_error_t err = PSM_OK;
    struct ips_proto *proto = ipsaddr->proto;

    req->buf = (void *) buf;
    req->buf_len = len;
    req->send_msglen = len;
    req->send_msgoff = 0;
    req->recv_msgoff = 0;
    req->rts_peer = ipsaddr->epaddr;
        
    scb = mq_alloc_tiny(proto);

    /* If the expected tid protocol is active, use it or else resort to
     * eager-based r-v. */
    if (proto->protoexp != NULL)
	ips_scb_mqhdr(scb) = req->type & MQE_TYPE_WAITING ? 
			     MQ_MSG_RTS_WAIT : MQ_MSG_RTS;
    else
	ips_scb_mqhdr(scb) = MQ_MSG_RTS_EGR;

    ips_scb_epaddr(scb) = ipsaddr;
    ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
    ips_scb_flags(scb) |= IPS_SEND_FLAG_ACK_REQ;
    
    ips_scb_uwords(scb)[0].u64   = req->tag;
    ips_scb_uwords(scb)[1].u32w0 = psmi_mpool_get_obj_index(req);
    ips_scb_uwords(scb)[1].u32w1 = len;

    if ((err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_TRUE)))
	goto fail;
	    
    /* Assume that we already put a few rndv requests in flight.  This helps
     * for bibw microbenchmarks and doesn't hurt the 'blocking' case since
     * we're going to poll anyway */
    psmi_poll_internal(req->mq->ep, 1);

fail:
    _IPATH_VDBG("[rndv][%s->%s][b=%p][m=%d][t=%"PRIx64"][req=%p/%d]: %s\n", 
	psmi_epaddr_get_name(proto->ep->epid),
	psmi_epaddr_get_name(ipsaddr->epaddr->epid), buf, len, req->tag, req, 
	psmi_mpool_get_obj_index(req),
	psm_error_get_string(err));

    return err; 
}

psm_error_t __sendpath
ips_proto_mq_isend(ptl_t *ptl, psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	     uint64_t tag, const void *ubuf, uint32_t len, void *context,
	     psm_mq_req_t *req_o)
{
    uint8_t *buf = (uint8_t *) ubuf;
    uint32_t pktlen = 0;
    ips_scb_t *scb;
    ips_epaddr_t *ipsaddr = epaddr->ptladdr;
    struct ips_proto *proto = ipsaddr->proto;
    uint32_t pad_write_bytes;
    psm_error_t err = PSM_OK;
    psm_mq_req_t req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
    if_pf (req == NULL)
	return PSM_NO_MEMORY;

    req->send_msglen = len;
    req->tag = tag;
    req->context = context;

    if (!flags && len <= MQ_IPATH_THRESH_TINY) {
	scb = mq_alloc_tiny(proto);
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_HDR;
	ips_scb_hdr_dlen(scb) = len;
	ips_scb_mqhdr(scb) = MQ_MSG_TINY;
	ips_scb_mqtag(scb) = tag;
	mq_copy_tiny((uint32_t *)&ips_scb_mqparam(scb), (uint32_t *)buf, len);
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_TRUE);
	/* We can mark this op complete since all the data is now copied
	 * into an SCB that remains live until it is remotely acked */
	req->state = MQ_STATE_COMPLETE;
	mq_qq_append(&mq->completed_q, req);
        _IPATH_VDBG("[itiny][%s->%s][b=%p][m=%d][t=%"PRIx64"][req=%p]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, len, tag, req);
	*req_o = req;
	mq->stats.tx_num++;
	mq->stats.tx_eager_num++;
	mq->stats.tx_eager_bytes += len;
	return err;
    }
    else if (flags & PSM_MQ_FLAG_SENDSYNC) {/* skip eager accounting below */
	err = ips_ptl_mq_rndv(ptl, req, ipsaddr, ubuf, len);
	*req_o = req;
	return err;
    }
    else if (len <= ipsaddr->epr.epr_piosize) {
        uint32_t cksum_len = (proto->flags & IPS_PROTO_FLAG_CKSUM) ? 
	  PSM_CRC_SIZE_IN_BYTES : 0;
	
	pad_write_bytes = ((PSM_CACHE_LINE_BYTES - 
			    ((len + cksum_len) & (PSM_CACHE_LINE_BYTES-1))) & 
			   (PSM_CACHE_LINE_BYTES-1));
	
        if_pf ((pad_write_bytes + len) > ipsaddr->epr.epr_piosize)
	  pad_write_bytes = 0;
	scb = mq_alloc_pkts(proto, 1, (len + pad_write_bytes),
			    IPS_SCB_FLAG_ADD_BUFFER);
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
	ips_scb_hdr_dlen(scb) = pad_write_bytes;
	ips_scb_length(scb) = len + pad_write_bytes;
	ips_scb_mqhdr(scb) = MQ_MSG_SHORT;
	ips_scb_mqtag(scb) = tag;
	ips_shortcpy (ips_scb_buffer(scb), buf, len);
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_TRUE);
	req->state = MQ_STATE_COMPLETE;
	mq_qq_append(&mq->completed_q, req);
        _IPATH_VDBG("[ishrt][%s->%s][b=%p][m=%d][t=%"PRIx64"][req=%p]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, len, tag, req);
    }
    else if (len <= mq->ipath_thresh_rv) {
	uint32_t proto_flags = proto->flags & IPS_PROTO_FLAG_MQ_MASK;
	struct ips_flow *flow;
	psmi_egrid_t egrid;

	req->buf = (uint8_t *) buf;
	req->buf_len = len;
	scb = mq_alloc_pkts(proto, 1, 0, 0);

	if (len < proto->iovec_thresh_eager) {
	    if (len <= 2 * ipsaddr->epr.epr_piosize) {
		// split into 2 packets and round second down to dword multiple
		pktlen = len - (((len >> 1) + 3) & ~0x3);
	    }
	    else {
	        pktlen = min(len, ipsaddr->epr.epr_piosize);
	    }
	    proto_flags &= ~IPS_PROTO_FLAG_MQ_EAGER_SDMA;
	}
	else {
	  psmi_assert(proto_flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA);
	  pktlen = PSMI_PAGESIZE - ((uintptr_t) buf & (PSMI_PAGESIZE-1));
	  if (pktlen > ipsaddr->epr.epr_piosize)
	    pktlen = 0;
	}
	psmi_assert(pktlen <= ipsaddr->epr.epr_piosize);
	
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
	ips_scb_length(scb) = pktlen;
	ips_scb_mqhdr(scb) = MQ_MSG_LONG;
	ips_scb_mqtag(scb) = tag;
	ips_scb_mqparam(scb).u32w0 = len;

	/* In non-blocking mode, directly send from user's buffer */
	ips_scb_buffer(scb) = buf;
	
	if (proto_flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA)
	    flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
	else {
	    /* mask off eager dma cause if it's enabled, we're not using it
	     * because of size cutoff */
	    proto_flags &= ~IPS_PROTO_FLAG_MQ_EAGER_SDMA;
	    flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
	}

       /* We need a new eager long message number */
	egrid.egr_data = ips_scb_mqparam(scb).u32w1 = 
		flow->xmit_egrlong.egr_data;
	flow->xmit_egrlong.egr_msgno++;

	/* Send the envelope but don't flush if writev is enabled */
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_FALSE);
	ips_mq_send_payload(ptl, ipsaddr, egrid, 
			    buf+pktlen, len-pktlen, req, 
			    proto_flags);

        _IPATH_VDBG("[ilong][%s->%s][b=%p][l=%d][m=%d][t=%"PRIx64"][req=%p]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, pktlen, len, tag, req);
    }
    else { /* skip eager accounting below */
	err = ips_ptl_mq_rndv(ptl, req, ipsaddr, ubuf, len);
	*req_o = req;
	return err;
    }

    *req_o = req;
    mq->stats.tx_num++;
    mq->stats.tx_eager_num++;
    mq->stats.tx_eager_bytes += len;

    return err;
}

__sendpath
psm_error_t
ips_proto_mq_send(ptl_t *ptl, psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	    uint64_t tag, const void *ubuf, uint32_t len)
{
    uint8_t *buf = (uint8_t *) ubuf;
    uint32_t pktlen;
    ips_scb_t *scb;
    ips_epaddr_t *ipsaddr = epaddr->ptladdr;
    uint32_t pad_write_bytes;
    psm_error_t err = PSM_OK;
    struct ips_proto *proto = ipsaddr->proto;
    
    if (flags == 0 && len <= MQ_IPATH_THRESH_TINY) {
	scb = mq_alloc_tiny(proto);
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_HDR;
	ips_scb_hdr_dlen(scb) = len;
	ips_scb_mqhdr(scb) = MQ_MSG_TINY;
	ips_scb_mqtag(scb) = tag;

	mq_copy_tiny((uint32_t *)&ips_scb_mqparam(scb), (uint32_t *)buf, len);
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_TRUE);
	_IPATH_VDBG("[tiny][%s->%s][b=%p][m=%d][t=%"PRIx64"]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, len, tag);
	mq->stats.tx_num++;
	mq->stats.tx_eager_num++;
	mq->stats.tx_eager_bytes += len;
	return err;
    }
    else if ((flags & PSM_MQ_FLAG_SENDSYNC)) {
	goto do_rendezvous;
    }
    else if (len <= ipsaddr->epr.epr_piosize) {
        uint32_t cksum_len = (proto->flags & IPS_PROTO_FLAG_CKSUM) ? 
	  PSM_CRC_SIZE_IN_BYTES : 0;
	
	pad_write_bytes = ((PSM_CACHE_LINE_BYTES - 
			    ((len + cksum_len) & (PSM_CACHE_LINE_BYTES-1))) & 
			   (PSM_CACHE_LINE_BYTES-1));
	
        if_pf ((pad_write_bytes + len) > ipsaddr->epr.epr_piosize)
	  pad_write_bytes = 0;

	scb = mq_alloc_pkts(proto, 1, (len + pad_write_bytes),
			    IPS_SCB_FLAG_ADD_BUFFER);
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
	ips_scb_hdr_dlen(scb) = pad_write_bytes;
	ips_scb_length(scb) = len + pad_write_bytes;
	ips_scb_mqhdr(scb) = MQ_MSG_SHORT;
	ips_scb_mqtag(scb) = tag;
		
	ips_shortcpy (ips_scb_buffer(scb), buf, len);
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_TRUE);
        _IPATH_VDBG("[shrt][%s->%s][b=%p][m=%d][t=%"PRIx64"]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, len, tag);
    }
    else if (len <= mq->ipath_thresh_rv) {
	uint32_t proto_flags = proto->flags & IPS_PROTO_FLAG_MQ_MASK;
	psmi_egrid_t egrid;
	struct ips_flow *flow;

	if (len < proto->iovec_thresh_eager_blocking) {
	    if (len <= 2 * ipsaddr->epr.epr_piosize) {
		// split into 2 packets and round second down to dword multiple
		pktlen = len - (((len >> 1) + 3) & ~0x3);
	    }
	    else {
	        pktlen = min(len, ipsaddr->epr.epr_piosize);
	    }
	    proto_flags &= ~IPS_PROTO_FLAG_MQ_EAGER_SDMA;
	}
	else {
	    psmi_assert(proto_flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA);
	    pktlen = PSMI_PAGESIZE - ((uintptr_t) buf & (PSMI_PAGESIZE-1));
	    if (pktlen > ipsaddr->epr.epr_piosize)
	      pktlen = 0;
	}
	psmi_assert(pktlen <= ipsaddr->epr.epr_piosize);
	
	scb = mq_alloc_pkts(proto, 1, pktlen, IPS_SCB_FLAG_ADD_BUFFER);
		
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
	ips_scb_length(scb) = pktlen;
	ips_scb_mqhdr(scb) = MQ_MSG_LONG;
	ips_scb_mqtag(scb) = tag;
	ips_scb_mqparam(scb).u32w0 = len;
	
	if (proto_flags & IPS_PROTO_FLAG_MQ_EAGER_SDMA) 
	  flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA];
	else {
	    /* mask off eager dma cause if it's enabled, we're not using it
	     * because of size cutoff */
	    proto_flags &= ~IPS_PROTO_FLAG_MQ_EAGER_SDMA;
	    flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
	}

	/* In blocking mode, copy to scb bounce buffer */
	ips_shortcpy (ips_scb_buffer(scb), buf, pktlen);
	
	/* We need a new eager long message number */
	egrid.egr_data = ips_scb_mqparam(scb).u32w1 = 
		flow->xmit_egrlong.egr_data;
	flow->xmit_egrlong.egr_msgno++;

	/* Send the envelope but don't flush if writev is enabled */
	err = ips_mq_send_envelope(ptl, proto, ipsaddr, scb, PSMI_FALSE);
	ips_mq_send_payload(ptl, ipsaddr, egrid, buf+pktlen, len-pktlen, NULL,
			    proto_flags);

        _IPATH_VDBG("[long][%s->%s][b=%p][l=%d][m=%d][t=%"PRIx64"]\n", 
	    psmi_epaddr_get_name(mq->ep->epid), 
	    psmi_epaddr_get_name(epaddr->epid), buf, pktlen, len, tag);
    }
    else {
	psm_mq_req_t req;
do_rendezvous:
	/* Block until we can get a req */
	PSMI_BLOCKUNTIL(mq->ep, err, 
			(req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND)));
	req->type |= MQE_TYPE_WAITING;
	req->tag = tag;
	err = ips_ptl_mq_rndv(ptl, req, ipsaddr, ubuf, len);
	if (err != PSM_OK)
	    return err;
	psmi_mq_wait_internal(&req);
	return err; /* skip accounting, done separately at completion time */
    }

    mq->stats.tx_num++;
    mq->stats.tx_eager_num++;
    mq->stats.tx_eager_bytes += len;

    return err;
}

static
psm_error_t __recvpath
ips_proto_mq_rts_match_callback(psm_mq_req_t req, int was_posted)
{
    psm_epaddr_t epaddr = req->rts_peer;
    ips_epaddr_t *ipsaddr = epaddr->ptladdr;
    struct ips_proto *proto = ipsaddr->proto;

    req->recv_msgoff = 0;
    req->recv_msgposted = 0;
    req->next = NULL;

    /* We have a match.
     *
     * If we're doing eager-based r-v, just send back the sreq and length and
     * have the sender complete the send.
     *
     */
    if (proto->protoexp == NULL) {	/* only eager-based r-v so far */
	struct ips_pend_sends *pends = &proto->pend_sends;
	struct ips_pend_sreq *sreq = psmi_mpool_get(proto->pend_sends_pool);
	psmi_assert(sreq != NULL);
	sreq->type = IPS_PENDSEND_EAGER_REQ;
	sreq->req  = req;

	STAILQ_INSERT_TAIL(&pends->pendq, sreq, next);
	psmi_timer_request(proto->timerq, &pends->timer, PSMI_TIMER_PRIO_1);
    }
    else {
	ips_protoexp_tid_get_from_token(
	    proto->protoexp, req->buf, req->recv_msglen, ipsaddr, 
	    req->rts_reqidx_peer, 
	    req->type & MQE_TYPE_WAITING_PEER ? IPS_PROTOEXP_TIDGET_PEERWAIT : 0,
	    ips_proto_mq_rv_complete_exp, req);
    }

    _IPATH_VDBG("req=%p, dest=%p, len=%d, recv_msglen=%d, stok=%p, expected=%s\n", 
		req, req->buf, req->buf_len, req->recv_msglen,
		req->ptl_req_ptr, was_posted ? "YES" : "NO");

    return PSM_OK;
}

psm_error_t __recvpath
ips_proto_mq_push_eager_req(struct ips_proto *proto, psm_mq_req_t req)
{
    ips_scb_t *scb;
    ptl_arg_t *args;
    ips_epaddr_t *ipsaddr;
    struct ips_flow *flow;

    scb = ips_scbctrl_alloc(&proto->scbc_egr, 1, 0, 0);
    if (scb == NULL)
	return PSM_OK_NO_PROGRESS;

    args = (ptl_arg_t *) ips_scb_uwords(scb);

    args[0].u32w0 = req->rts_reqidx_peer;
    args[0].u32w1 = psmi_mpool_get_obj_index(req);
    args[1].u32w0 = req->recv_msglen;

    ipsaddr = req->rts_peer->ptladdr;
    flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
    ips_scb_epaddr(scb) = ipsaddr;
    ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
    ips_scb_mqhdr (scb) = MQ_MSG_CTS_EGR;
    
    if (req->recv_msglen == 0) {
	ips_scb_cb(scb) = ips_proto_mq_rv_complete;
	ips_scb_cb_param(scb) = req;
    }

    flow->fn.xfer.enqueue(flow, scb);
    flow->fn.xfer.flush(flow, NULL);

    return PSM_OK;
}

psm_error_t __recvpath
ips_proto_mq_push_eager_data(struct ips_proto *proto, psm_mq_req_t req)
{
    uintptr_t buf = (uintptr_t) req->buf;
    ips_epaddr_t *ipsaddr = req->rts_peer->ptladdr;
    uint32_t nbytes_this;
    uint32_t nbytes_left = req->send_msglen - req->send_msgoff;
    uint16_t frag_size = ipsaddr->epr.epr_piosize;
    struct ips_flow *flow = &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
    ips_scb_t *scb;

    psmi_assert(nbytes_left > 0);

    while (nbytes_left > 0) {
      scb = ips_scbctrl_alloc(proto->scbc_rv, 1, 0, 0);
	if (scb == NULL)
	    return PSM_OK_NO_PROGRESS;
	
	nbytes_this = min(nbytes_left, frag_size);
	ips_scb_epaddr(scb) = ipsaddr;
	ips_scb_length(scb) = nbytes_this;
	ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_CTRL;
	ips_scb_mqhdr (scb) = MQ_MSG_DATA_REQ;
	ips_scb_buffer(scb) = (void *)(buf + req->send_msgoff);
	ips_scb_uwords(scb)[0].u32w0 = req->rts_reqidx_peer;
	ips_scb_uwords(scb)[0].u32w1 = req->send_msgoff;

	if (nbytes_left == nbytes_this) {
	    ips_scb_cb(scb) = ips_proto_mq_rv_complete;
	    ips_scb_cb_param(scb) = req;
	    ips_scb_flags(scb) |= IPS_SEND_FLAG_ACK_REQ;
	}
#if 0
	_IPATH_INFO("send req %p, off %d/%d, len %d, last=%s\n",
		req, req->send_msgoff, req->send_msglen, nbytes_this,
		nbytes_left == nbytes_this ? "YES" : "NO");
#endif
	SLIST_NEXT(scb, next) = NULL;

	flow->fn.xfer.enqueue(flow, scb);
	flow->fn.xfer.flush(flow, NULL);

	nbytes_left      -= nbytes_this;
	req->send_msgoff += nbytes_this;
    }

    return PSM_OK;
}

int __recvpath
ips_proto_mq_handle_cts(struct ips_proto *proto, ptl_arg_t *args)
{
    psm_mq_req_t req;
    psm_mq_t mq = proto->ep->mq;
    uint32_t reqidx, reqidx_peer;
    struct ips_pend_sreq *sreq;
    uint32_t msglen;

    reqidx      = args[0].u32w0;
    reqidx_peer = args[0].u32w1;
    msglen      = args[1].u32w0;
    
    req = psmi_mpool_find_obj_by_index(mq->sreq_pool, reqidx);
    psmi_assert_always(req != NULL);

    if (msglen == 0) {
	ips_proto_mq_rv_complete(req);
	return IPS_RECVHDRQ_CONTINUE;
    }

    sreq	      = psmi_mpool_get(proto->pend_sends_pool);
    sreq->type	      = IPS_PENDSEND_EAGER_DATA;
    sreq->req	      = req;
    req->rts_reqidx_peer = reqidx_peer;
    req->send_msglen     = msglen;
    req->send_msgoff     = 0;
    STAILQ_INSERT_TAIL(&proto->pend_sends.pendq, sreq, next);
    /* Make sure it's processed by timer */
    psmi_timer_request(proto->timerq, &proto->pend_sends.timer, 
		      PSMI_TIMER_PRIO_1);

    /* XXX Optimization here:  If the 'req' is blocking in the MPI sense, we
     * could choose to break out of the progress loop and make progress on it
     * ASAP instead of continuing to process the receive queue */
    return IPS_RECVHDRQ_CONTINUE;
}

int __recvpath
ips_proto_mq_handle_rts_envelope(psm_mq_t mq, int mode, ips_epaddr_t *ipsaddr, 
				 uint64_t tag, uint32_t reqidx_peer, 
				 uint32_t msglen)
{
    psm_mq_req_t req;
    _IPATH_VDBG("tag=%llx reqidx_peer=%d, msglen=%d\n", 
		    (long long) tag, reqidx_peer, msglen);
    int rc = psmi_mq_handle_rts(mq, tag, 0, msglen, ipsaddr->epaddr,
		                ips_proto_mq_rts_match_callback, &req);
    req->rts_reqidx_peer = reqidx_peer;
    if (mode == MQ_MSG_RTS_WAIT)
	req->type |= MQE_TYPE_WAITING_PEER;

    if (rc == MQ_RET_MATCH_OK) {
	ips_proto_mq_rts_match_callback(req, 1);
	/* XXX if blocking, break out of progress loop */
    }

    /* If no match, will be called when send actually matches */
    return IPS_RECVHDRQ_CONTINUE;
}

