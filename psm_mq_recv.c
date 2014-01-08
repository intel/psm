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
#include "psm_mq_internal.h"

#define psmi_mq_handle_egrdata(mq, req, epaddr) \
    do { \
	    psm_mq_req_t dreq, treq; \
	    dreq = STAILQ_FIRST(&epaddr->mctxt_master->egrdata); \
	    while (dreq) { \
		treq = dreq; \
		dreq = STAILQ_NEXT(dreq, nextq); \
		if (treq->egrid.egr_data == req->egrid.egr_data) { \
		    psmi_mq_handle_data(req, epaddr, treq->egrid.egr_data, \
			treq->recv_msgoff, treq->buf, treq->recv_msglen); \
		    psmi_mq_sysbuf_free(mq, treq->buf); \
		    STAILQ_REMOVE(&epaddr->mctxt_master->egrdata, \
			treq, psm_mq_req, nextq); \
		    psmi_mq_req_free(treq); \
		} \
	    } \
    } while (0)

static void __recvpath
psmi_mq_req_copy(psm_mq_req_t req, psm_epaddr_t epaddr,
		uint32_t offset, const void *buf, uint32_t nbytes)
{
    // recv_msglen may be changed by unexpected receive buf.
    uint32_t msglen_this, end;
    uint8_t *msgptr = (uint8_t *)req->buf + offset;
    
    end = offset + nbytes;
    if (end > req->recv_msglen) {
	if (offset >= req->recv_msglen) msglen_this = 0;
	else msglen_this = req->recv_msglen - offset;
    } else {
	msglen_this = nbytes;
    }

    VALGRIND_MAKE_MEM_DEFINED(msgptr, msglen_this);
    psmi_mq_mtucpy(msgptr, buf, msglen_this);
    
    if (req->recv_msgoff < end) {
	req->recv_msgoff = end;
    }
    req->send_msgoff += nbytes;
    return;
}

int __recvpath
psmi_mq_handle_data(psm_mq_req_t req, psm_epaddr_t epaddr,
		    uint32_t egrid, uint32_t offset,
		    const void *buf, uint32_t nbytes)
{
    psm_mq_t mq;
    int rc;
    
    if (req == NULL) goto no_req;

    mq = req->mq;
    if (req->state == MQ_STATE_MATCHED)
	rc = MQ_RET_MATCH_OK;
    else {
	psmi_assert(req->state == MQ_STATE_UNEXP);
	rc = MQ_RET_UNEXP_OK;
    }

    psmi_assert(req->egrid.egr_data == egrid);
    psmi_mq_req_copy(req, epaddr, offset, buf, nbytes);

    if (req->send_msgoff == req->send_msglen) {
	if (req->type & MQE_TYPE_EGRLONG) {
	    STAILQ_REMOVE(&epaddr->mctxt_master->egrlong,
				req, psm_mq_req, nextq);
	}
	    
	if (req->state == MQ_STATE_MATCHED) {
	    req->state = MQ_STATE_COMPLETE;
	    mq_qq_append(&mq->completed_q, req);
	}
	else { /* MQ_STATE_UNEXP */
	    req->state = MQ_STATE_COMPLETE;
	}
	_IPATH_VDBG("epaddr=%s completed %d byte send, state=%d\n", 
		    psmi_epaddr_get_name(epaddr->epid),
		    (int)req->send_msglen, req->state);
    }

    return rc;

no_req:
    mq = epaddr->ep->mq;
    req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
    psmi_assert(req != NULL);

    req->egrid.egr_data = egrid;
    req->recv_msgoff = offset;
    req->recv_msglen = nbytes;
    req->buf = psmi_mq_sysbuf_alloc(mq, nbytes);
    psmi_mq_mtucpy(req->buf, buf, nbytes);

    STAILQ_INSERT_TAIL(&epaddr->mctxt_master->egrdata, req, nextq);

    return MQ_RET_UNEXP_OK;
}

int __recvpath
psmi_mq_handle_rts(psm_mq_t mq, uint64_t tag, 
		   uintptr_t send_buf, uint32_t send_msglen, 
		   psm_epaddr_t peer, mq_rts_callback_fn_t cb, 
		   psm_mq_req_t *req_o)
{
    psm_mq_req_t req;
    int rc;

    PSMI_PLOCK_ASSERT();

    req = mq_req_match(&(mq->expected_q), tag, 1);

    if (req) { /* we have a match, no need to callback */
	(void)mq_set_msglen(req, req->buf_len, send_msglen);
	req->state = MQ_STATE_MATCHED;
	req->tag = tag;
	req->send_msgoff = 0;
	req->rts_peer = peer;
	req->rts_sbuf = send_buf;
	*req_o = req; /* yes match */
	rc = MQ_RET_MATCH_OK;
    }
    else { /* No match, keep track of callback */
	req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
	psmi_assert(req != NULL);
	/* We don't know recv_msglen yet but we set it here for
	 * mq_iprobe */
	req->send_msglen = req->recv_msglen = send_msglen;
	req->state = MQ_STATE_UNEXP_RV;
	req->tag = tag;
	req->rts_callback = cb;
	req->recv_msgoff = 0;
	req->send_msgoff = 0;
	req->rts_peer = peer;
	req->rts_sbuf = send_buf;
	mq_sq_append(&mq->unexpected_q, req);
	*req_o = req; /* no match, will callback */
	rc = MQ_RET_UNEXP_OK;
    }

    _IPATH_VDBG("from=%s match=%s (req=%p) mqtag=%" PRIx64" recvlen=%d "
		"sendlen=%d errcode=%d\n", psmi_epaddr_get_name(peer->epid), 
		rc == MQ_RET_MATCH_OK ? "YES" : "NO", req, req->tag, 
		req->recv_msglen, req->send_msglen, req->error_code);
    return rc;
}

void
psmi_mq_handle_rts_complete(psm_mq_req_t req) 
{
    psm_mq_t mq = req->mq;

    /* Stats on rendez-vous messages */
    psmi_mq_stats_rts_account(req);
    req->state = MQ_STATE_COMPLETE;
    mq_qq_append(&mq->completed_q, req);
#ifdef PSM_VALGRIND
    if (MQE_TYPE_IS_RECV(req->type))
	PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len, req->recv_msglen);
    else
	VALGRIND_MAKE_MEM_DEFINED(req->buf, req->buf_len);
#endif
    _IPATH_VDBG("RTS complete, req=%p, recv_msglen = %d\n", 
		    req, req->recv_msglen);
    return;
}

/* Not exposed in public psm, but may extend parts of PSM 2.1 to support
 * this feature before 2.3 */
psm_mq_unexpected_callback_fn_t
psmi_mq_register_unexpected_callback(psm_mq_t mq, 
				     psm_mq_unexpected_callback_fn_t fn)
{
    psm_mq_unexpected_callback_fn_t old_fn = mq->unexpected_callback;
    mq->unexpected_callback = fn;
    return old_fn;
}

int __recvpath
psmi_mq_handle_envelope_unexpected(
	psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr,
	uint64_t tag, psmi_egrid_t egrid, uint32_t send_msglen, 
	const void *payload, uint32_t paylen)
{
    psm_mq_req_t req;
    uint32_t msglen;

    /* 
     * Keep a callback here in case we want to fit some other high-level
     * protocols over MQ (i.e. shmem).  These protocols would bypass the
     * normal mesage handling and go to higher-level message handlers.
     */
    if (mode >= MQ_MSG_USER_FIRST && mq->unexpected_callback) {
	mq->unexpected_callback(mq,mode,epaddr,tag,send_msglen,payload,paylen);
	return MQ_RET_UNEXP_OK;
    }
    req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
    psmi_assert(req != NULL);

    req->tag = tag;
    req->recv_msgoff = 0;
    req->recv_msglen = req->send_msglen = req->buf_len = msglen = send_msglen;

    _IPATH_VDBG(
		"from=%s match=NO (req=%p) mode=%x mqtag=%" PRIx64
		" send_msglen=%d\n", psmi_epaddr_get_name(epaddr->epid), 
		req, mode, tag, send_msglen);
#if 0
    if (mq->cur_sysbuf_bytes+msglen > mq->max_sysbuf_bytes) {
		_IPATH_VDBG("req=%p with len=%d exceeds limit of %llu sysbuf_bytes\n",
			req, msglen, (unsigned long long) mq->max_sysbuf_bytes);
		return MQ_RET_UNEXP_NO_RESOURCES;
    }
#endif
    switch (mode) {
	case MQ_MSG_TINY:
	    if (msglen > 0) {
		req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
		mq_copy_tiny((uint32_t *)req->buf, (uint32_t *)payload, msglen);
	    }
	    else
		req->buf = NULL;
	    req->state = MQ_STATE_COMPLETE;
	    break;

	case MQ_MSG_SHORT:
	    req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
	    psmi_mq_mtucpy(req->buf, payload, msglen);
	    req->state = MQ_STATE_COMPLETE;
	    break;

	case MQ_MSG_LONG:
	    req->egrid = egrid;
	    req->send_msgoff = 0;
	    req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
	    req->state = MQ_STATE_UNEXP;
	    req->type |= MQE_TYPE_EGRLONG;
	    STAILQ_INSERT_TAIL(&epaddr->mctxt_master->egrlong, req, nextq);
	    _IPATH_VDBG("unexp MSG_LONG %d of length %d bytes pay=%d\n", 
			egrid.egr_msgno, msglen, paylen);
	    if (paylen > 0)
		psmi_mq_handle_data(req, epaddr,
			egrid.egr_data, 0, payload, paylen);
	    psmi_mq_handle_egrdata(mq, req, epaddr);
	    break;

	default:
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			    "Internal error, unknown packet 0x%x", mode);
    }
    mq_sq_append(&mq->unexpected_q, req);
    mq->stats.rx_sys_bytes += msglen;
    mq->stats.rx_sys_num++;

    return MQ_RET_UNEXP_OK;
}

/* 
 * This handles the regular (i.e. non-rendezvous MPI envelopes) 
 */
int __recvpath
psmi_mq_handle_envelope(psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr,
		   uint64_t tag, psmi_egrid_t egrid, uint32_t send_msglen, 
		   const void *payload, uint32_t paylen)
{
    psm_mq_req_t req;
    uint32_t msglen;
    int rc;

    psmi_assert(epaddr != NULL);

    req = mq_req_match(&(mq->expected_q), tag, 1);

    if (req) { /* we have a match */
	psmi_assert(MQE_TYPE_IS_RECV(req->type));
	req->tag = tag;
	msglen = mq_set_msglen(req, req->buf_len, send_msglen);

	_IPATH_VDBG("from=%s match=YES (req=%p) mode=%x mqtag=%"
		PRIx64" msglen=%d paylen=%d\n", psmi_epaddr_get_name(epaddr->epid), 
		req, mode, tag, msglen, paylen);

	switch(mode) {
	    case MQ_MSG_TINY:
		PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len, msglen);
		mq_copy_tiny((uint32_t *)req->buf, (uint32_t *)payload, msglen);
		req->state = MQ_STATE_COMPLETE;
		mq_qq_append(&mq->completed_q, req);
		break;

	    case MQ_MSG_SHORT: /* message fits in 1 payload */
		PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len, msglen);
		psmi_mq_mtucpy(req->buf, payload, msglen);
		req->state = MQ_STATE_COMPLETE;
		mq_qq_append(&mq->completed_q, req);
		break;

	    case MQ_MSG_LONG:
		req->egrid = egrid;
		req->state = MQ_STATE_MATCHED;
		req->type |= MQE_TYPE_EGRLONG;
		req->send_msgoff = req->recv_msgoff = 0;
		STAILQ_INSERT_TAIL(&epaddr->mctxt_master->egrlong, req, nextq);
		_IPATH_VDBG("exp MSG_LONG %d of length %d bytes pay=%d\n", 
			egrid.egr_msgno, msglen, paylen);
		if (paylen > 0)
		    psmi_mq_handle_data(req, epaddr,
			egrid.egr_data, 0, payload, paylen);
		psmi_mq_handle_egrdata(mq, req, epaddr);
		break;

	    default:
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			    "Internal error, unknown packet 0x%x", mode);
	}

	mq->stats.rx_user_bytes += msglen;
	mq->stats.rx_user_num++;

	rc = MQ_RET_MATCH_OK;
	if (mode == MQ_MSG_LONG)
	    return rc;
    }
    else
	rc =  psmi_mq_handle_envelope_unexpected(mq, mode, epaddr, tag,
		    egrid, send_msglen, payload, paylen);

    return rc;
}

/*
 * Note, epaddr is the master.
 */
int __recvpath
psmi_mq_handle_outoforder_queue(psm_epaddr_t epaddr)
{
    psm_mq_t mq = epaddr->ep->mq;
    psm_mq_req_t ureq, ereq;
    uint32_t msglen;

    next_ooo:
    ureq = mq_ooo_match(&epaddr->outoforder_q, epaddr->mctxt_recv_seqnum);
    if (ureq == NULL) return 0;
    epaddr->mctxt_recv_seqnum++;
    epaddr->outoforder_c--;

    ereq = mq_req_match(&(mq->expected_q), ureq->tag, 1);
    if (ereq == NULL) {
	mq_sq_append(&mq->unexpected_q, ureq);
	if (epaddr->outoforder_c) goto next_ooo;
	return 0;
    }

    psmi_assert(MQE_TYPE_IS_RECV(ereq->type));
    ereq->tag = ureq->tag;
    msglen = mq_set_msglen(ereq, ereq->buf_len, ureq->send_msglen);

    switch (ureq->state) {
    case MQ_STATE_COMPLETE:
	if (ureq->buf != NULL) { /* 0-byte don't alloc a sysbuf */
	    psmi_mq_mtucpy(ereq->buf,
		(const void *)ureq->buf, msglen);
	    psmi_mq_sysbuf_free(mq, ureq->buf);
	}
	ereq->state = MQ_STATE_COMPLETE;
	mq_qq_append(&mq->completed_q, ereq);
	break;
    case MQ_STATE_UNEXP: /* not done yet */
	ereq->type = ureq->type;
	ereq->egrid = ureq->egrid;
	ereq->epaddr = ureq->epaddr;
	ereq->send_msgoff = ureq->send_msgoff;
	ereq->recv_msgoff = min(ureq->recv_msgoff, msglen);
	psmi_mq_mtucpy(ereq->buf,
	    (const void *)ureq->buf, ereq->recv_msgoff);
	psmi_mq_sysbuf_free(mq, ureq->buf);
	ereq->state = MQ_STATE_MATCHED;
	STAILQ_INSERT_AFTER(&ureq->epaddr->mctxt_master->egrlong,
			ureq, ereq, nextq);
	STAILQ_REMOVE(&ureq->epaddr->mctxt_master->egrlong,
			ureq, psm_mq_req, nextq);
	break;
    case MQ_STATE_UNEXP_RV: /* rendez-vous ... */
	ereq->state = MQ_STATE_MATCHED;
	ereq->rts_peer = ureq->rts_peer;
	ereq->rts_sbuf = ureq->rts_sbuf;
	ereq->send_msgoff = 0;
	ereq->rts_callback = ureq->rts_callback;
	ereq->rts_reqidx_peer = ureq->rts_reqidx_peer;
	ereq->type = ureq->type;
	ereq->rts_callback(ereq, 0);
	break;
    default:
	fprintf(stderr, "Unexpected state %d in req %p\n", ureq->state, ureq);
	fprintf(stderr, "type=%d, mq=%p, tag=%p\n",
			ureq->type, ureq->mq, (void *)(uintptr_t)ureq->tag);
	abort();
    }

    psmi_mq_req_free(ureq);
    if (epaddr->outoforder_c) goto next_ooo;
    return 0;
}

int __recvpath
psmi_mq_handle_envelope_outoforder(psm_mq_t mq, uint16_t mode,
		   psm_epaddr_t epaddr, uint16_t msg_seqnum,
		   uint64_t tag, psmi_egrid_t egrid, uint32_t send_msglen, 
		   const void *payload, uint32_t paylen)
{
    psm_mq_req_t req;
    uint32_t msglen;

    req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
    psmi_assert(req != NULL);

    req->tag = tag;
    req->recv_msgoff = 0;
    req->recv_msglen = req->send_msglen = req->buf_len = msglen = send_msglen;

    _IPATH_VDBG(
		"from=%s match=NO (req=%p) mode=%x mqtag=%" PRIx64
		" send_msglen=%d\n", psmi_epaddr_get_name(epaddr->epid), 
		req, mode, tag, send_msglen);
    switch (mode) {
	case MQ_MSG_TINY:
	    if (msglen > 0) {
		req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
		mq_copy_tiny((uint32_t *)req->buf, (uint32_t *)payload, msglen);
	    }
	    else
		req->buf = NULL;
	    req->state = MQ_STATE_COMPLETE;
	    break;

	case MQ_MSG_SHORT:
	    req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
	    psmi_mq_mtucpy(req->buf, payload, msglen);
	    req->state = MQ_STATE_COMPLETE;
	    break;

	case MQ_MSG_LONG:
	    req->egrid = egrid;
	    req->epaddr = epaddr;
	    req->send_msgoff = 0;
	    req->buf = psmi_mq_sysbuf_alloc(mq, msglen);
	    req->state = MQ_STATE_UNEXP;
	    req->type |= MQE_TYPE_EGRLONG;
	    STAILQ_INSERT_TAIL(&epaddr->mctxt_master->egrlong, req, nextq);
	    _IPATH_VDBG("unexp MSG_LONG %d of length %d bytes pay=%d\n", 
			egrid.egr_msgno, msglen, paylen);
	    if (paylen > 0)
		psmi_mq_handle_data(req, epaddr,
			egrid.egr_data, 0, payload, paylen);
	    psmi_mq_handle_egrdata(mq, req, epaddr);
	    break;

	default:
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			    "Internal error, unknown packet 0x%x", mode);
    }

    req->msg_seqnum = msg_seqnum;
    mq_sq_append(&epaddr->mctxt_master->outoforder_q, req);
    epaddr->mctxt_master->outoforder_c++;
    mq->stats.rx_sys_bytes += msglen;
    mq->stats.rx_sys_num++;

    return MQ_RET_UNEXP_OK;
}

int __recvpath
psmi_mq_handle_rts_outoforder(psm_mq_t mq, uint64_t tag, 
		   uintptr_t send_buf, uint32_t send_msglen, 
		   psm_epaddr_t peer, uint16_t msg_seqnum,
		   mq_rts_callback_fn_t cb, 
		   psm_mq_req_t *req_o)
{
    psm_mq_req_t req;

    PSMI_PLOCK_ASSERT();

    req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
    psmi_assert(req != NULL);

    /* We don't know recv_msglen yet but we set it here for
     * mq_iprobe */
    req->send_msglen = req->recv_msglen = send_msglen;
    req->state = MQ_STATE_UNEXP_RV;
    req->tag = tag;
    req->rts_callback = cb;
    req->recv_msgoff = 0;
    req->send_msgoff = 0;
    req->rts_peer = peer;
    req->rts_sbuf = send_buf;
    req->msg_seqnum = msg_seqnum;
    mq_sq_append(&peer->mctxt_master->outoforder_q, req);
    peer->mctxt_master->outoforder_c++;
    *req_o = req; /* no match, will callback */

    _IPATH_VDBG("from=%s match=%s (req=%p) mqtag=%" PRIx64" recvlen=%d "
		"sendlen=%d errcode=%d\n", psmi_epaddr_get_name(peer->epid), 
		"NO", req, req->tag, 
		req->recv_msglen, req->send_msglen, req->error_code);
    return MQ_RET_UNEXP_OK;
}

