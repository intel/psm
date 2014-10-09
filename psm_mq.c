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

#include <sched.h>

#include "psm_user.h"
#include "psm_mq_internal.h"

/* 
 * Functions to manipulate the expected queue in mq_ep.
 */

/*
 * ! @brief PSM exposed version to allow PTLs to match 
 */

static
psm_mq_req_t 
mq_req_match_with_tagsel(psm_mq_t mq, struct mqsq *q, uint64_t tag, 
			 uint64_t tagsel, int remove)
{
    psm_mq_req_t *curp;
    psm_mq_req_t cur;

    for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
	if (!((tag ^ cur->tag) & tagsel)) { /* match! */
	    if (remove) {
		if ((*curp = cur->next) == NULL) /* fix tail */
		    q->lastp = curp;
		cur->next = NULL;
	    }
	    return cur;
	}
    }
    return NULL;
}

#if 0
/* Only for psm_mq_irecv. Currently not enabled. */
PSMI_ALWAYS_INLINE(
psm_mq_req_t
mq_req_match_with_tagsel_inline(struct mqsq *q, uint64_t tag, uint64_t tagsel))
{
    psm_mq_req_t cur = q->first;
    if (cur == NULL)
	return NULL;
    else if (!((cur->tag ^ tag) & tagsel)) {
	if ((q->first = cur->next) == NULL)
	    q->lastp = &q->first;
	cur->next = NULL;
	return cur;
    }
    else
	return mq_req_match_with_tagsel(q, tag, tagsel, 1);
}
#endif

static
int
mq_req_remove_single(psm_mq_t mq, struct mqsq *q, psm_mq_req_t req)
{
    psm_mq_req_t *curp;
    psm_mq_req_t cur;

    for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
	if (cur == req) {
	    if ((*curp = cur->next) == NULL)
		q->lastp = curp;
	    cur->next = NULL;
	    return 1;
	}
    }
    return 0;
}

#if 0
 /*XXX only used with cancel, for now */

static
psm_mq_req_t 
mq_req_match_req(struct mqsq *q, psm_mq_req_t req, int remove)
{
    psm_mq_req_t *curp;
    psm_mq_req_t cur;

    for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
	if (cur->send_req == req) {
	    if (remove) {
		if ((*curp = cur->next) == NULL) /* fix tail */
		    q->lastp = curp;
		cur->next = NULL;
	    }
	    return cur;
	}
    }
    return NULL; /* no match */
}
#endif

void 
psmi_mq_mtucpy(void *vdest, const void *vsrc, uint32_t nchars)
{
#ifdef __MIC__
    memcpy(vdest, vsrc, nchars);
#else
    unsigned char *dest = (unsigned char *)vdest;
    const unsigned char *src  = (const unsigned char *)vsrc;
    if(nchars>>2)
        ipath_dwordcpy((uint32_t*) dest, (uint32_t*) src, nchars>>2);
    dest += (nchars>>2)<<2;
    src += (nchars>>2)<<2;
    switch (nchars&0x03) {
        case 3: *dest++ = *src++;
        case 2: *dest++ = *src++;
        case 1: *dest++ = *src++;
    }
#endif
}

#if 0 // defined(__x86_64__) No consumers of mtucpy safe
void 
psmi_mq_mtucpy_safe(void *vdest, const void *vsrc, uint32_t nchars)
{
    unsigned char *dest = (unsigned char *)vdest;
    const unsigned char *src  = (const unsigned char *)vsrc;
    if(nchars>>2)
        ipath_dwordcpy_safe((uint32_t*) dest, (uint32_t*) src, nchars>>2);
    dest += (nchars>>2)<<2;
    src += (nchars>>2)<<2;
    switch (nchars&0x03) {
        case 3: *dest++ = *src++;
        case 2: *dest++ = *src++;
        case 1: *dest++ = *src++;
    }
}
#endif

psm_error_t
__psm_mq_iprobe(psm_mq_t mq, uint64_t tag, uint64_t tagsel, psm_mq_status_t *status)
{
    psm_mq_req_t req;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();
    req = mq_req_match_with_tagsel(mq, &mq->unexpected_q, tag, tagsel, 0);

    if (req != NULL) {
	PSMI_PUNLOCK();
	if (status != NULL)
	    mq_status_copy(req, status);
	return PSM_OK;
    }

    psmi_poll_internal(mq->ep, 1);
    /* try again */
    req = mq_req_match_with_tagsel(mq, &mq->unexpected_q, tag, tagsel, 0);

    if (req != NULL) {
	PSMI_PUNLOCK();
	if (status != NULL)
	    mq_status_copy(req, status);
	return PSM_OK;
    }
    PSMI_PUNLOCK();
    return PSM_MQ_NO_COMPLETIONS;
}
PSMI_API_DECL(psm_mq_iprobe)

psm_error_t
__psm_mq_cancel(psm_mq_req_t *ireq)
{
    psm_mq_req_t req = *ireq;
    psm_mq_t mq;
    psm_error_t err = PSM_OK;

    PSMI_ASSERT_INITIALIZED();

    if (req == NULL)
	return PSM_MQ_NO_COMPLETIONS;

    /* Cancelling a send is a blocking operation, and expensive.
     * We only allow cancellation of rendezvous sends, consider the eager sends
     * as always unsuccessfully cancelled.
     */
    PSMI_PLOCK();

    mq = req->mq;
    if (MQE_TYPE_IS_RECV(req->type)) {
	if (req->state == MQ_STATE_POSTED) {
	    int rc;

	    rc = mq_req_remove_single(mq, &mq->expected_q, req);
	    psmi_assert_always(rc);
	    req->state = MQ_STATE_COMPLETE;
	    mq_qq_append(&mq->completed_q, req);
	    err = PSM_OK;
	}
	else 
	    err = PSM_MQ_NO_COMPLETIONS;
    }
    else {
	err = psmi_handle_error(mq->ep, PSM_PARAM_ERR,
		"Cannot cancel send requests (req=%p)", req);
    }

    PSMI_PUNLOCK();

    return err;
}
PSMI_API_DECL(psm_mq_cancel)

/* This is the only PSM function that blocks.
 * We handle it in a special manner since we don't know what the user's
 * execution environment is (threads, oversubscribing processes, etc).
 *
 */
PSMI_ALWAYS_INLINE(
psm_error_t 
psmi_mq_wait_inner(psm_mq_req_t *ireq, psm_mq_status_t *status, int do_lock))
{
    psm_error_t err = PSM_OK;

    psm_mq_req_t req = *ireq;
    if (req == PSM_MQ_REQINVALID) {
	return PSM_OK;
    }

    if (do_lock)
	PSMI_PLOCK();

    if (req->state != MQ_STATE_COMPLETE) {
	psm_mq_t mq = req->mq;

	/* We'll be waiting on this req, mark it as so */
	req->type |= MQE_TYPE_WAITING;

	_IPATH_VDBG("req=%p, buf=%p, len=%d, waiting\n", 
		 req, req->buf, req->buf_len);

	if (req->testwait_callback) {
	    err = req->testwait_callback(ireq, 0, status);
	    if (do_lock)
		PSMI_PUNLOCK();
	    return err;
	}

	PSMI_BLOCKUNTIL(mq->ep, err, req->state == MQ_STATE_COMPLETE);

	if (err > PSM_OK_NO_PROGRESS)
	    goto fail_with_lock;
	else
	    err = PSM_OK;
    }

    mq_qq_remove(&req->mq->completed_q, req);

    if (status != NULL)
	mq_status_copy(req, status);
    psmi_mq_req_free(req);
    *ireq = PSM_MQ_REQINVALID;

    _IPATH_VDBG("req=%p complete, buf=%p, len=%d, err=%d\n", 
		 req, req->buf, req->buf_len, req->error_code);

fail_with_lock:
    if (do_lock)
	PSMI_PUNLOCK();
    return err;
}

psm_error_t __sendpath
__psm_mq_wait(psm_mq_req_t *ireq, psm_mq_status_t *status)
{
    PSMI_ASSERT_INITIALIZED();
    return psmi_mq_wait_inner(ireq, status, 1);
}
PSMI_API_DECL(psm_mq_wait)

psm_error_t __sendpath
psmi_mq_wait_internal(psm_mq_req_t *ireq)
{
    return psmi_mq_wait_inner(ireq, NULL, 0);
}

psm_error_t __sendpath
__psm_mq_test(psm_mq_req_t *ireq, psm_mq_status_t *status)
{
    psm_mq_req_t req = *ireq;
    psm_error_t err = PSM_OK;

    PSMI_ASSERT_INITIALIZED();

    if (req == PSM_MQ_REQINVALID) {
	return PSM_OK;
    }

    if (req->state != MQ_STATE_COMPLETE) {
	if (req->testwait_callback) {
	    PSMI_PLOCK();
	    err = req->testwait_callback(ireq, 1, status);
	    PSMI_PUNLOCK();
	    return err;
	}
	else
	    return PSM_MQ_NO_COMPLETIONS;
    }

    if (status != NULL)
	mq_status_copy(req, status);

    PSMI_PLOCK();
    mq_qq_remove(&req->mq->completed_q, req);
    psmi_mq_req_free(req);
    PSMI_PUNLOCK();

    *ireq = PSM_MQ_REQINVALID;
    _IPATH_VDBG("req=%p complete, tag=%llx buf=%p, len=%d, err=%d\n", 
	req, (unsigned long long) req->tag, req->buf, 
	req->buf_len, req->error_code);

    return err;
}
PSMI_API_DECL(psm_mq_test)

psm_error_t __sendpath
__psm_mq_isend(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags, uint64_t stag, 
	     const void *buf, uint32_t len, void *context, psm_mq_req_t *req)
{
    psm_error_t err;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();
    err = dest->ptlctl->mq_isend(mq, dest, flags, stag, buf, len, context, req);
    PSMI_PUNLOCK();

#if 0
#ifdef PSM_VALGRIND
    /* If the send isn't completed yet, make sure that we mark the memory as
     * unaccessible 
     */
    if (*req != PSM_MQ_REQINVALID && 
	(*req)->state != MQ_STATE_COMPLETE)
	VALGRIND_MAKE_MEM_NOACCESS(buf, len);
#endif
#endif
    psmi_assert(*req != NULL);
    return err;
}
PSMI_API_DECL(psm_mq_isend)

psm_error_t __sendpath
__psm_mq_send(psm_mq_t mq, psm_epaddr_t dest, uint32_t flags, uint64_t stag, 
	    const void *buf, uint32_t len)
{
    psm_error_t err;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();
    err =  dest->ptlctl->mq_send(mq, dest, flags, stag, buf, len);
    PSMI_PUNLOCK();
    return err;
}
PSMI_API_DECL(psm_mq_send)

psm_error_t __recvpath
__psm_mq_irecv(psm_mq_t mq, uint64_t tag, uint64_t tagsel, uint32_t flags, 
	      void *buf, uint32_t len, void *context, psm_mq_req_t *reqo)
{
    psm_error_t err = PSM_OK;
    psm_mq_req_t req;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();

    /* First check unexpected Queue and remove req if found */
    req = mq_req_match_with_tagsel(mq, &mq->unexpected_q, tag, tagsel, 1);

    if (req == NULL) 
    {
	/* prepost before arrival, add to expected q */
	req = psmi_mq_req_alloc(mq, MQE_TYPE_RECV);
	if_pf (req == NULL) {
	    err = PSM_NO_MEMORY;
	    goto ret;
	}

	req->tag = tag;
	req->tagsel = tagsel;
	req->state = MQ_STATE_POSTED;
	req->buf = buf;
	req->buf_len = len;
	req->recv_msglen = len;
	req->recv_msgoff = 0;
	req->context = context;

	/* Nobody should touch the buffer after it's posted */
	VALGRIND_MAKE_MEM_NOACCESS(buf, len);

	mq_sq_append(&mq->expected_q, req);
	_IPATH_VDBG("buf=%p,len=%d,tag=%"PRIx64
		    " tagsel=%"PRIx64" req=%p\n", 
		    buf,len,tag, tagsel, req);
    }
    else {
	uint32_t copysz;
	req->context = context;

	psmi_assert(MQE_TYPE_IS_RECV(req->type));
	_IPATH_VDBG("unexpected buf=%p,len=%d,tag=%"PRIx64 
		    " tagsel=%"PRIx64" req=%p\n", buf, len, tag, tagsel, req);

	switch (req->state) {
	  case MQ_STATE_COMPLETE:
	    if (req->buf != NULL) { /* 0-byte messages don't alloc a sysbuf */
		copysz = mq_set_msglen(req, len, req->send_msglen);
		psmi_mq_mtucpy(buf, (const void *) req->buf, copysz);
		psmi_mq_sysbuf_free(mq, req->buf);
	    }
	    req->buf = buf;
	    req->buf_len = len;
	    mq_qq_append(&mq->completed_q, req);
	    break;

	  case MQ_STATE_UNEXP: /* not done yet */
	    copysz = mq_set_msglen(req, len, req->send_msglen);
	    /* Copy What's been received so far and make sure we don't receive
	     * any more than copysz.  After that, swap system with user buffer
	     */
	    req->recv_msgoff = min(req->recv_msgoff, copysz);
	    psmi_mq_mtucpy(buf, (const void *) req->buf, req->recv_msgoff);
	    /* What's "left" is no access */
	    VALGRIND_MAKE_MEM_NOACCESS(
		(void *)((uintptr_t) buf + req->recv_msgoff), len - req->recv_msgoff);
	    psmi_mq_sysbuf_free(mq, req->buf);
	    req->state = MQ_STATE_MATCHED;
	    req->buf = buf;
	    req->buf_len = len;
	    break;

	  case MQ_STATE_UNEXP_RV: /* rendez-vous ... */
	    copysz = mq_set_msglen(req, len, req->send_msglen);
	    req->state = MQ_STATE_MATCHED;
	    req->buf = buf;
	    req->buf_len = len;
	    VALGRIND_MAKE_MEM_NOACCESS(buf, len);
	    req->recv_msgoff = 0;
	    req->rts_callback(req, 0);
	    break;

	  default:
	    fprintf(stderr, "Unexpected state %d in req %p\n", req->state, req);
	    fprintf(stderr, "type=%d, mq=%p, tag=%p\n",
			    req->type, req->mq, (void *)(uintptr_t)req->tag);
	    abort();
	}
    }

ret:
    PSMI_PUNLOCK();
    *reqo = req;
    return err;
}
PSMI_API_DECL(psm_mq_irecv)

psm_error_t __sendpath
__psm_mq_ipeek(psm_mq_t mq, psm_mq_req_t *oreq, psm_mq_status_t *status)
{
    psm_mq_req_t req;

    PSMI_ASSERT_INITIALIZED();

    if ((req = mq->completed_q.first) == NULL) {
	PSMI_PLOCK();
	psmi_poll_internal(mq->ep, 1);
	if ((req = mq->completed_q.first) == NULL) {
	    PSMI_PUNLOCK();
	    return PSM_MQ_NO_COMPLETIONS;
	}
	PSMI_PUNLOCK();
    }
    /* something in the queue */
    *oreq = req;
    if (status != NULL)
	mq_status_copy(req, status);

    return PSM_OK;
}
PSMI_API_DECL(psm_mq_ipeek)

static
psm_error_t
psmi_mqopt_ctl(psm_mq_t mq, uint32_t key, void *value, int get)
{
    psm_error_t err = PSM_OK;
    uint32_t val32;

    switch (key) {
	case PSM_MQ_RNDV_IPATH_SZ:
	    if (get) 
		*((uint32_t *)value) = mq->ipath_thresh_rv;
	    else {
		val32 = *((uint32_t *) value);
		mq->ipath_thresh_rv = val32;
	    }
	    _IPATH_VDBG("RNDV_IPATH_SZ = %d (%s)\n",
			mq->ipath_thresh_rv, get ? "GET" : "SET");
	    break;

	case PSM_MQ_RNDV_SHM_SZ:
	    if (get) 
		*((uint32_t *)value) = mq->shm_thresh_rv;
	    else {
		val32 = *((uint32_t *) value);
		mq->shm_thresh_rv = val32;
	    }
	    _IPATH_VDBG("RNDV_SHM_SZ = %d (%s)\n",
			mq->shm_thresh_rv, get ? "GET" : "SET");
	    break;

	case PSM_MQ_MAX_SYSBUF_MBYTES:
	    if (get)
		*((uint32_t *)value) = (uint32_t)(mq->max_sysbuf_bytes / 1048576);
	    else {
		val32 = *((uint32_t *) value);
		/* XXX For now, don't support this */
		/* mq->max_sysbuf_bytes = 1048576ULL * val32; */
		mq->max_sysbuf_bytes = ~(0ULL);
	    }
	    break;
	
	default:
	    err = psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown option key=%u", key);
	    break;
    }
    return err;
}

psm_error_t
__psm_mq_getopt(psm_mq_t mq, int key, void *value)
{
    PSMI_ERR_UNLESS_INITIALIZED(mq->ep);
    return psmi_mqopt_ctl(mq, key, value, 1);
}
PSMI_API_DECL(psm_mq_getopt)

psm_error_t
__psm_mq_setopt(psm_mq_t mq, int key, const void *value)
{
    PSMI_ERR_UNLESS_INITIALIZED(mq->ep);
    return psmi_mqopt_ctl(mq, key, (void *) value, 0);
}
PSMI_API_DECL(psm_mq_setopt)

/*
 * This is the API for the user.  We actually allocate the MQ much earlier, but
 * the user can set options after obtaining an endpoint
 */
psm_error_t
__psm_mq_init(psm_ep_t ep, uint64_t tag_order_mask, 
	    const struct psm_optkey *opts, 
	    int numopts, psm_mq_t *mqo)
{
    psm_error_t err = PSM_OK;
    psm_mq_t mq = ep->mq;
    int i;

    PSMI_ERR_UNLESS_INITIALIZED(ep);

    psmi_assert(mq != NULL);
    psmi_assert(mq->ep != NULL);

    /* Process options */
    for (i = 0; err == PSM_OK && i < numopts; i++) 
	err = psmi_mqopt_ctl(mq, opts[i].key, opts[i].value, 0);
    if (err != PSM_OK) /* error already handled */
	goto fail;
    
    *mqo = mq;

fail:
    return err;
}
PSMI_API_DECL(psm_mq_init)

psm_error_t
__psm_mq_finalize(psm_mq_t mq)
{
    psm_ep_t	ep;
    PSMI_ERR_UNLESS_INITIALIZED(mq->ep);

    ep = mq->ep;
    do {
	ep->mq = NULL;
	ep = ep->mctxt_next;
    } while (ep != mq->ep);

    return psmi_mq_free(mq);
}
PSMI_API_DECL(psm_mq_finalize)

void
__psm_mq_get_stats(psm_mq_t mq, psm_mq_stats_t *stats)
{
    memcpy(stats, &mq->stats, sizeof(psm_mq_stats_t));
}
PSMI_API_DECL(psm_mq_get_stats)

psm_error_t
psmi_mq_malloc(psm_mq_t *mqo)
{
    psm_error_t err = PSM_OK;

    psm_mq_t mq = (psm_mq_t) psmi_calloc(NULL, UNDEFINED, 1, sizeof(struct psm_mq));
    if (mq == NULL) {
	err = psmi_handle_error(NULL, PSM_NO_MEMORY,
		"Couldn't allocate memory for mq endpoint");
	goto fail;
    }

    mq->ep = NULL;
    mq->memmode = psmi_parse_memmode();
    mq->expected_q.first = NULL;
    mq->expected_q.lastp = &mq->expected_q.first;
    mq->unexpected_q.first = NULL;
    mq->unexpected_q.lastp = &mq->unexpected_q.first;
    mq->completed_q.first = NULL;
    mq->completed_q.lastp = &mq->completed_q.first;

    mq->cur_sysbuf_bytes = 0ULL;
    mq->max_sysbuf_bytes = ~(0ULL);

    /* The values are overwritten in initialize_defaults, they're just set to
     * sensible defaults until then */
    mq->ipath_thresh_rv = 64000;
    mq->ipath_window_rv = 131072;
    mq->shm_thresh_rv = 16000;

    memset(&mq->stats, 0, sizeof(psm_mq_stats_t));
    err = psmi_mq_req_init(mq);
    if (err)
	goto fail;

    /* Initialize the unexpected system buffer allocator */
    psmi_mq_sysbuf_init(mq);
    char buf[128];
    psmi_mq_sysbuf_getinfo(mq, buf, sizeof buf);
    _IPATH_VDBG("%s", buf);
    *mqo = mq;

    return PSM_OK;
fail:
    if (mq != NULL)
	psmi_free(mq);
    return err;
}

psm_error_t
psmi_mq_initialize_defaults(psm_mq_t mq)
{
    union psmi_envvar_val env_rvwin, env_ipathrv, env_shmrv;

    psmi_getenv("PSM_MQ_RNDV_IPATH_THRESH", 
		"ipath eager-to-rendezvous switchover",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) mq->ipath_thresh_rv, &env_ipathrv);
    mq->ipath_thresh_rv = env_ipathrv.e_uint;

    /* Re-evaluate this since it may have changed after initializing the shm
     * device */
    mq->shm_thresh_rv = psmi_shm_mq_rv_thresh;
    psmi_getenv("PSM_MQ_RNDV_SHM_THRESH", 
		"shm eager-to-rendezvous switchover",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) mq->shm_thresh_rv, &env_shmrv);
    mq->shm_thresh_rv = env_shmrv.e_uint;

    psmi_getenv("PSM_MQ_RNDV_IPATH_WINDOW", 
		"ipath rendezvous window size",
		PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) mq->ipath_window_rv, &env_rvwin);
    mq->ipath_window_rv = env_rvwin.e_uint;

    return PSM_OK;
}
    

psm_error_t
psmi_mq_free(psm_mq_t mq)
{
    psmi_mq_req_fini(mq);
    psmi_mq_sysbuf_fini(mq);
    psmi_free(mq);
    return PSM_OK;
}
