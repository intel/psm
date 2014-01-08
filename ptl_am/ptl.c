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
#include "psm_am_internal.h"
#include "kcopyrw.h"
#include "knemrw.h"

static
psm_error_t
ptl_handle_rtsmatch_request(psm_mq_req_t req, int was_posted, amsh_am_token_t *tok)
{
    psm_amarg_t	args[5];
    psm_epaddr_t epaddr = req->rts_peer;
    ptl_t *ptl = epaddr->ptl;
    int pid = 0;

    psmi_assert((tok != NULL && was_posted) || (tok == NULL && !was_posted));

    _IPATH_VDBG("[shm][rndv][recv] req=%p dest=%p len=%d tok=%p\n",
		    req, req->buf, req->recv_msglen, tok);

    if ((ptl->ep->psmi_kassist_mode & PSMI_KASSIST_GET) && req->recv_msglen > 0 &&
	(pid = psmi_epaddr_kcopy_pid(epaddr)))
    {
      if (ptl->ep->psmi_kassist_mode & PSMI_KASSIST_KCOPY) {
	/* kcopy can be done in handler context or not. */
	size_t nbytes = kcopy_get(ptl->ep->psmi_kassist_fd, pid, (void *) req->rts_sbuf,
				  req->buf, req->recv_msglen);
	psmi_assert_always(nbytes == req->recv_msglen);
      }
      else {
	psmi_assert_always(ptl->ep->psmi_kassist_mode & PSMI_KASSIST_KNEM);
	
	/* knem copy can be done in handler context or not */
	knem_get(ptl->ep->psmi_kassist_fd, (int64_t) req->rts_sbuf, 
		 (void*) req->buf, req->recv_msglen);
      }
      
    }

    args[0].u64w0 = (uint64_t)(uintptr_t) req->ptl_req_ptr;
    args[1].u64w0 = (uint64_t)(uintptr_t) req;
    args[2].u64w0 = (uint64_t)(uintptr_t) req->buf;
    args[3].u32w0 = req->recv_msglen;
    args[3].u32w1 = tok != NULL ? 1 : 0;
    
    /* If KNEM PUT is active register region for peer to PUT data to */
    if (ptl->ep->psmi_kassist_mode == PSMI_KASSIST_KNEM_PUT)
      args[4].u64w0 = knem_register_region(req->buf, req->recv_msglen, 
					   PSMI_TRUE);
    else
      args[4].u64w0 = 0;
    
    if (tok != NULL) { 
	psmi_am_reqq_add(AMREQUEST_SHORT, tok->ptl, tok->tok.epaddr_from, 
	    mq_handler_rtsmatch_hidx, args, 5, NULL, 0, NULL, 0);
    }
    else
	psmi_amsh_short_request(ptl, epaddr, mq_handler_rtsmatch_hidx, 
				    args, 5, NULL, 0, 0);

    /* 0-byte completion or we used kcopy */
    if (pid || req->recv_msglen == 0) 
	psmi_mq_handle_rts_complete(req);
    return PSM_OK;
}

static
psm_error_t
ptl_handle_rtsmatch(psm_mq_req_t req, int was_posted)
{
    /* was_posted == 0 allows us to assume that we're not running this callback
     * within am handler context (i.e. we can poll) */
    psmi_assert(was_posted == 0);
    return ptl_handle_rtsmatch_request(req, 0, NULL);
}

void
psmi_am_mq_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    amsh_am_token_t *tok = (amsh_am_token_t *) toki;
    ptl_t *ptl = tok->ptl;
    psm_mq_req_t    req;
    int rc;
    int mode        = args[0].u32w0;
    uint64_t tag    = args[1].u64;
    uint32_t msglen = mode <= MQ_MSG_SHORT ? len : args[0].u32w1;

    _IPATH_VDBG("mq=%p mode=%d, len=%d, msglen=%d val_32=%d\n", 
	    tok->mq, mode, (int) len, msglen, buf == NULL ? 0 : *((uint32_t *)buf)); 

    switch(mode) {
	case MQ_MSG_TINY:
	  rc = psmi_mq_handle_tiny_envelope(tok->mq, tok->tok.epaddr_from, tag,
					    buf, (uint32_t) len);
	  return;
	  break;
	case MQ_MSG_SHORT:
	case MQ_MSG_LONG:
	  rc = psmi_mq_handle_envelope(tok->mq, mode, tok->tok.epaddr_from,
				       tag, (union psmi_egrid) 0U,
				       msglen, buf, (uint32_t) len);
	  return;
	  break;
	default: {
	    void *sreq = (void *)(uintptr_t) args[2].u64w0;
	    uintptr_t sbuf = (uintptr_t) args[3].u64w0;
	    psmi_assert(narg == 5);
	    psmi_assert_always(mode == MQ_MSG_RTS);
	    rc = psmi_mq_handle_rts(tok->mq, tag, sbuf, msglen, 
				    tok->tok.epaddr_from,
				    ptl_handle_rtsmatch, &req);
	    req->ptl_req_ptr = sreq;
	    
	    /* Overload rts_sbuf to contain the cookie for remote region */
	    if (ptl->ep->psmi_kassist_mode & PSMI_KASSIST_KNEM)
	      req->rts_sbuf = (uintptr_t) args[4].u64w0;
	    
	    if (rc == MQ_RET_MATCH_OK) /* we are in handler context, issue a reply */
		ptl_handle_rtsmatch_request(req, 1, tok);
	    /* else will be called later */
	}
    }
    return;
}

void
psmi_am_mq_handler_data(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    amsh_am_token_t *tok = (amsh_am_token_t *) toki;
    psm_mq_req_t req = STAILQ_FIRST(&tok->tok.epaddr_from->egrlong);
    psmi_mq_handle_data(req, tok->tok.epaddr_from, 0, args[2].u32w0, buf, len);
    
    return;
}

void
psmi_am_mq_handler_rtsmatch(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    amsh_am_token_t *tok = (amsh_am_token_t *) toki;
    ptl_t *ptl = tok->ptl;
    psm_mq_req_t sreq = (psm_mq_req_t) (uintptr_t) args[0].u64w0;
    void *dest = (void *)(uintptr_t) args[2].u64w0;
    uint32_t msglen = args[3].u32w0;
    int pid = 0;
    psm_amarg_t rarg[1];

    _IPATH_VDBG("[rndv][send] req=%p dest_req=%p src=%p dest=%p len=%d\n",
		    sreq, (void*)(uintptr_t)args[1].u64w0, sreq->buf, dest, msglen);

    if (msglen > 0) {
	rarg[0].u64w0 = args[1].u64w0; /* rreq */
	if (ptl->ep->psmi_kassist_mode & PSMI_KASSIST_MASK)
	    pid = psmi_epaddr_kcopy_pid(tok->tok.epaddr_from);
	else
	    pid = 0;

	if (!pid) 
	    psmi_amsh_long_reply(tok, mq_handler_rtsdone_hidx, rarg, 1, 
				 sreq->buf, msglen, dest, 0);
	else if (ptl->ep->psmi_kassist_mode & PSMI_KASSIST_PUT)
	{
	  if (ptl->ep->psmi_kassist_mode & PSMI_KASSIST_KCOPY) {
	    size_t nbytes = kcopy_put(ptl->ep->psmi_kassist_fd, sreq->buf, pid, dest,
				      msglen);
	    psmi_assert_always(nbytes == msglen);
	  }
	  else {
	    int64_t cookie = args[4].u64w0;
	    
	    psmi_assert_always(ptl->ep->psmi_kassist_mode & PSMI_KASSIST_KNEM);
	    
	    /* Do a PUT using KNEM */
	    knem_put(ptl->ep->psmi_kassist_fd, sreq->buf, msglen, cookie);
	  }
	  
	  /* Send response that PUT is complete */
	  psmi_amsh_short_reply(tok, mq_handler_rtsdone_hidx, rarg, 1,
				NULL, 0, 0);
	}
    }
    psmi_mq_handle_rts_complete(sreq);
}

void
psmi_am_mq_handler_rtsdone(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    psm_mq_req_t rreq = (psm_mq_req_t) (uintptr_t) args[0].u64w0;
    psmi_assert(narg == 1);
    _IPATH_VDBG("[rndv][recv] req=%p dest=%p len=%d\n", rreq, rreq->buf, rreq->recv_msglen);
    psmi_mq_handle_rts_complete(rreq);
}

void
psmi_am_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    amsh_am_token_t *tok = (amsh_am_token_t *) toki;
    psm_am_handler_fn_t hfn;
        
    hfn = psm_am_get_handler_function(tok->mq->ep, 
				      (psm_handler_t) args[0].u32w0);
    
    /* Invoke handler function. For AM we do not support break functionality */
    hfn(toki, tok->tok.epaddr_from, args+1, narg-1, buf, len);
    
    return;
}
