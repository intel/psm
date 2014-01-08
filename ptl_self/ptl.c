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

/* 
 * This file implements the PSM PTL for self (loopback)
 */

#include "psm_user.h"
#include "psm_mq_internal.h"

struct ptl {
    psm_ep_t	    ep;
    psm_epid_t	    epid;
    psm_epaddr_t    epaddr;
    ptl_ctl_t	    *ctl;
};

static
psm_error_t __fastpath
ptl_handle_rtsmatch(psm_mq_req_t recv_req, int was_posted)
{
    psm_mq_req_t send_req = (psm_mq_req_t) recv_req->ptl_req_ptr;

    if (recv_req->recv_msglen > 0) {
	PSM_VALGRIND_DEFINE_MQ_RECV(recv_req->buf, recv_req->buf_len,
				recv_req->recv_msglen);
	VALGRIND_MAKE_MEM_DEFINED(send_req->buf, send_req->buf_len);
	VALGRIND_MAKE_MEM_DEFINED(send_req->buf, recv_req->recv_msglen);

	psmi_mq_mtucpy(recv_req->buf, send_req->buf, recv_req->recv_msglen); 
    }

    psmi_mq_handle_rts_complete(recv_req);

    /* If the send is already marked complete, that's because it was internally
     * buffered. */
    if (send_req->state == MQ_STATE_COMPLETE) {
	psmi_mq_stats_rts_account(send_req);
	if (send_req->buf != NULL && send_req->send_msglen > 0) 
	    psmi_mq_sysbuf_free(send_req->mq, send_req->buf);
	psmi_mq_req_free(send_req); /* req was left "live" even though the
				     * sender was told that the send was done */
    }
    else
	psmi_mq_handle_rts_complete(send_req);

    _IPATH_VDBG("[self][complete][b=%p][sreq=%p][rreq=%p]\n",
	    recv_req->buf, send_req, recv_req);
    return PSM_OK;
}

static
psm_error_t
self_mq_send_testwait(psm_mq_req_t *ireq, int istest, psm_mq_status_t *status)
{
    uint8_t *ubuf;
    psm_mq_req_t req = *ireq;

    PSMI_PLOCK_ASSERT();

    /* We're waiting on a send request, and the matching receive has not been
     * posted yet.  This is a deadlock condition in MPI but we accodomate it
     * here in the "self ptl" by using system-allocated memory.
     */
    req->testwait_callback = NULL; /* no more calls here */

    ubuf = req->buf;
    if (ubuf != NULL && req->send_msglen > 0) {
	req->buf = psmi_mq_sysbuf_alloc(req->mq, req->send_msglen);
	if (req->buf == NULL)
	    return PSM_NO_MEMORY;
	psmi_mq_mtucpy(req->buf, ubuf, req->send_msglen); 
    }

    /* Mark it complete but don't free the req, it's freed when the receiver
     * does the match */
    req->state = MQ_STATE_COMPLETE;
    *ireq = PSM_MQ_REQINVALID;

    if (status != NULL)
	mq_status_copy(req, status);
    return PSM_OK;
}

/* Self is different.  We do everything as rendezvous. */
static
psm_error_t __fastpath
self_mq_isend(psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	     uint64_t tag, const void *ubuf, uint32_t len, void *context,
	     psm_mq_req_t *req_o)
{
    psm_mq_req_t send_req;
    psm_mq_req_t recv_req;
    int rc;

    send_req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
    if_pf (send_req == NULL)
	return PSM_NO_MEMORY;

    rc = psmi_mq_handle_rts(mq, tag, (uintptr_t) ubuf, len, epaddr,
		                ptl_handle_rtsmatch, &recv_req);
    send_req->buf = (void *) ubuf;
    send_req->send_msglen = len;
    send_req->context = context;
    recv_req->ptl_req_ptr = (void *) send_req;
    if (rc == MQ_RET_MATCH_OK) 
	ptl_handle_rtsmatch(recv_req, 1);
    else  
	send_req->testwait_callback = self_mq_send_testwait;

    _IPATH_VDBG("[self][b=%p][m=%d][t=%"PRIx64"][match=%s][req=%p]\n",
	    ubuf, len, tag, rc == MQ_RET_MATCH_OK ? "YES" : "NO", send_req);
    *req_o = send_req;
    return PSM_OK;
}

static __fastpath
psm_error_t
self_mq_send(psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	    uint64_t tag, const void *ubuf, uint32_t len)
{
    psm_error_t err;
    psm_mq_req_t req;
    err = self_mq_isend(mq,epaddr,flags,tag,ubuf,len,NULL,&req);
    psmi_mq_wait_internal(&req);
    return err; 
}

static
psm_error_t 
self_connect(ptl_t *ptl,
             int numep,
	     const psm_epid_t array_of_epid[], 
	     const int array_of_epid_mask[],
             psm_error_t  array_of_errors[],
	     psm_epaddr_t array_of_epaddr[],
	     uint64_t timeout_ns)
{
    psmi_assert_always(ptl->epaddr != NULL);
    psm_epaddr_t epaddr;
    psm_error_t err = PSM_OK;
    int i;

    PSMI_PLOCK_ASSERT();

    for (i = 0; i < numep; i++) {
	if (!array_of_epid_mask[i])
	    continue;

	if (array_of_epid[i] == ptl->epid) {
	    epaddr = psmi_epid_lookup(ptl->ep, ptl->epid);
	    psmi_assert_always(epaddr == NULL);
	    array_of_epaddr[i] = ptl->epaddr;
	    array_of_epaddr[i]->ptl = ptl;
	    array_of_epaddr[i]->ptlctl = ptl->ctl;
	    array_of_epaddr[i]->epid = ptl->epid;
	    array_of_epaddr[i]->ep = ptl->ep;
	    if (psmi_epid_set_hostname(psm_epid_nid(ptl->epid), 
				       psmi_gethostname(), 0)) {
		err = PSM_NO_MEMORY;
		goto fail;
	    }
	    psmi_epid_add(ptl->ep, ptl->epid, ptl->epaddr);
	    array_of_errors[i] = PSM_OK;
	}
	else {
	    array_of_epaddr[i] = NULL;
	    array_of_errors[i] = PSM_EPID_UNREACHABLE;
	}
    }

fail:
    return err;
}

#if 0
static
psm_error_t 
self_disconnect(ptl_t *ptl, int numep, 
		const psm_epaddr_t array_of_epaddr[],
		int array_of_epaddr_mask[],
		int force, uint64_t timeout_ns)
{
    int i;
    for (i = 0; i < numep; i++) {
	if (array_of_epaddr_mask[i] == 0)
	    continue;

	if (array_of_epaddr[i] == ptl->epaddr) 
	    array_of_epaddr_mask[i] = 1;
	else
	    array_of_epaddr_mask[i] = 0;
    }
    return PSM_OK;
}
#endif

static
size_t
self_ptl_sizeof(void)
{
    return sizeof(ptl_t);
}

static
psm_error_t 
self_ptl_init(const psm_ep_t ep, ptl_t *ptl, ptl_ctl_t *ctl)
{
    psmi_assert_always(ep != NULL);
    psmi_assert_always(ep->epaddr != NULL);
    psmi_assert_always(ep->epid != 0);

    ptl->ep   = ep; 
    ptl->epid = ep->epid;
    ptl->epaddr = ep->epaddr;
    ptl->ctl = ctl;
    ep->epaddr->mctxt_prev = ep->epaddr;
    ep->epaddr->mctxt_next = ep->epaddr;
    ep->epaddr->mctxt_master = ep->epaddr;

    memset(ctl, 0, sizeof(*ctl));
    /* Fill in the control structure */
    ctl->ptl = ptl;
    ctl->ep_poll = NULL;
    ctl->ep_connect = self_connect;
    ctl->ep_disconnect = NULL;

    ctl->mq_send  = self_mq_send;
    ctl->mq_isend = self_mq_isend;

    /* No stats in self */
    ctl->epaddr_stats_num  = NULL;
    ctl->epaddr_stats_init = NULL;
    ctl->epaddr_stats_get  = NULL;

    return PSM_OK;
}

static
psm_error_t 
self_ptl_fini(ptl_t *ptl, int force, uint64_t timeout_ns)
{
    return PSM_OK; /* nothing to do */
}

static 
psm_error_t
self_ptl_setopt(const void *component_obj, int optname, 
		const void *optval, uint64_t optlen)
{
  /* No options for SELF PTL at the moment */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown SELF ptl option %u.", optname);
}

static
psm_error_t
self_ptl_getopt(const void *component_obj, int optname,
	       void *optval, uint64_t *optlen)
{
  /* No options for SELF PTL at the moment */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown SELF ptl option %u.", optname);
}

/* Only symbol we expose out of here */
struct ptl_ctl_init
psmi_ptl_self = { 
  self_ptl_sizeof, self_ptl_init, self_ptl_fini,self_ptl_setopt,self_ptl_getopt
};
