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

/*
 * Expected tid operations are carried out over "sessions".  One session is a
 * collection of N tids where N is determined by the expected message window
 * size (-W option or PSM_MQ_RNDV_IPATH_WINDOW).  Since naks can cause
 * retransmissions, each session has an session index (_desc_idx) and a
 * generation count (_desc_genc) to be able to identify if retransmitted
 * packets reference the correct session.
 *
 * index and generation count are each 4 bytes encoded in one ptl_arg.  They
 * could be compressed further but we have the header space, so we don't
 * bother.
 */
#define _desc_idx   u32w0
#define _desc_genc  u32w1

/* 
 * Easy switch to (say) _IPATH_INFO if debugging in the expected protocol is
 * needed
 */
#define _IPATH_EXP _IPATH_VDBG

/*
 * Timer callbacks.  When we need work to be done out of the receive process
 * loop, we schedule work on timers to be done at a later time.
 */
static psm_error_t 
ips_tid_pendsend_timer_callback(struct psmi_timer *timer, uint64_t current);

static psm_error_t 
ips_tid_pendtids_timer_callback(struct psmi_timer *timer, uint64_t current);

static psm_error_t 
ips_tid_release_timer_callback(struct psmi_timer *timer, uint64_t current);

static psm_error_t 
ips_tid_grant_timer_callback(struct psmi_timer *timer, uint64_t current);

static psm_error_t 
ips_tid_send_handle_tidreq(struct ips_protoexp *protoexp, psm_mq_req_t req, 
			   uint32_t msglen, int flags, ptl_epaddr_t *ipsaddr,
			   psmi_seqnum_t flowgenseq,
			   ips_tid_session_list *tid_list, 
			   uint32_t tid_list_size);

static void 
ips_tid_scbavail_callback(struct ips_scbctrl *scbc, void *context);

static void
ips_tid_flowavail_callback(struct ips_tfctrl *tfctrl, void *context);

static void 
ips_tid_mpool_tidrecv_callback(void *context);

/* Defined at the ptl-level (breaks abstractions but needed for shared vs
 * non-shared contexts */
extern int ips_ptl_recvq_isempty(const struct ptl *ptl);

static psm_error_t ips_tid_recv_free(struct ips_tid_recv_desc *tidrecvc);

psm_error_t
ips_protoexp_init(const psmi_context_t *context, 
		  const struct ips_proto *proto, 
		  uint32_t protoexp_flags,
		  int num_of_send_bufs,
		  int num_of_send_desc,
		  struct ips_protoexp **protoexp_o)
{
    struct ips_protoexp	*protoexp = NULL;
    uint32_t tidmtu_max;
    psm_error_t err = PSM_OK;
        
    protoexp = (struct ips_protoexp *)
	    psmi_calloc(context->ep, UNDEFINED, 1, sizeof(struct ips_protoexp));
    if (protoexp == NULL) {
	err = PSM_NO_MEMORY;
	goto fail;
    }
    *protoexp_o = protoexp;

    protoexp->ptl   = (const struct ptl *) proto->ptl;
    protoexp->proto = (struct ips_proto *) proto;
    protoexp->timerq = proto->timerq;
    protoexp->tid_flags = protoexp_flags;
    protoexp->tidflow_seed = (unsigned int) getpid();

    /* Must be initialized already */
    /* Comment out because of Klockwork scanning critical error. CQ 11/16/2012
    psmi_assert_always(proto->ep != NULL && proto->ep->mq != NULL &&
		       proto->ep->mq->rreq_pool != NULL &&
		       proto->ep->mq->sreq_pool != NULL);
    */
    psmi_assert_always(proto->timerq != NULL);
    /* Make sure pbc is at the right place before the message header */
    psmi_assert_always(sizeof(union ipath_pbc) == (size_t)
	(offsetof(struct ips_scb, ips_lrh) - offsetof(struct ips_scb, pbc)));

    /* These request pools are managed by the MQ component */
    protoexp->tid_sreq_pool = proto->ep->mq->sreq_pool;
    protoexp->tid_rreq_pool = proto->ep->mq->rreq_pool;

    if (proto->flags & IPS_PROTO_FLAG_MQ_EXPECTED_SDMA) {
      protoexp->tid_ep_flow = EP_FLOW_GO_BACK_N_DMA;
      protoexp->tid_xfer_type = PSM_TRANSFER_DMA;
    }
    else {
      protoexp->tid_ep_flow = EP_FLOW_GO_BACK_N_PIO;
      protoexp->tid_xfer_type = PSM_TRANSFER_PIO;
    }

    /* Initialze tid flow control. */
    {
      const struct ipath_user_info *user_info = &context->user_info;
      const struct ipath_base_info *base_info = &context->base_info;
      uint32_t num_flow, start_flow, end_flow;
      uint32_t has_hw_hdrsupp = (context->runtime_flags & IPATH_RUNTIME_HDRSUPP);
      
      if (!user_info->spu_subcontext_cnt || !has_hw_hdrsupp) {
	/* If no context sharing enabled can use full tidflow table for
	 * all HCAs. 
	 */
	start_flow = 0;
	num_flow = INFINIPATH_TF_NFLOWS;
      }
      else {
	/* Context sharing on QLE73XX requires hardware tidflow table to be
	 * shared as well.
	 */
	num_flow = (uint32_t) (INFINIPATH_TF_NFLOWS / user_info->spu_subcontext_cnt);
	start_flow = base_info->spi_subcontext * num_flow;
      }
      
      end_flow = start_flow + num_flow;
      
      if ((err = ips_tf_init(context, &protoexp->tfctrl,
			     start_flow, end_flow,
			     ips_tid_flowavail_callback, protoexp)))
	goto fail;
    }
    
    /* Fix the fragsize to be a power of two (usually 2048) */
    protoexp->tid_send_fragsize = context->base_info.spi_tid_maxsize;
    if (proto->flags & IPS_PROTO_FLAG_MQ_EXPECTED_SDMA)
	tidmtu_max = proto->epinfo.ep_mtu;
    else
	tidmtu_max = proto->epinfo.ep_piosize;

    while (protoexp->tid_send_fragsize > tidmtu_max)
	protoexp->tid_send_fragsize /= 2;

    if ((err = ips_tid_init(&protoexp->tidc, context)))
	goto fail;

    {
	uint32_t bounce_size, num_bounce_bufs;

	if ((protoexp->tid_xfer_type == PSM_TRANSFER_DMA) ||
	    (protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM)) {
	    num_bounce_bufs = max(8, num_of_send_bufs >> 2);
	    bounce_size = protoexp->tid_send_fragsize;
	}
	else {
	  /* no bufs, we only need the buffers to handle misalignment on the
	   * sender when using send dma. */
	  num_bounce_bufs = 0;
	  bounce_size = 0;
	}
	if ((err = ips_scbctrl_init(context, num_of_send_desc, num_bounce_bufs,
		0, bounce_size, ips_tid_scbavail_callback,
		protoexp, &protoexp->tid_scbc_rv)))
	    goto fail;
    }
    
    {
      /* Determine interval to generate headers (relevant only when header
       * suppression is enabled) else headers will always be generated.
       *
       * The PSM_EXPECTED_HEADERS environment variable can specify the
       * packet interval to generate headers at. Else a header packet is
       * generated every 
       * min(PSM_DEFAULT_EXPECTED_HEADER, window_size/tid_send_fragsize).
       * Note: A header is always generated for the last packet in the flow.
       */
      
      union psmi_envvar_val env_exp_hdr;
      uint32_t defval = 
	min(PSM_DEFAULT_EXPECTED_HEADER, 
	    proto->mq->ipath_window_rv/protoexp->tid_send_fragsize);
      
      psmi_getenv("PSM_EXPECTED_HEADERS",
		  "Interval to generate expected protocol headers",
		  PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		  (union psmi_envvar_val) defval, &env_exp_hdr);
      
      protoexp->hdr_pkt_interval = env_exp_hdr.e_uint;
      /* Account for flow credits - Should try to have atleast 4 headers
       * generated per window.
       */
      protoexp->hdr_pkt_interval = 
	max(min(protoexp->hdr_pkt_interval, proto->flow_credits >> 2), 1);
      
      if (protoexp->hdr_pkt_interval != env_exp_hdr.e_uint) {
	_IPATH_VDBG("Overriding PSM_EXPECTED_HEADERS=%u to be '%u'\n",
		    env_exp_hdr.e_uint, protoexp->hdr_pkt_interval);
      }
      
    }
    
    /* Send descriptors.
     *
     * There can be up to 2^32 of these send descriptors.  We conservatively
     * allocate 256 but large node configurations can allocate up to sdesc_num
     * of these (they are about 2k each).
     * We impose a theoretical limit of 2^30.
     */
    {
	struct psmi_rlimit_mpool rlim = TID_SENDSESSIONS_LIMITS;
	uint32_t maxsz, chunksz;

	if ((err = psmi_parse_mpool_env(protoexp->proto->mq, 1,
					   &rlim,  &maxsz, &chunksz)))
	    goto fail;
				    
	protoexp->tid_desc_send_pool =
	    psmi_mpool_create(sizeof(struct ips_tid_send_desc), chunksz, maxsz,
			      0, DESCRIPTORS, NULL, NULL);

	if (protoexp->tid_desc_send_pool == NULL) {
	    err = psmi_handle_error(proto->ep, PSM_NO_MEMORY,
			    "Couldn't allocate tid descriptor memory pool");
	    goto fail;
	}
    }

    /* Receive descriptors.
     *
     * There can only be 256 of these because the field to identify the receive
     * descriptor is only 8 bits.  This currently isn't a problem because we
     * only have 512 tids and each descriptor consumes ~32 tids per tid window.
     * This means only roughly 16 descriptors are ever used.
     */

    {
	struct psmi_rlimit_mpool rlim = TID_RECVSESSIONS_LIMITS;
	uint32_t maxsz, chunksz;

	if ((err = psmi_parse_mpool_env(protoexp->proto->mq, 1,
					   &rlim,  &maxsz, &chunksz)))
	    goto fail;
				    
	protoexp->tid_desc_recv_pool =
	    psmi_mpool_create(sizeof(struct ips_tid_recv_desc), chunksz, maxsz, 
			      0, DESCRIPTORS, ips_tid_mpool_tidrecv_callback, 
			      protoexp);

	if (protoexp->tid_desc_recv_pool == NULL) {
	    err = psmi_handle_error(proto->ep, PSM_NO_MEMORY,
		    "Couldn't allocate tid descriptor memory pool");
	    goto fail;
	}
    }

    /* This pool can never be smaller than the max number of rreqs that can be
     * allocated. */
    {
	uint32_t rreq_per_chunk, rreq_max;

	psmi_assert_always(protoexp->proto->mq->rreq_pool != NULL);

	psmi_mpool_get_obj_info(protoexp->proto->mq->rreq_pool,
				&rreq_per_chunk,
				&rreq_max);

	protoexp->tid_getreq_pool =
	    psmi_mpool_create(sizeof(struct ips_tid_get_request), 
		    rreq_per_chunk, rreq_max, 0, DESCRIPTORS, NULL, NULL);

	if (protoexp->tid_getreq_pool == NULL) {
	    err = psmi_handle_error(proto->ep, PSM_NO_MEMORY,
		"Couldn't allocate getreq descriptor memory pool");
	    goto fail;
	}
    }

    /*
     * Parse the tid timeout settings from the environment.
     * <min_timeout>:<max_timeout>:<interrupt_iters>
     *
     */
    {
	int tvals[3];
	char *tid_to;
	union psmi_envvar_val env_to;

	if (context->runtime_flags & PSMI_RUNTIME_RCVTHREAD) {
	    tvals[0] = 200;
	    tvals[1] = 1000;
	    tvals[2] = 2;
	    tid_to = "200:1000:2";
	}
	else {
	    /* This has always been the behavior ips < 2.1 */
	    tid_to = "100:100:3";
	    tvals[0] = 100;
	    tvals[1] = 100;
	    tvals[2] = 3;
	}

	if (!psmi_getenv("PSM_TID_TIMEOUT",
			 "Tid timeout control <min:max:intr_count>",
			 PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
			 (union psmi_envvar_val) tid_to,
			 &env_to)) {
	    /* not using default values */
	    tid_to = env_to.e_str;
	    psmi_parse_str_tuples(tid_to, 3, tvals);
	}
	protoexp->tid_to_cyc_min = us_2_cycles((uint64_t) tvals[0]);
	protoexp->tid_to_cyc_max = us_2_cycles((uint64_t) tvals[1]);
	protoexp->tid_to_intr = tvals[2];
	_IPATH_PRDBG("Tid control message settings: timeout min=%dus/max=%dus, "
		     "interrupt when trying attempt #%d\n",
		    tvals[0], tvals[1], tvals[2]);
    }

    /*
     * Make sure that the rendezvous window size settings are not larger than
     * the largest packet we can put on the wire.
     */
    {
	uint32_t winsize = protoexp->proto->mq->ipath_window_rv;

	if (winsize < ips_tid_page_size(&protoexp->tidc)) {
	    _IPATH_INFO("Overriding request for rndv window size %d "
			"to minimum supported value %d bytes\n",
			winsize, ips_tid_page_size(&protoexp->tidc));
	    protoexp->proto->mq->ipath_window_rv = 
		    ips_tid_page_size(&protoexp->tidc);
	}
	else { /* Figure out maximum supportable value assuming we can
		* send a maxmium payload of 2048 bytes */
	    int maxtids = 0;

	    while (PSMI_ALIGNUP((sizeof(ips_tid_session_list) +
		   ((maxtids+1) * sizeof(ips_tid_session_member))), 4) 
		    < IPS_PROTOEXP_MIN_MTU)
	    {
		maxtids++;
	    }

	    /* Assume worse-case alignment when deriving the amount of tids,
	     * need one tid for bad page-alignment and another for spillover
	     * into last page */
	    winsize = (maxtids-2) * ips_tid_page_size(&protoexp->tidc);

	    if (protoexp->proto->mq->ipath_window_rv > winsize) {
		_IPATH_INFO("Overriding request for rndv window size %d "
			    "to maximum supported value %d bytes\n",
			    protoexp->proto->mq->ipath_window_rv,
			    winsize);
		protoexp->proto->mq->ipath_window_rv = winsize;
	    }
	}
    }

    /*
     * Allow setting of PSM_TID_MIN_EXPSEND, the minimum amount of expected
     * send packets we send before checking the receive queue.
     */
    {
	union psmi_envvar_val env_mincnt;

	psmi_getenv("PSM_TID_MIN_EXPSEND",
		    "Min expsend pkt cnt before recv",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val) 3, &env_mincnt);
	protoexp->tid_min_expsend_cnt = env_mincnt.e_uint;
    }

    /* Timers to handle requeueing of work out of the receive path */
    psmi_timer_entry_init(&protoexp->timer_send,
			 ips_tid_pendsend_timer_callback, protoexp);
    STAILQ_INIT(&protoexp->pend_sendq);
    psmi_timer_entry_init(&protoexp->timer_getreqs,
			 ips_tid_pendtids_timer_callback, protoexp);
    STAILQ_INIT(&protoexp->pend_getreqsq);

    protoexp->tid_page_offset_mask = 
	(uint32_t) context->base_info.spi_tid_maxsize - 1;
    protoexp->tid_page_mask =  
	~((uint64_t) context->base_info.spi_tid_maxsize - 1);

    if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) {
	protoexp->tid_info = (struct ips_tidinfo *)
	    psmi_calloc(context->ep, UNDEFINED, IPS_TID_MAX_TIDS, 
			sizeof (struct ips_tidinfo));
	if (protoexp->tid_info == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
    }
    else
	protoexp->tid_info = NULL;

    psmi_assert(err == PSM_OK);
    return err;

fail:
    if (protoexp != NULL && protoexp->tid_getreq_pool != NULL)
	psmi_mpool_destroy(protoexp->tid_getreq_pool);
    if (protoexp != NULL && protoexp->tid_desc_recv_pool != NULL)
	psmi_mpool_destroy(protoexp->tid_desc_recv_pool);
    if (protoexp != NULL && protoexp->tid_desc_send_pool != NULL)
	psmi_mpool_destroy(protoexp->tid_desc_send_pool);
    if (protoexp != NULL)
	ips_scbctrl_fini(&protoexp->tid_scbc_rv);
    if (protoexp != NULL)
	psmi_free(protoexp);
    return err;
}

psm_error_t 
ips_protoexp_fini(struct ips_protoexp *protoexp)
{
    psm_error_t err = PSM_OK;

    psmi_mpool_destroy(protoexp->tid_getreq_pool);
    psmi_mpool_destroy(protoexp->tid_desc_recv_pool);
    psmi_mpool_destroy(protoexp->tid_desc_send_pool);

    if ((err = ips_scbctrl_fini(&protoexp->tid_scbc_rv)))
	goto fail;

    if ((err = ips_tid_fini(&protoexp->tidc)))
	goto fail;
    
    if ((err = ips_tf_fini(&protoexp->tfctrl)))
      goto fail;
    
    _IPATH_PRDBG("Tid control resends: tid_grant=%lld,tid_release=%lld,"
		 "request_intr=%lld\n",
		(long long) protoexp->tid_grant_resends,
		(long long) protoexp->tid_release_resends,
		(long long) protoexp->tid_intr_reqs);

    if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG)
	psmi_free(protoexp->tid_info);

    psmi_free(protoexp);

fail:
    return err;
}

/* New scbs now available.  If we have pending sends because we were out of
 * scbs, put the pendq on the timerq so it can be processed. */
static
void
ips_tid_scbavail_callback(struct ips_scbctrl *scbc, void *context)
{
    struct ips_protoexp *protoexp = (struct ips_protoexp *) context;

    if (!STAILQ_EMPTY(&protoexp->pend_sendq))
	psmi_timer_request(protoexp->timerq, 
			  &protoexp->timer_send, PSMI_TIMER_PRIO_1);
    return;
}

/* New Tid Flows are available. If there are pending get requests put the
 * get timer on the timerq so it can be processed. */
static
void
ips_tid_flowavail_callback(struct ips_tfctrl *tfctrl, void *context)
{
  struct ips_protoexp *protoexp = (struct ips_protoexp *) context;

  if (!STAILQ_EMPTY(&protoexp->pend_getreqsq))
    psmi_timer_request(protoexp->timerq,
		       &protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);
  return;
}

/*
 * The tid get request is always issued from within the receive progress loop,
 * which is why we always enqueue the request instead of issuing it directly.
 * Eventually, if we expose tid_get to users, we will want to differentiate
 * when the request comes from the receive progress loop from cases where the
 * tid_get is issued directly from user code.
 *
 */
psm_error_t
ips_protoexp_tid_get_from_token(
	    struct ips_protoexp *protoexp,
	    void		*buf,
	    uint32_t		 length,
	    psm_epaddr_t	 epaddr,
	    uint32_t		 remote_tok,
	    uint32_t		 flags,
	    ips_tid_completion_callback_t callback,
	    void			  *context)
{
    struct ips_tid_get_request *getreq;
    int count, fragsize;

    getreq = (struct ips_tid_get_request *) 
	     psmi_mpool_get(protoexp->tid_getreq_pool);

    /* We can't *really* run out of these here because we always allocate as
     * much as available receive reqs */
    if_pf (getreq == NULL) 
	psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
	    "Ran out of 'getreq' descriptors");

    getreq->tidgr_protoexp  = protoexp;
    getreq->tidgr_epaddr    = epaddr;
    getreq->tidgr_lbuf	    = buf;
    getreq->tidgr_length    = length;
    getreq->tidgr_sendtoken = remote_tok;
    getreq->tidgr_ucontext  = context;
    getreq->tidgr_callback  = callback;
    getreq->tidgr_offset    = 0;
    getreq->tidgr_bytesdone = 0;
    getreq->tidgr_desc_seqno= 0;
    getreq->tidgr_flags     = flags; 

    /* nsconn is the # of slave channels. */
    /* fragsize is the bytes each channel should transfer. */
    count = epaddr->mctxt_master->mctxt_nsconn;
    fragsize = (length+count)/(count+1);
    if (fragsize < 4096) fragsize = 4096;
    getreq->tidgr_rndv_winsz= min(fragsize, epaddr->ep->mq->ipath_window_rv);

    STAILQ_INSERT_TAIL(&protoexp->pend_getreqsq, getreq, tidgr_next);
    if (ips_tid_num_available(&protoexp->tidc) >=
	    ips_tid_num_required(&protoexp->tidc, (void *) NULL,
		getreq->tidgr_rndv_winsz))
	ips_tid_pendtids_timer_callback(&protoexp->timer_getreqs, 0);
    else
	psmi_timer_request(protoexp->timerq, &protoexp->timer_getreqs, 
		      PSMI_TIMER_PRIO_1);
    return PSM_OK;
}

/* List of perf events */
#define _ips_logeventid_tid_send_reqs	0   /* out of tid send descriptors */

#define ips_logevent_id(event)	 _ips_logeventid_ ## event
#define ips_logevent(proto, event,ptr) ips_logevent_inner(proto, ips_logevent_id(event), ptr)

static
void
ips_logevent_inner(struct ips_proto *proto, int eventid, void *context)
{
    uint64_t t_now = get_cycles();

    switch (eventid) {
	case ips_logevent_id(tid_send_reqs): {
	    ips_epaddr_t *ipsaddr = (ips_epaddr_t *) context;
	    proto->psmi_logevent_tid_send_reqs.count++;

	    if (t_now >= proto->psmi_logevent_tid_send_reqs.next_warning) {
		psmi_handle_error(PSMI_EP_LOGEVENT, PSM_OK,
		    "Non-fatal temporary exhaustion of send tid dma descriptors "
		    "(elapsed=%.3fs, source LID=0x%x/context=%d, count=%lld)", 
		    (double) cycles_to_nanosecs(t_now - ipsaddr->proto->t_init) / 1.0e9,
		    (int) psm_epid_nid(ipsaddr->epaddr->epid), 
		    (int) psm_epid_context(ipsaddr->epaddr->epid),
		    (long long) proto->psmi_logevent_tid_send_reqs.count);
		proto->psmi_logevent_tid_send_reqs.next_warning = t_now + 
		    sec_2_cycles(proto->psmi_logevent_tid_send_reqs.interval_secs);
	    }
	}
	break;

	default:
	    break;
    }

    return;
}

/*
 * Expected Protocol.
 *
 * We're granted tids (as part of a tid get request) and expected to fulfill
 * the request by associating the request's sendtoken to a tid send descriptor.
 *
 * It's possible to be out of tid send descriptors when somehow all allocated
 * descriptors can't complete all of their sends.  For example, the targets of
 * the sends may be busy in computation loops and not processing incoming
 * packets.
 */

void __fastpath 
ips_protoexp_tid_grant(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    ips_tid_session_list *tid_list;
    ips_epaddr_t *ipsaddr = rcv_ev->ipsaddr;
    uint32_t paylen, msglen;
    uint32_t reqidx;
    psmi_seqnum_t flowgenseq;
    psm_error_t err = PSM_OK;
    psm_mq_req_t req;
    ptl_arg_t args[3];
    uint8_t index, seqno;

    paylen   = ips_recvhdrq_event_paylen(rcv_ev);
    tid_list = (ips_tid_session_list *) ips_recvhdrq_event_payload(rcv_ev);
    reqidx   = p_hdr->data[0].u32w0;
    msglen   = p_hdr->data[0].u32w1;
    flowgenseq.val = p_hdr->data[1].u32w0;
    
    /* Increment grant received stats for endpoint */
    ipsaddr->stats.tids_grant_recv++;
    index = tid_list->tsess_seqno % sizeof(req->tid_grant);
    seqno = tid_list->tsess_seqno / sizeof(req->tid_grant);

    req = psmi_mpool_find_obj_by_index(protoexp->tid_sreq_pool, reqidx);

    if (req) {
    _IPATH_VDBG("req=%p (%d) wait=%s req_seqno=%d pkt_len=%d, seqno=%d, msglen=%d\n", 
	req, reqidx, req->type & MQE_TYPE_WAITING ? "yes" : "no", 
	req->recv_msgoff, paylen, tid_list->tsess_seqno, msglen);
    }

    /* We use recv_msgoff to track the latest receive sequence number */

    if (req == NULL) {
	/* Not found, bogus req, ack it anyway */
    }
    else if (seqno < req->tid_grant[index]) {
	/* dupe, ack it */
    }
    else if (seqno > req->tid_grant[index]) {
	/* lost tidreq, wait for rexmit */
	/* XXX count this to see if it's worth handling instead of dropping */
	goto no_ack;
    }
    else {
	req->tid_grant[index]++;
	/* Safe to keep updating every time */
	req->send_msglen = msglen;
	if ((err = ips_tid_send_handle_tidreq(protoexp, req, msglen, 0, ipsaddr, flowgenseq, tid_list, paylen)) != PSM_OK)
        {
	    ips_logevent(rcv_ev->proto, tid_send_reqs, ipsaddr);
	    /* Out of send reqs, wait for rexmit */
	    goto no_ack;
	}
	req->recv_msgoff = tid_list->tsess_seqno + 1;
	rcv_ev->proto->psmi_logevent_tid_send_reqs.next_warning = 0;
    }

    /* At this point we can ack the request */
    args[0]	  = tid_list->tsess_descid;

    ips_proto_send_ctrl_message(&ipsaddr->flows[protoexp->tid_ep_flow], 
				OPCODE_TIDS_GRANT_ACK,
				&ipsaddr->ctrl_msg_queued, args);

no_ack:
    return; 
}

void __fastpath 
ips_protoexp_tid_grant_ack(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    struct ips_tid_recv_desc *tidrecvc;
    ptl_arg_t desc_id = p_hdr->data[0];
    ptl_arg_t desc_tidrecvc;

    tidrecvc = (struct ips_tid_recv_desc *)
		psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool, 
					     desc_id._desc_idx);

    if (tidrecvc == NULL) /* dupe or gone, drop it */
	return;

    psmi_mpool_get_obj_index_gen_count(tidrecvc, 
					&desc_tidrecvc._desc_idx, 
					&desc_tidrecvc._desc_genc);

    _IPATH_VDBG("desc_req:id=%d,gen=%d desc_tidc:id=%d,gen=%d\n", 
		    desc_id._desc_idx, desc_id._desc_genc,
		    desc_tidrecvc._desc_idx, desc_tidrecvc._desc_genc);

    if (desc_tidrecvc.u64 == desc_id.u64 && 
	tidrecvc->state == TIDRECVC_STATE_GRANT) 
    {
	psmi_timer_cancel(protoexp->timerq, &tidrecvc->timer_tidreq);
	tidrecvc->state = TIDRECVC_STATE_GRANT_ACK;
    }
    return;
}

void
__fastpath
ips_protoexp_recv_unaligned_data(struct ips_recvhdrq_event *rcv_ev)
{
  
  struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
  struct ips_message_header *p_hdr = rcv_ev->p_hdr;
  struct ptl_epaddr *ipsaddr = rcv_ev->ipsaddr;
  uint32_t tid_recv_sessid;
  struct ips_tid_recv_desc *tidrecvc;
  ptl_arg_t desc_id = rcv_ev->p_hdr->data[0];
  int i;
  uint8_t *byte_index = (uint8_t *) &p_hdr->data[1].u32w0;
  uint8_t *buffer;

  if (!ips_proto_is_expected_or_nak(rcv_ev)) goto process_ack;

  psmi_assert(p_hdr->flags & (IPS_SEND_FLAG_UNALIGNED_DATA | IPS_SEND_FLAG_ACK_REQ));
  
  tid_recv_sessid = desc_id._desc_idx;
  tidrecvc = 
    psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
				 tid_recv_sessid);
    
  if_pf (tidrecvc == NULL) {
    _IPATH_ERROR("No tidrecv session with index %d\n",
		 tid_recv_sessid);
    goto process_ack;
  }
  
  if_pf (psmi_mpool_get_obj_gen_count(tidrecvc) != desc_id._desc_genc) {
    _IPATH_ERROR("Expected packet to tid session %d, now %d instead "
		 "of %d; skipping\n", tid_recv_sessid,
		 psmi_mpool_get_obj_gen_count(tidrecvc), 
		 desc_id._desc_genc);
      goto process_ack; /* skip */
  }
  
  psmi_assert(p_hdr->hdr_dlen == 
	      (tidrecvc->tid_list.tsess_unaligned_start + tidrecvc->tid_list.tsess_unaligned_end));

  /* Cancel tid grant timer (if still active) */
  if (tidrecvc->num_recv_hdrs++ == 0)
    psmi_timer_cancel(protoexp->timerq, &tidrecvc->timer_tidreq);

  buffer = tidrecvc->buffer;
  for (i = 0; i < tidrecvc->tid_list.tsess_unaligned_start; i++)
    *buffer++ = *byte_index++;

  buffer =
    (uint8_t *) tidrecvc->buffer + tidrecvc->recv_msglen -
    tidrecvc->tid_list.tsess_unaligned_end;
  byte_index = (uint8_t *)&p_hdr->data[1].u32w1;
  
  for (i = 0; i < tidrecvc->tid_list.tsess_unaligned_end; i++)
    *buffer++ = *byte_index++;
  
  /* If packet has checksum for window cache it */
  if (p_hdr->flags & IPS_SEND_FLAG_HAS_CKSUM) {
    uint32_t *cksum = (uint32_t*) ips_recvhdrq_event_payload(rcv_ev);
    
    psmi_assert_always(protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM);
    psmi_assert_always(ips_recvhdrq_event_payload(rcv_ev));
    psmi_assert_always(ips_recvhdrq_event_paylen(rcv_ev));
    tidrecvc->cksum = *cksum;
  }
 
process_ack:
  ips_proto_process_ack(rcv_ev);
  /* May require ACK for this packet. */
  if (p_hdr->flags & IPS_SEND_FLAG_ACK_REQ)
    ips_proto_send_ack((struct ips_recvhdrq *) rcv_ev->recvq,
		&ipsaddr->flows[ips_proto_flowid(p_hdr)]);

  return;
}

void
__fastpath 
ips_protoexp_data(struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    uint32_t tid_recv_sessid;
    struct ips_tid_recv_desc *tidrecvc;
    ptl_arg_t desc_id = rcv_ev->p_hdr->data[0];
    ptl_arg_t send_descid = rcv_ev->p_hdr->data[1];
    uint32_t paylen;
    psmi_seqnum_t sequence_num, expected_sequence_num;
    uint32_t has_hw_hdrsupp = (protoexp->ptl->context->runtime_flags & IPATH_RUNTIME_HDRSUPP);
    ptl_arg_t args[3];
    
    paylen = ips_recvhdrq_event_paylen(rcv_ev);
    tid_recv_sessid = desc_id._desc_idx;
    tidrecvc = 
      psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
				   tid_recv_sessid);
    
    if_pf (tidrecvc == NULL) {
      _IPATH_ERROR("No tidrecv session with index %d\n",
		   tid_recv_sessid);
      return;
    }

    if_pf (rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER && paylen != 0) {
      _IPATH_ERROR("Expected packet, but eager index is set; skipping\n");
      return;
    }

    if_pf (psmi_mpool_get_obj_gen_count(tidrecvc) != desc_id._desc_genc) {
      _IPATH_ERROR("Expected packet to tid session %d, now %d instead "
		   "of %d; skipping\n", tid_recv_sessid,
		   psmi_mpool_get_obj_gen_count(tidrecvc), 
		   desc_id._desc_genc);
      return; /* skip */
    }
    
    sequence_num.val = __be32_to_cpu(p_hdr->bth[2]);
    expected_sequence_num = tidrecvc->tidflow_genseq;
    
    /* On QLE73XX this is only called if data was fully received or the ACK
     * interval was reached else the gen/seq error handlers are called 
     * from ips_proto_recv.
     */
    if (has_hw_hdrsupp) {      
      
      /* Drop packet if generation number does not match */
      if (expected_sequence_num.gen != sequence_num.gen) 
	return;
      
      /* Increment the expected sequence number taking into account the number
       * of headers that were suppressed. 
       */
      expected_sequence_num.seq += (protoexp->hdr_pkt_interval - 1);
      
      /* Special case for last packet as may be lesser than interval. */
      if (p_hdr->flags & IPS_SEND_FLAG_EXPECTED_DONE)
	expected_sequence_num = sequence_num;
      
      /* TIDFLOW will restart in the if block below */
      if_pf (sequence_num.psn != expected_sequence_num.psn) { 
	_IPATH_EPDBG("Expected: Packet PSN %d received and were expecting %d. Restarting flow.\n", sequence_num.psn, expected_sequence_num.psn);
      }
      
    }
    
    /* IBTA CCA handling for expected flow. */
    if (rcv_ev->is_congested & IPS_RECV_EVENT_FECN) {
      /* Mark flow to generate BECN in control packet */
      tidrecvc->ipsaddr->tidgr_flow.flags |= IPS_FLOW_FLAG_GEN_BECN;
      /* Update stats for congestion encountered */
      rcv_ev->ipsaddr->stats.congestion_pkts++;
      /* Clear FECN event */
      rcv_ev->is_congested &= ~IPS_RECV_EVENT_FECN;
    }

    if_pf (sequence_num.psn != expected_sequence_num.psn) {
      psmi_assert(sequence_num.flow == tidrecvc->tidflow_idx);
      psmi_assert(sequence_num.flow == tidrecvc->tidflow_genseq.flow);

      /* Generation mismatch */
      if (sequence_num.gen != tidrecvc->tidflow_genseq.gen)
	return ips_protoexp_handle_tf_generr(rcv_ev);
      
      /* Sequence mismatch error */
      return ips_protoexp_handle_tf_seqerr(rcv_ev);
    }
    else { 
      
      /* Update the shadow tidflow_genseq */
      tidrecvc->tidflow_genseq.seq = sequence_num.seq + 1;
      
      /* On QLE71XX/QLE72XX update tidflow table in software */
      if (!has_hw_hdrsupp) 
	ipath_tidflow_set_entry(tidrecvc->context->ctrl,
				tidrecvc->tidflow_idx,
				tidrecvc->tidflow_genseq.gen,
				tidrecvc->tidflow_genseq.seq); 
      
      /* Reset the swapped generation count as we received a valid packet */
      tidrecvc->tidflow_nswap_gen = 0;
    }
    
    /* Do some sanity checking */
    psmi_assert_always(((__be32_to_cpu(rcv_ev->p_hdr->bth[0]) >> 20) & 3) == 0);
    psmi_assert_always(tidrecvc->state  != TIDRECVC_STATE_DONE);
    
    /* If first packet received cancel tid grant timer */
    if (tidrecvc->num_recv_hdrs++ == 0)
      psmi_timer_cancel(protoexp->timerq, &tidrecvc->timer_tidreq);
    
    /* If last packet we can close the tidflow.
     * We can deallocate tidflow even if the unaligned data has not been
     * received. The TID_RELEASE message will deallocate the receive 
     * descriptor.
     *
     * Note: If we were out of tidflows this will invoke the callback to 
     * schedule pending transfers.
     */

    if (p_hdr->flags & IPS_SEND_FLAG_EXPECTED_DONE) {
      
      psm_error_t ret = PSM_OK;
      
      /* Acquire lock before updating state (ERR_CHK_GEN also tests for
       * state before responding.
       */
      
      ips_ptladdr_lock(rcv_ev->ipsaddr);
      
      /* Mark receive as done */
      tidrecvc->state = TIDRECVC_STATE_DONE;
      
      ret = ips_tf_deallocate(&protoexp->tfctrl,
			      tidrecvc->tidflow_idx);
      psmi_assert_always (ret == PSM_OK);
      
      /* Release lock */
      ips_ptladdr_unlock(rcv_ev->ipsaddr);
    }
    
    /* Respond with an ACK if sender requested one or incoming flow faced
     * congestion. The ACK in this case will have the BECN bit set. 
     */
    if ((p_hdr->flags & IPS_SEND_FLAG_ACK_REQ) ||
	(tidrecvc->ipsaddr->tidgr_flow.flags & IPS_FLOW_FLAG_GEN_BECN)) {
      
      /* Ack sender with descriptor index */
      args[0] = send_descid;
      args[1] = tidrecvc->tid_list.tsess_descid;
      
      ips_proto_send_ctrl_message(&tidrecvc->ipsaddr->tidgr_flow,
				  OPCODE_ACK,
				  &tidrecvc->ctrl_msg_queued, args);
    }
    
    return;
}

#ifndef PSM_DEBUG
#  define ips_dump_tids(tid_list,msg,...)
#else
static
void
ips_dump_tids(ips_tid_session_list *tid_list, const char *msg, ...)
{
    char buf[256];
    size_t off = 0;
    int i, num_tids = tid_list->tsess_tidcount;

    va_list argptr;
    va_start(argptr, msg);
      off += vsnprintf(buf, sizeof buf - off, msg, argptr);
    va_end(argptr);

    for (i = 0; i < num_tids && off < (sizeof buf - 1); i++) 
	off += snprintf(buf + off, sizeof buf - off, "%d%s", 
	    (int) tid_list->tsess_list[i].tid, 
	    i < num_tids-1 ? "," : "");

    _IPATH_VDBG("%s\n", buf);
    return;
}
#endif

static
void
ips_expsend_tiderr(struct ips_tid_send_desc *tidsendc)
{
    char buf[256];
    size_t off = 0;
    int i;

    off += snprintf(buf + off, sizeof buf - off,
		    "Remaining bytes: %d Member id %d is not in tid_session_id=%d :", tidsendc->remaining_bytes, tidsendc->tid_idx, 
	     tidsendc->tid_list.tsess_descid._desc_idx);

    for (i = 0; i < tidsendc->tid_list.tsess_tidcount+1; i++) 
	off += snprintf(buf + off, sizeof buf - off, "%d,", 
			    tidsendc->tid_list.tsess_list[i].tid);
    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
	"Trying to use tid idx %d and there are %d members: %s\n",
	tidsendc->tid_idx, tidsendc->tid_list.tsess_tidcount, buf);
    return;
}

void	    
ips_protoexp_scb_inflight(ips_scb_t *scb)
{
    if (scb->tidsendc)
	scb->tidsendc->iovec_cntr_last = scb->dma_ctr;
    return;
}

static 
void __fastpath
ips_tid_send_tid_release_msg(struct ips_tid_send_desc *tidsendc)
{
  psm_error_t err;
  struct ips_protoexp *protoexp = tidsendc->protoexp;
  psm_mq_req_t req = tidsendc->mqreq;
  ptl_arg_t desc_id[3] = {};
  uint64_t t_cyc;
  
  desc_id[0] = tidsendc->tid_list.tsess_descid;
  desc_id[1] = tidsendc->descid;
  desc_id[2].u32w0 = tidsendc->release_cnt;
  
  err = ips_proto_send_ctrl_message(&tidsendc->ipsaddr->
				    flows[protoexp->tid_ep_flow],
				    OPCODE_TIDS_RELEASE,
				    &tidsendc->ctrl_msg_queued,
				    desc_id);
  
  if (err != PSM_EP_NO_RESOURCES) {
    tidsendc->release_cnt++;
    t_cyc = get_cycles() + protoexp->tid_to_cyc_min;
  }
  else
    t_cyc = get_cycles() + protoexp->proto->timeout_send;
  
  psmi_timer_request_always(protoexp->timerq, &tidsendc->timer_tidrelease, 
			    t_cyc);

  req->send_msgoff += tidsendc->length;
  
  _IPATH_VDBG("[rndv][send] tid chunk of size %d done %d/%d for req=%p%s\n", 
	      tidsendc->length, req->send_msgoff, req->send_msglen, req,
	      req->send_msgoff == req->send_msglen ? " (complete)" : "");
  
  if (req->send_msgoff == req->send_msglen) 
    psmi_mq_handle_rts_complete(req);
}

static
int __fastpath 
ips_tid_send_completion_unaligned_callback(void * param, uint32_t nbytes)
{
  struct ips_tid_send_desc *tidsendc = (struct ips_tid_send_desc *) param;
  
  /* Decrement completion counter and complete if unaligned data sent */
  tidsendc->completion_counter--;
  
  psmi_assert(tidsendc->completion_counter >= 0);
  
  if (tidsendc->completion_counter == 0)
    ips_tid_send_tid_release_msg(tidsendc);
  
  return IPS_RECVHDRQ_CONTINUE;
}

static
int __fastpath 
ips_tid_send_completion_callback(void * param, uint32_t nbytes)
{
    struct ips_tid_send_desc *tidsendc = (struct ips_tid_send_desc *) param;
    struct ips_protoexp *protoexp = tidsendc->protoexp;
    
    if (protoexp->tid_xfer_type == PSM_TRANSFER_DMA)
	ips_proto_dma_wait_until(protoexp->proto, tidsendc->iovec_cntr_last);

    if (tidsendc->bounce_buf) psmi_free(tidsendc->bounce_buf);

    /* Decrement completion counter and complete if unaligned data sent */
    tidsendc->completion_counter--;
    
    psmi_assert(tidsendc->completion_counter >= 0);
    
    if (tidsendc->completion_counter == 0)
      ips_tid_send_tid_release_msg(tidsendc);
    
    return IPS_RECVHDRQ_CONTINUE;
}

static 
psm_error_t  __fastpath
ips_tid_release_timer_callback(struct psmi_timer *timer, uint64_t current)
{
    struct ips_tid_send_desc *tidsendc = 
	(struct ips_tid_send_desc *) timer->context;
    struct ips_protoexp *protoexp = tidsendc->protoexp;
    uint64_t t_cyc;
    psm_error_t err;
    ptl_arg_t desc_id[3] = {};

    /* 0 contain's the receiver's desc_id, 1 contains the sender's desc_id */
    desc_id[0] = tidsendc->tid_list.tsess_descid;
    desc_id[1] = tidsendc->descid;
    desc_id[2].u32w0 = tidsendc->release_cnt;

    err = ips_proto_send_ctrl_message(&tidsendc->ipsaddr->
				      flows[protoexp->tid_ep_flow],
				      OPCODE_TIDS_RELEASE,
				      &tidsendc->ctrl_msg_queued,
				      desc_id);
    
    if (err == PSM_EP_NO_RESOURCES) {
	t_cyc = get_cycles() + protoexp->proto->timeout_send;
    }
    else {
	tidsendc->release_cnt++;
	protoexp->tid_release_resends++;
	t_cyc = get_cycles() +
		min(tidsendc->release_cnt * protoexp->tid_to_cyc_min,
		    protoexp->tid_to_cyc_max);
    }

    psmi_timer_request_always(protoexp->timerq, 
			     &tidsendc->timer_tidrelease, 
			     t_cyc);
    
    return PSM_OK;
}

static 
psm_error_t __fastpath
ips_tid_grant_timer_callback(struct psmi_timer *timer, uint64_t current)
{
    struct ips_tid_recv_desc *tidrecvc = 
	(struct ips_tid_recv_desc *) timer->context;
    struct ips_protoexp *protoexp = tidrecvc->protoexp;
    ips_epaddr_t *ipsaddr = tidrecvc->ipsaddr;
    psm_error_t err;
    uint64_t t_cyc;

    err = ips_proto_send_ctrl_message(&ipsaddr->flows[protoexp->tid_ep_flow], 
				      OPCODE_TIDS_GRANT,
				      &tidrecvc->ctrl_msg_queued, 
				      &tidrecvc->tid_list);
    
    if (err == PSM_EP_NO_RESOURCES) {
	t_cyc = get_cycles() + protoexp->proto->timeout_send;
    }
    else {
	tidrecvc->grant_cnt++;
	protoexp->tid_grant_resends++;
	t_cyc = get_cycles() +
		min(tidrecvc->grant_cnt * protoexp->tid_to_cyc_min,
		    protoexp->tid_to_cyc_max);
    }

    psmi_timer_request_always(protoexp->timerq, timer, t_cyc);

    return PSM_OK;
}

static
__fastpath
psm_error_t
ips_tid_send_handle_tidreq(struct ips_protoexp *protoexp, 
		      psm_mq_req_t req, uint32_t msglen,
		      int flags, ptl_epaddr_t *ipsaddr,
		      psmi_seqnum_t flowgenseq,
		      ips_tid_session_list *tid_list, 
		      uint32_t tid_list_size)
{
    struct ips_tid_send_desc *tidsendc;
    req->send_msglen = msglen;

    psmi_assert(tid_list_size >= sizeof(ips_tid_session_list));
    psmi_assert(tid_list_size <= 2096);

    tidsendc = (struct ips_tid_send_desc *)
		psmi_mpool_get(protoexp->tid_desc_send_pool);
    if (tidsendc == NULL) 
	return PSM_EP_NO_RESOURCES;

    tidsendc->protoexp = protoexp;

    /* Uniquely identify this send descriptor in space and time */
    tidsendc->descid._desc_idx  = psmi_mpool_get_obj_index(tidsendc);
    tidsendc->descid._desc_genc = psmi_mpool_get_obj_gen_count(tidsendc);

    psmi_mq_mtucpy(&tidsendc->tid_list, tid_list, tid_list_size);
    tid_list = &tidsendc->tid_list;

    tidsendc->length   = tid_list->tsess_length;
    tidsendc->ipsaddr   = ipsaddr;
    tidsendc->mqreq    = req;
    tidsendc->bounce_buf = NULL;
    tidsendc->buffer     =
	    (void *)((uintptr_t)req->buf + tid_list->tsess_srcoff);
    tidsendc->tid_idx    = 0;
    tidsendc->is_complete= 0;
    tidsendc->release_cnt= 0;

    /* Initialize tidflow for window. Use path requested by remote endpoint */
    ips_flow_init(&tidsendc->tidflow, NULL, ipsaddr, protoexp->tid_xfer_type,
		  PSM_PROTOCOL_TIDFLOW, IPS_PATH_LOW_PRIORITY, 0);
    
    tidsendc->tidflow.xmit_seq_num = flowgenseq;
    tidsendc->tidflow.xmit_ack_num = flowgenseq;
    tidsendc->tidflow.xmit_ack_num.seq--; /* last acked */
    tidsendc->ctrl_msg_queued = 0;
    tidsendc->completion_counter = 1;
    
    /* If unaligned data will need to send a separate packet containing 
     * unaligned data.
     */
    if ((tidsendc->tid_list.tsess_unaligned_start) ||
	(tidsendc->tid_list.tsess_unaligned_end) ||
	(protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM))
      tidsendc->completion_counter += 1;
    
    if (tid_list->tsess_tidcount == 0) {
	_IPATH_VDBG("no tids used, alloc eager tid\n");
	tid_list->tsess_list[0].tid = IPATH_EAGER_TID_ID;
	tid_list->tsess_list[0].length = 0;
	tid_list->tsess_list[0].offset = 0;
    }

    tidsendc->frame_send = 0;
    tidsendc->remaining_bytes = tid_list->tsess_length;
    tidsendc->remaining_bytes_in_page = 
			   tid_list->tsess_list[0].length;
    tidsendc->offset     = tid_list->tsess_list[0].offset;
    tidsendc->unaligned_sent = 0;
    
    psmi_timer_entry_init(&tidsendc->timer_tidrelease,
			 ips_tid_release_timer_callback, tidsendc);

    _IPATH_EXP("alloc tidsend=%4d tidrecv=%4d srcoff=%6d length=%6d,s=%d,e=%d\n",
	    tidsendc->descid._desc_idx, tid_list->tsess_descid._desc_idx,
	    tid_list->tsess_srcoff, tid_list->tsess_length,
	    tid_list->tsess_unaligned_start,
	    tid_list->tsess_unaligned_end
	    );

    /* We have no tids, we're expected to stuff everything in user
     * header words, so mark it as an eager packet */
    if (tid_list->tsess_tidcount > 0) {
	ips_dump_tids(&tidsendc->tid_list, 
		"Received %d tids: ", tidsendc->tid_list.tsess_tidcount);
    }

    /* Add as a pending op and ring up the timer */
    STAILQ_INSERT_TAIL(&protoexp->pend_sendq, tidsendc, next);
    psmi_timer_request(protoexp->timerq, &protoexp->timer_send, PSMI_TIMER_PRIO_1);

    /* Consider breaking out of progress engine here */
    return PSM_OK;
}

void __fastpath 
ips_protoexp_tid_release_ack(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_tid_send_desc *tidsendc;
    ptl_arg_t desc_id = rcv_ev->p_hdr->data[1];

    tidsendc = (struct ips_tid_send_desc *)
		psmi_mpool_find_obj_by_index(protoexp->tid_desc_send_pool, 
					     desc_id._desc_idx);
    _IPATH_VDBG("desc_id=%d (%p)\n", desc_id._desc_idx, tidsendc);
    if (tidsendc == NULL) {
	_IPATH_ERROR("OPCODE_TIDS_RELEASE_CONFIRM ERROR: Index %d is out of range\n", 
			desc_id._desc_idx);
    }
    else {
	ptl_arg_t desc_tidsendc;
	psmi_mpool_get_obj_index_gen_count(tidsendc, 
					   &desc_tidsendc._desc_idx, 
					   &desc_tidsendc._desc_genc);

	_IPATH_VDBG("desc_req:id=%d,gen=%d desc_sendc:id=%d,gen=%d\n", 
		    desc_id._desc_idx, desc_id._desc_genc,
		    desc_tidsendc._desc_idx, desc_tidsendc._desc_genc);

	/* See if the reference is still live and valid */
	if (desc_tidsendc.u64 == desc_id.u64) {
	    psmi_timer_cancel(protoexp->timerq, &tidsendc->timer_tidrelease);
	    psmi_timer_cancel(rcv_ev->proto->timerq,
			      &tidsendc->tidflow.timer_send);
	    psmi_timer_cancel(rcv_ev->proto->timerq,
			      &tidsendc->tidflow.timer_ack);
	    psmi_mpool_put(tidsendc);
	}
    }
    return;
}

static
psm_error_t __fastpath
ips_scb_send_unaligned_data(ips_scb_t *scb)
{
  struct ips_tid_send_desc *tidsendc = scb->tidsendc;
  struct ips_protoexp *protoexp = tidsendc->protoexp;
  uint8_t *bufptr = tidsendc->buffer;
  int frame_extra, i;
  uint8_t *packptr;
  uint8_t *unptr_beg = bufptr;
  uint8_t *unptr_end = bufptr + tidsendc->length - 
    tidsendc->tid_list.tsess_unaligned_end;
  struct ips_flow *flow = &tidsendc->ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO];
  
  psmi_assert(tidsendc->tid_idx == 0);
  
  /* arg[0] is recv descriptor id */
  scb->ips_lrh.data[0] = tidsendc->tid_list.tsess_descid;

  if (protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM) {
    uint32_t cksum = 0xffffffff;
    
    if (!ips_scbctrl_bufalloc(scb)) {
      ips_scbctrl_free(scb);
      return PSM_EP_NO_RESOURCES;
    }
    
    cksum = ips_crc_calculate(tidsendc->length, 
			      (uint8_t*) tidsendc->buffer, cksum);
    *(uint32_t*) ips_scb_buffer(scb) =  cksum;
    ips_scb_length(scb) = sizeof(cksum);
    scb->flags |= IPS_SEND_FLAG_HAS_CKSUM;
  }
  
  // Make sure not to over read unaligned buffer
  packptr = (uint8_t *)&scb->ips_lrh.data[1].u32w0;
  for (i = 0; i < tidsendc->tid_list.tsess_unaligned_start; i++)
    packptr[i] = unptr_beg[i];
  
  packptr = (uint8_t *)&scb->ips_lrh.data[1].u32w1;
  for (i = 0; i < tidsendc->tid_list.tsess_unaligned_end; i++)
    packptr[i] = unptr_end[i];
  
  ips_scb_subopcode(scb) = OPCODE_SEQ_MQ_EXPTID_UNALIGNED;
  ips_scb_hdr_dlen(scb) = tidsendc->tid_list.tsess_unaligned_start + 
    tidsendc->tid_list.tsess_unaligned_end;
  
  ips_scb_cb(scb) = ips_tid_send_completion_unaligned_callback;
  ips_scb_cb_param(scb) = tidsendc;
  scb->flags   |= IPS_SEND_FLAG_UNALIGNED_DATA | IPS_SEND_FLAG_ACK_REQ;
  
  bufptr       += tidsendc->tid_list.tsess_unaligned_start;
  frame_extra = tidsendc->tid_list.tsess_unaligned_start + 
    tidsendc->tid_list.tsess_unaligned_end;

  
  tidsendc->remaining_bytes -= frame_extra;

  tidsendc->buffer = bufptr;

  /* Enqueue scb on the flow and flush */
  flow->fn.xfer.enqueue(flow, scb);
  flow->fn.xfer.flush(flow, NULL);
  
  return PSM_OK;
}

static 
ips_scb_t * __fastpath
ips_scb_prepare_tid_sendctrl(struct ips_flow *flow,
			     struct ips_tid_send_desc *tidsendc)
{
    struct ips_protoexp *protoexp = tidsendc->protoexp;
    uint8_t *bufptr = tidsendc->buffer;
    uint16_t frame_len, frag_size, nfrag;
    int payload_size, idx;
    ips_scb_t *scb;

    if ((scb = ips_scbctrl_alloc(&protoexp->tid_scbc_rv, 1, 0, 0)) == NULL)
	return NULL;

    /*
     * Expected sends require 4-byte alignment, so we stuff whatever
     * misalignment in the header's available user bytes.
     * 
     * In the current interface, misalignment can only occur at the
     * start or end of the packet, so we handle it as a special packet
     * before the first packet can be sent off.
     *
     * If checksum is enabled we send the checksum for the send window 
     * wiithin/as an unaligned packet as well.
     */
    
    if (tidsendc->length && 
	(tidsendc->tid_list.tsess_unaligned_start || 
	 tidsendc->tid_list.tsess_unaligned_end ||
	 (protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM)) &&
	!(tidsendc->unaligned_sent)) {      
	
      /* Send unaligned data separately over ipsaddr->flow. Completion over
       * both flows is synchronized to generate TIDS_RELEASE. The receive will
       * only finish when tid release is received. */
      scb->tidsendc = tidsendc;
      if (ips_scb_send_unaligned_data(scb) != PSM_OK)
	return NULL;
      
      /* Sent unaligned data */
      tidsendc->unaligned_sent = 1;
      
      
      /* Buffer may have been updated (unaligned start) */
      bufptr = tidsendc->buffer;
      
      /* Try to obtain another scb after sending unaligned data */
      if ((scb = ips_scbctrl_alloc(&protoexp->tid_scbc_rv, 1, 0, 0)) == NULL)
	return NULL;
    }
    
    if ((uintptr_t)bufptr & 0x3) {
	bufptr = psmi_malloc(protoexp->proto->ep,
		UNDEFINED, tidsendc->remaining_bytes);
	if (!bufptr) {
	    ips_scbctrl_free(scb);
	    return NULL;
	}

	memcpy(bufptr, tidsendc->buffer, tidsendc->remaining_bytes);
	tidsendc->buffer = tidsendc->bounce_buf = bufptr;
    }

    idx = tidsendc->tid_idx;
    scb->tidsendc     = tidsendc;
    SLIST_NEXT(scb,next) = NULL;

    scb->ips_lrh.sub_opcode = OPCODE_SEQ_MQ_EXPTID;
    scb->ips_lrh.data[0] = tidsendc->tid_list.tsess_descid;
    scb->ips_lrh.data[1] = tidsendc->descid;
    scb->tid	         = tidsendc->tid_list.tsess_list[idx].tid;
    scb->tsess		 = (void *)&tidsendc->tid_list.tsess_list[idx];
    scb->offset		 = tidsendc->offset;
    scb->payload         = (void *) bufptr;

    /*
     * Loop over the tid session list, count the frag number and payload size.
     * The payload size is limited by the pbc.length field which is 16 bits in
     * DWORD, including both message header and payload. This translates to
     * less than 256K payload. So 128K is used.
     */
    nfrag = 0;
    payload_size = 0;
    frag_size = min(protoexp->tid_send_fragsize, flow->path->epr_mtu);
    frame_len = min(tidsendc->remaining_bytes_in_page, frag_size);
    while (1) {
	nfrag++;
	payload_size += frame_len;

	/* adjust counter and pointers */
	tidsendc->remaining_bytes -= frame_len;
	tidsendc->remaining_bytes_in_page -= frame_len;
	tidsendc->offset += frame_len;

	if (!tidsendc->remaining_bytes_in_page) { 
	    /* Done with this page, move on to the next tid */
	    tidsendc->tid_idx++;
	    tidsendc->remaining_bytes_in_page = 
		tidsendc->tid_list.tsess_list[tidsendc->tid_idx].length;
	    tidsendc->offset =
		tidsendc->tid_list.tsess_list[tidsendc->tid_idx].offset;

	    /* The payload size is limited by the pbc.length field which
	     * is 16 bits in DWORD, including both message header and
	     * payload. This translates to less than 256K payload. So 128K
	     * is used. */
	    /* break when current page is done */
	    if (payload_size > 131072) break;
	}

#if 0
	if (1) {
#else
	if (flow->transfer == PSM_TRANSFER_PIO) {
#endif
	    break;	/* turn on to use single frag-size packet */
	}

	if (!tidsendc->remaining_bytes) break;
	frame_len = min(tidsendc->remaining_bytes_in_page, frag_size);
    }
    scb->nfrag = nfrag;
    scb->frag_size = frag_size;
    scb->payload_size = payload_size;
    scb->tsess_length = sizeof(ips_tid_session_member) *
				(tidsendc->tid_idx - idx);

    /* Keep track of latest buffer location so we restart at the
     * right location, if we don't complete the transfer */
    tidsendc->buffer = bufptr + payload_size;

    /* If last packet, we want a completion notification */
    if (!tidsendc->remaining_bytes) {
	scb->flags = (IPS_SEND_FLAG_ACK_REQ | IPS_SEND_FLAG_EXPECTED_DONE);
	scb->callback = ips_tid_send_completion_callback;
	scb->cb_param = tidsendc;
	
	tidsendc->is_complete = 1;
    } else {
	scb->flags = IPS_SEND_FLAG_HDR_SUPPRESS;
	scb->callback = NULL;
	scb->cb_param = NULL;
    }

#if 0
    if (1) {
#else
    if (flow->transfer == PSM_TRANSFER_PIO) {
#endif
	/* turn on to use single frag-size packet */
	/* Do not suppress header every hdr_pkt_interval or the last packet */
	if ((++tidsendc->frame_send % protoexp->hdr_pkt_interval) == 0) {
	    scb->flags &= ~IPS_SEND_FLAG_HDR_SUPPRESS;
	    scb->flags |= IPS_SEND_FLAG_ACK_REQ; /* Request an ACK */
	}
    }
 
    return scb;
}

/*
 * Returns:
 *
 * PSM_OK: scb was allocated for at least one frame, the packet may be queued
 *         or actually sent.
 *
 * PSM_OK_NO_PROGRESS: Reached a limit on the maximum number of sends we allow
 *		       to be enqueued before polling receive queue.
 *
 * PSM_EP_NO_RESOURCES: No scbs, available, a callback will be issued when more
 *                      scbs become available.
 *
 * PSM_TIMEOUT: PIO-busy or DMA-busy, stop trying to send for now.
 *
 */

psm_error_t __fastpath 
ips_tid_send_exp(struct ips_tid_send_desc *tidsendc)
{
    ips_scb_t *scb = NULL;
    psm_error_t err = PSM_OK, err_f;
    struct ips_protoexp *protoexp = tidsendc->protoexp;
    struct ips_proto *proto = protoexp->proto;
    struct ips_flow *flow = &tidsendc->tidflow;

    /*
     * We aggressively try to grab as many scbs as possible, enqueue them to a
     * flow and flush them when either we're out of scbs our we've completely
     * filled the send request.
     */
    while (!tidsendc->is_complete)
    {
	if_pf (tidsendc->tid_list.tsess_tidcount &&
	       (tidsendc->tid_idx >= tidsendc->tid_list.tsess_tidcount || 
	        tidsendc->tid_idx < 0) )
	    ips_expsend_tiderr(tidsendc);

	if ((scb = ips_scb_prepare_tid_sendctrl(flow, tidsendc)) == NULL) {
	    proto->stats.scb_exp_unavail_cnt++;
	    err = PSM_EP_NO_RESOURCES;
	    break;
	}
	else {
	  flow->fn.xfer.enqueue(flow, scb);
	}
    }

    if (!SLIST_EMPTY(&flow->scb_pend)) { /* Something to flush */
	int num_sent;
	err_f = flow->fn.xfer.flush(flow, &num_sent);

	if (err != PSM_EP_NO_RESOURCES) {
	    /* PSM_EP_NO_RESOURCES is reserved for out-of-scbs */
	    if (err_f == PSM_EP_NO_RESOURCES)
		err = PSM_TIMEOUT; /* force a resend reschedule */
	    else if (err_f == PSM_OK && num_sent > 0 && 
		     !ips_ptl_recvq_isempty(protoexp->ptl))
		err = PSM_OK_NO_PROGRESS; /* force a rcvhdrq service */
	}
    }

    return err;
}

static
psm_error_t __recvpath
ips_tid_pendsend_timer_callback(struct psmi_timer *timer, uint64_t current)
{
    struct ips_protoexp *protoexp = (struct ips_protoexp *) timer->context;
    struct ips_tid_send_pend *phead = &protoexp->pend_sendq;
    struct ips_tid_send_desc *tidsendc;
    psm_error_t err = PSM_OK;

    while (!STAILQ_EMPTY(phead)) {
	tidsendc = STAILQ_FIRST(phead);

	err = ips_tid_send_exp(tidsendc);

	if (tidsendc->is_complete)
	    STAILQ_REMOVE_HEAD(phead, next);

	if (err == PSM_OK) {
	    /* Was able to complete the send, keep going */

#if 0
	    _IPATH_EXP("tidsess=%6d tid=%4d @ %3d size=%4d offset=%4d, next=%p\n",
			tidsendc->descid.u32w0, 
			tidsendc->tid_list.tsess_list[tidsendc->tid_idx].tid,
			tidsendc->tid_idx,
			tidsendc->length,
			tidsendc->length - tidsendc->remaining_bytes,
			STAILQ_FIRST(phead)
			);
#endif
	}
	else if (err == PSM_EP_NO_RESOURCES) {
	    /* No more sendbufs available, sendbuf callback will requeue this
	     * timer */
	    break;
	}
	else if (err == PSM_TIMEOUT) {
	    /* Always a case of try later:
	     * On PIO flow, means no send pio bufs available
	     * On DMA flow, means kernel can't queue request or would have to block
	     */
	    psmi_timer_request(protoexp->proto->timerq, 
			      &protoexp->timer_send, 
			      get_cycles() + protoexp->proto->timeout_send);
	    break;
	}
	else {
	    /* Forced to reschedule later so we can check receive queue */
	    psmi_assert(err == PSM_OK_NO_PROGRESS); 
	    psmi_timer_request(protoexp->proto->timerq, 
			      &protoexp->timer_send, PSMI_TIMER_PRIO_1);
	    break;
	}
    }

    return PSM_OK;
}

// Right now, in the kernel we are allowing for virtually non-contiguous pages,
// in a single call, and we are therefore locking one page at a time, but since
// the intended use of this routine is for a single group of
// virtually contiguous pages, that should change to improve
// performance.  That means possibly changing the calling MPI code.
// Doing so gets rid of some of the loop stuff here, and in the driver,
// and allows for a single call to the core VM code in the kernel,
// rather than one per page, definitely improving performance.

static
psm_error_t __fastpath
ips_tid_recv_alloc_frag(struct ips_protoexp *protoexp,
			void *buf, uint32_t buflen, 
			ips_tid_session_list *tid_list,
			uint64_t *ts_map)
{
    uint16_t unalignment;
    uint32_t remaining_buffer_size = buflen;
    uint32_t num_tids;
    uint32_t num_tids_avail = ips_tid_num_available(&protoexp->tidc);
    uint16_t tidids[IPS_TID_MAX_TIDS]; 
    void *bufmap;
    uint8_t *bufptr = (uint8_t *) buf;
    const uint32_t page_size = ips_tid_page_size(&protoexp->tidc);
    const uint32_t page_offset_mask = protoexp->tid_page_offset_mask;
    int i;
    psm_error_t err = PSM_OK;

    /*
     * The following remaining_buffer_size calculation
     * does not work with buflen<4 and byte aligned
     * buf, it can get negative value.
     * In function ips_tid_pendtids_timer_callback(),
     * we try to avoid nbytes_this(which is buflen)
     * to be a few bytes.
     */
    if (buflen < 4) {
	tid_list->tsess_unaligned_start = buflen;
	tid_list->tsess_unaligned_end = 0;
	remaining_buffer_size = 0;
    } else {
	tid_list->tsess_unaligned_start = unalignment = 
	    ((uintptr_t) buf & 3) ? (4 - ((uintptr_t) buf & 3)) : 0;
	remaining_buffer_size -= unalignment;
	bufptr += unalignment;
			
	tid_list->tsess_unaligned_end = unalignment = 
	    remaining_buffer_size & 3;
	remaining_buffer_size -= unalignment;
    }

    bufmap = bufptr;
    psmi_assert_always(ips_tid_num_required(&protoexp->tidc, bufmap, 
	remaining_buffer_size) <= num_tids_avail);
    
    tid_list->tsess_list[0].tid = 0;
    tid_list->tsess_list[0].offset = 0;
    tid_list->tsess_list[0].length = 0;

    for (i = 0, num_tids = 0; remaining_buffer_size && i < num_tids_avail; i++) {
	uint32_t page_off = (uintptr_t) bufptr & page_offset_mask;
	uint32_t page_len = min(remaining_buffer_size, page_size - page_off);
	tid_list->tsess_list[i].offset = page_off;
	tid_list->tsess_list[i].length = page_len;
	bufptr += page_len;
	remaining_buffer_size -= page_len;
	tidids[i] = 0; /* Ensure tidids[i] is never seen as  uninitialized */
	num_tids++;
    }
    psmi_assert_always(remaining_buffer_size == 0);

    if (num_tids && 
	(err = ips_tid_acquire(&protoexp->tidc, 
			(void *) ((uintptr_t) bufmap & 
				  (uintptr_t) protoexp->tid_page_mask),
			num_tids, ts_map, tidids)))
	goto fail;

    tid_list->tsess_tidcount = num_tids;
    for (i = 0; i < num_tids; i++) 
        tid_list->tsess_list[i].tid = tidids[i];

    ips_dump_tids(tid_list, "Registered %d tids: ", num_tids);

fail:
    return err;
}

static
void
ips_tid_mpool_tidrecv_callback(void *context)
{
    struct ips_protoexp *protoexp = (struct ips_protoexp *) context;

    if (!STAILQ_EMPTY(&protoexp->pend_getreqsq)) 
	psmi_timer_request(protoexp->proto->timerq, 
			  &protoexp->timer_getreqs, PSMI_TIMER_PRIO_1);

    return;
}

static
__fastpath 
struct ips_tid_recv_desc *
ips_tid_recv_alloc(struct ips_protoexp *protoexp, ips_epaddr_t *ipsaddr,
	const struct ips_tid_get_request *getreq, uint32_t nbytes_this)
{
    struct ips_tid_recv_desc *tidrecvc;
    psm_error_t err = PSM_OK;
    
    tidrecvc = (struct ips_tid_recv_desc *)
		psmi_mpool_get(protoexp->tid_desc_recv_pool);
    if (tidrecvc == NULL)
        return NULL;

    tidrecvc->context = &protoexp->proto->ep->context;
    tidrecvc->protoexp = protoexp;
    tidrecvc->ipsaddr = ipsaddr;
    tidrecvc->state = TIDRECVC_STATE_GRANT;
    tidrecvc->buffer = 
	(void *)((uintptr_t) getreq->tidgr_lbuf + getreq->tidgr_offset);
    tidrecvc->num_recv_hdrs = 0;
    tidrecvc->recv_msglen = nbytes_this;
    tidrecvc->tid_list.tsess_tidcount = 0;
    tidrecvc->getreq = (struct ips_tid_get_request *) getreq;
    tidrecvc->grant_cnt = 0;
    tidrecvc->recv_framecnt = 0;
    tidrecvc->flags = 0;
    tidrecvc->tidflow_active_gen = IPS_TF_INVALID_GENERATION;
    tidrecvc->ctrl_msg_queued = 0;
    tidrecvc->cksum = 0xb5b5b5b5;
    tidrecvc->stats.nSeqErr = 0;
    tidrecvc->stats.nGenErr = 0;
    tidrecvc->stats.nReXmit = 0;
    tidrecvc->stats.nErrChkReceived = 0;

    if ((err = ips_tf_allocate(&protoexp->tfctrl,
			       &tidrecvc->tidflow_idx,
			       &tidrecvc->tidflow_active_gen))){
      /* Unable to get a tidflow for expected protocol. */
      psmi_mpool_put(tidrecvc);
      /* XXX log this event */
      return NULL;
    }
    
    tidrecvc->tidflow_genseq.flow = tidrecvc->tidflow_idx;
    tidrecvc->tidflow_genseq.gen  = tidrecvc->tidflow_active_gen;
    tidrecvc->tidflow_genseq.seq  = rand_r(&protoexp->tidflow_seed) & 0x3ff;

    ipath_tidflow_set_entry(tidrecvc->context->ctrl,
			    tidrecvc->tidflow_genseq.flow,
			    tidrecvc->tidflow_genseq.gen,
			    tidrecvc->tidflow_genseq.seq);
    
    tidrecvc->tidflow_nswap_gen = 0;
    tidrecvc->tid_list.tsess_type = IPS_TID_SESSTYPE_MEMBER_LIST;
    tidrecvc->tid_list.tsess_tidcount = 0;
    tidrecvc->tid_list.tsess_tidlist_length = 0;
    tidrecvc->tid_list.tsess_unaligned_start = 0;
    tidrecvc->tid_list.tsess_unaligned_end = 0;

    tidrecvc->tid_list.tsess_descid._desc_idx = 
		psmi_mpool_get_obj_index(tidrecvc);
    tidrecvc->tid_list.tsess_descid._desc_genc = 
		psmi_mpool_get_obj_gen_count(tidrecvc);

    tidrecvc->tid_list.tsess_seqno  = getreq->tidgr_desc_seqno;
    tidrecvc->tid_list.tsess_srcoff = getreq->tidgr_offset;
    tidrecvc->tid_list.tsess_length = nbytes_this;
    
    psmi_timer_entry_init(&tidrecvc->timer_tidreq,
			 ips_tid_grant_timer_callback, tidrecvc);

    if (nbytes_this > 0) {
	if ((err = ips_tid_recv_alloc_frag(protoexp, tidrecvc->buffer, 
		    nbytes_this, &tidrecvc->tid_list, tidrecvc->ts_map))) {
	    tidrecvc->tid_list.tsess_tidcount = 0;
	    ips_tf_deallocate(&protoexp->tfctrl, tidrecvc->tidflow_idx);
	    psmi_mpool_put(tidrecvc);
	    /* XXX log me !!! */
	    return NULL;
	}
	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG)
	{
	    int num_tids = tidrecvc->tid_list.tsess_tidcount;
	    int tid, i;
	    for (i = 0; i < num_tids; i++) {
		tid = tidrecvc->tid_list.tsess_list[i].tid;
		psmi_assert(protoexp->tid_info[tid].state == TIDSTATE_FREE);
		protoexp->tid_info[tid].tid = tid;
		protoexp->tid_info[tid].state = TIDSTATE_USED;
		protoexp->tid_info[tid].tidrecvc = tidrecvc;
	    }
	}
    }

    /* This gets sent out as a control message, so we need to force 4-byte IB
     * alignment */
    tidrecvc->tid_list.tsess_tidlist_length = (uint16_t) 
	PSMI_ALIGNUP((sizeof(ips_tid_session_list) +
		     (tidrecvc->tid_list.tsess_tidcount * 
		      sizeof(ips_tid_session_member))), 4);

    _IPATH_EXP("alloc tidrecv=%d, ntid=%d, paylen=%d\n", 
	tidrecvc->tid_list.tsess_descid._desc_idx,
	tidrecvc->tid_list.tsess_tidcount, 
	tidrecvc->tid_list.tsess_tidlist_length);

    return tidrecvc;
}

static
psm_error_t __recvpath
ips_tid_pendtids_timer_callback(struct psmi_timer *timer, uint64_t current)
{
    struct ips_protoexp *protoexp = (struct ips_protoexp *) timer->context;
    struct ips_tid_get_pend *phead = &protoexp->pend_getreqsq;
    struct ips_tid_get_request *getreq;
    struct ips_tid_recv_desc *tidrecvc;
    uint32_t nbytes_this, leftover;
    uint64_t t_cyc;
    uintptr_t bufptr;
    psm_epaddr_t epaddr;
    ptl_epaddr_t *ipsaddr;
    psm_error_t err = PSM_OK;

    while (!STAILQ_EMPTY(phead)) {
	getreq = STAILQ_FIRST(phead);
	epaddr = getreq->tidgr_epaddr;

next_epaddr:
	ipsaddr = epaddr->ptladdr;
	protoexp = ipsaddr->proto->protoexp;
	nbytes_this = min(getreq->tidgr_length - getreq->tidgr_offset,
			  getreq->tidgr_rndv_winsz);
	/*
 	 * if the leftover is less than half window size,
 	 * we reduce nbytes_this by half, we want to avoid
 	 * to send a few bytes in a tid transaction.
 	 */
	leftover = getreq->tidgr_length -
			(getreq->tidgr_offset + nbytes_this);
	if (leftover && leftover < getreq->tidgr_rndv_winsz/2) {
		nbytes_this /= 2;
	}

	bufptr = (uintptr_t) getreq->tidgr_lbuf + getreq->tidgr_offset;

	if ((ips_tid_num_required(&protoexp->tidc, (void *) bufptr, nbytes_this) > ips_tid_num_available(&protoexp->tidc)) ||
	    !ips_tf_available(&protoexp->tfctrl)) {
	  /* We're out of tids/tidflow, tid release will requeue the callback */
	  ;
	}
	else if ((tidrecvc = ips_tid_recv_alloc(protoexp, ipsaddr,
				getreq, nbytes_this)) != NULL) {

	    err = ips_proto_send_ctrl_message(&ipsaddr->
					    flows[protoexp->tid_ep_flow],
					    OPCODE_TIDS_GRANT,
					    &tidrecvc->ctrl_msg_queued, 
					    &tidrecvc->tid_list);
	    
	    if (err != PSM_EP_NO_RESOURCES) {
		tidrecvc->grant_cnt++;
		t_cyc = get_cycles() + protoexp->tid_to_cyc_min;
	    }
	    else
		t_cyc = get_cycles() + protoexp->proto->timeout_send;

	    psmi_timer_request_always(protoexp->timerq, 
				     &tidrecvc->timer_tidreq, t_cyc);

	    getreq->tidgr_offset += nbytes_this;
	    _IPATH_VDBG("GRANT tididx=%d.%d srcoff=%d nbytes=%d/%d\n", 
			tidrecvc->tid_list.tsess_descid._desc_idx,
			getreq->tidgr_desc_seqno,
			getreq->tidgr_offset, nbytes_this, getreq->tidgr_length);

	    getreq->tidgr_desc_seqno++;
	    if (getreq->tidgr_offset == getreq->tidgr_length) {
		getreq->tidgr_protoexp = NULL;
		getreq->tidgr_epaddr = NULL;
		STAILQ_REMOVE_HEAD(phead, tidgr_next);
		continue;
	    }
	    epaddr = epaddr->mctxt_next;
	    goto next_epaddr;
	}
	else {
	    /* out of tidrecv desc.  The not-empty tidrecv mpool callback will
	     * cause us to requeue the getreq on the active timer queue */
	    ;
	}

	epaddr = epaddr->mctxt_next;
	if (epaddr != getreq->tidgr_epaddr) goto next_epaddr;
	break;
    }
    return PSM_OK; /* XXX err-broken */
}

static
psm_error_t __fastpath
ips_tid_recv_free(struct ips_tid_recv_desc *tidrecvc)
{
    struct ips_tid_get_request *getreq = tidrecvc->getreq;
    struct ips_protoexp *protoexp = tidrecvc->protoexp;
    int tidcount = tidrecvc->tid_list.tsess_tidcount;
    psm_error_t err = PSM_OK;
    
    psmi_assert(getreq != NULL);

    /* If checksum is enabled, make sure we have valid data for window */
    if (protoexp->proto->flags & IPS_PROTO_FLAG_CKSUM) {
      uint32_t cksum = ips_crc_calculate(tidrecvc->recv_msglen, 
					 (uint8_t*) tidrecvc->buffer, 
					 0xffffffff);
      if (tidrecvc->cksum != cksum) {
	psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			  "ErrPkt: Checksum mismatch. Expected: 0x%08x, Received: 0x%08x Source LID: %i. Rendezvous stats: nSeqErr: %d, nGenErr: %d, nReXmits: %d, nErrChkGen: %d. Aborting! \n", tidrecvc->cksum, cksum, __be16_to_cpu(tidrecvc->ipsaddr->tidgr_flow.path->epr_dlid), tidrecvc->stats.nSeqErr, tidrecvc->stats.nGenErr, tidrecvc->stats.nReXmit, tidrecvc->stats.nErrChkReceived);
	ips_proto_dump_data(tidrecvc->buffer, tidrecvc->recv_msglen);
	
	/* TODO: In order to recover from this we need to restart the rendezvous
	 * window again. This requires modifying the sender to not complete the
	 * send locally till TID_RELEASE_CONFIRM is released - currently it
	 * locally completes before sending the TID_RELEASE message.
	 */
      }
    }
    
    psmi_assert_always(tidrecvc->state == TIDRECVC_STATE_DONE);
    
    if (tidcount > 0) {
	if (protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG)
	{
	    int num_tids = tidrecvc->tid_list.tsess_tidcount;
	    int tid, i;
	    for (i = 0; i < num_tids; i++) {
		tid = tidrecvc->tid_list.tsess_list[i].tid;
		psmi_assert(protoexp->tid_info[tid].state == TIDSTATE_USED);
		psmi_assert(protoexp->tid_info[tid].tidrecvc == tidrecvc);
		protoexp->tid_info[tid].state = TIDSTATE_FREE;
	    }
	}

	ips_dump_tids(&tidrecvc->tid_list, "Deregistered %d tids: ", 
		      tidrecvc->tid_list.tsess_tidcount);

	if ((err = ips_tid_release(&tidrecvc->protoexp->tidc,
			  tidrecvc->ts_map, tidcount)))
	    goto fail;

    }
    
    getreq->tidgr_bytesdone += tidrecvc->recv_msglen;
    
    _IPATH_EXP("req=%p bytes=%d/%d\n",
		    getreq->tidgr_ucontext,
		    getreq->tidgr_bytesdone,
		    getreq->tidgr_length);
    
    tidrecvc->state = TIDRECVC_STATE_FREE;
    psmi_mpool_put(tidrecvc);

    if (getreq->tidgr_bytesdone == getreq->tidgr_length) {
	if (getreq->tidgr_callback)
	    getreq->tidgr_callback(getreq->tidgr_ucontext);
	psmi_mpool_put(getreq);
    }

    /* We just released some tids.  If requests are waiting on tids to be
     * freed, queue up the timer */
    if (tidcount > 0) {
	if (getreq->tidgr_offset < getreq->tidgr_length) {
#if 0
	    psmi_timer_request(getreq->tidgr_protoexp->timerq,
		&getreq->tidgr_protoexp->timer_getreqs,
		PSMI_TIMER_PRIO_1);
#endif
	    ips_tid_pendtids_timer_callback(
		&getreq->tidgr_protoexp->timer_getreqs, 0);
	}

	if (!STAILQ_EMPTY(&protoexp->pend_getreqsq)) {
	    psmi_timer_request(protoexp->timerq,
		&protoexp->timer_getreqs,
		PSMI_TIMER_PRIO_1);
	}
    }

fail:
    return err;
}

int 
__fastpath 
ips_protoexp_tid_release(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_tid_recv_desc *tidrecvc;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    ptl_arg_t desc_id = p_hdr->data[0];
    ptl_arg_t args[3];
    int rc = IPS_RECVHDRQ_CONTINUE;

    args[0] = p_hdr->data[0];
    args[1] = p_hdr->data[1];

    tidrecvc = (struct ips_tid_recv_desc *)
		psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool, 
					     desc_id._desc_idx);

    if (tidrecvc == NULL) 
        _IPATH_ERROR("OPCODE_TIDS_RELEASE: ERROR: Index %d is out of range\n",
		    desc_id._desc_idx);
    else {
	ptl_arg_t desc_tidrecvc;
	psmi_mpool_get_obj_index_gen_count(tidrecvc, 
					   &desc_tidrecvc._desc_idx, 
					   &desc_tidrecvc._desc_genc);

	_IPATH_VDBG("desc_req:id=%d,gen=%d desc_tidc:id=%d,gen=%d\n", 
		    desc_id._desc_idx, desc_id._desc_genc,
		    desc_tidrecvc._desc_idx, desc_tidrecvc._desc_genc);

	/* See if the reference is still live and valid */
	if (desc_tidrecvc.u64 == desc_id.u64) 
	  ips_tid_recv_free(tidrecvc);
    }

    /* Unconditionally echo back the confirmation.  If the release is a dupe
     * because a previous confirmation was lost, it still needs to be released
     * at the other end. */
    ips_proto_send_ctrl_message(&rcv_ev->ipsaddr->flows[protoexp->tid_ep_flow], 
				OPCODE_TIDS_RELEASE_CONFIRM,
				&rcv_ev->ipsaddr->ctrl_msg_queued, 
				args);
    return rc;
}

int  __fastpath
ips_protoexp_build_ctrl_message(struct ips_protoexp *protoexp, 
				struct ptl_epaddr *ipsaddr,
				ptl_arg_t *pargs,
				uint16_t *pkt_flags, uint8_t opcode, 
				void *payload)
{
    switch (opcode) {
	case OPCODE_TIDS_GRANT:
	{
	    ips_tid_session_list *tid_list = (ips_tid_session_list *) payload;
	    uint32_t desc_idx = tid_list->tsess_descid._desc_idx;
	    struct ips_tid_recv_desc *tidrecvc = (struct ips_tid_recv_desc *)
		psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool, 
					     desc_idx);
	    if (tidrecvc == NULL) return -1;

	    pargs[0].u32w0 = tidrecvc->getreq->tidgr_sendtoken;
	    pargs[0].u32w1 = tidrecvc->getreq->tidgr_length;
	    pargs[1].u32w0 = tidrecvc->tidflow_genseq.val;
	    
	    if (tidrecvc->grant_cnt >= protoexp->tid_to_intr && 
		ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD &&
		!(tidrecvc->getreq->tidgr_flags & IPS_PROTOEXP_TIDGET_PEERWAIT)) 
	    {

		*pkt_flags |= INFINIPATH_KPF_INTR;
		protoexp->tid_intr_reqs++;
	    }
	    return tid_list->tsess_tidlist_length;
	    break;
	}

	case OPCODE_TIDS_RELEASE:
	case OPCODE_TIDS_RELEASE_CONFIRM:
	case OPCODE_TIDS_GRANT_ACK:
	{
	    ptl_arg_t *args = (ptl_arg_t *) payload;
	    pargs[0].u64w0 = args[0].u64w0;
	    pargs[1].u64w0 = args[1].u64w0;
	    if (opcode == OPCODE_TIDS_RELEASE) {
		uint32_t release_cnt = args[2].u32w0;
		if (release_cnt >= protoexp->tid_to_intr && 
		    ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD) 
		{
			*pkt_flags |= INFINIPATH_KPF_INTR;
			protoexp->tid_intr_reqs++;
		}
	    }
	    return 0;
	}
	default:
	    return 0;
    }
}

void
__fastpath
ips_protoexp_handle_tiderr(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_tid_recv_desc *tidrecvc;
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;

    ptl_arg_t desc_id = p_hdr->data[0];
    ptl_arg_t desc_tidrecvc;
    int tid = IPS_HDR_TID(p_hdr);

    /* Expected sends not enabled */
    if (protoexp == NULL)
	return;

    /* Not doing extra tid debugging or not really a tiderr */
    if (!(protoexp->tid_flags & IPS_PROTOEXP_FLAG_TID_DEBUG) ||
	!(rcv_ev->error_flags & INFINIPATH_RHF_H_TIDERR))
	return;

    if (tid >= IPS_TID_MAX_TIDS || rcv_ev->ptype != RCVHQ_RCV_TYPE_EXPECTED) {
	_IPATH_ERROR("Unexpected tid value %d or ptype %d is not expected "
		     "in tid debugging\n", tid, rcv_ev->ptype);
	return;
    }
	
    tidrecvc = (struct ips_tid_recv_desc *)
	        psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool, 
					     desc_id._desc_idx);

    if (tidrecvc != NULL) 
	psmi_mpool_get_obj_index_gen_count(tidrecvc, 
				           &desc_tidrecvc._desc_idx, 
					   &desc_tidrecvc._desc_genc);

    if (protoexp->tid_info[tid].state != TIDSTATE_USED) {
	char buf[128];
	char *s = "invalid (not even in table)";
	if (tidrecvc != NULL) {
	    if (desc_tidrecvc._desc_idx == desc_id._desc_idx) {
		if (desc_tidrecvc._desc_genc == desc_id._desc_genc) 
		    s = "valid";
		else {
		    snprintf(buf, sizeof buf - 1, "valid session, but wrong "
			"generation (gen=%d,received=%d)", 
			desc_tidrecvc._desc_genc, desc_id._desc_genc);
		    buf[sizeof buf - 1] = '\0';
		    s = buf;
		}
	    }
	    else {
		snprintf(buf, sizeof buf - 1, "invalid session %d", 
			desc_id._desc_idx);
		buf[sizeof buf - 1] = '\0';
		s = buf;
	    }

	    if (protoexp->tid_info[tid].tidrecvc != tidrecvc) {
		_IPATH_ERROR("tid %d not a known member of tidsess %d\n", tid,
		desc_id._desc_idx);
	    }
	}

	_IPATH_ERROR("tid %d is marked unused (session=%d): %s\n", tid,
		desc_id._desc_idx, s);
    }
    return;
}

void
__fastpath
ips_protoexp_handle_data_err(const struct ips_recvhdrq_event *rcv_ev)
{
    struct ips_tid_recv_desc *tidrecvc;
    struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
    struct ips_message_header *p_hdr = rcv_ev->p_hdr;
    int hdr_err = rcv_ev->error_flags & INFINIPATH_RHF_H_IHDRERR;
    uint8_t op_code = __be32_to_cpu(p_hdr->bth[0]) >> 24 & 0xFF;
    char pktmsg[128];
    char errmsg[256];
    
    ips_proto_get_rhf_errstring(rcv_ev->error_flags, pktmsg, sizeof(pktmsg));

    snprintf(errmsg, sizeof(errmsg), 
	     "%s pkt type opcode 0x%x at hd=0x%x %s\n",
	     (rcv_ev->ptype == RCVHQ_RCV_TYPE_EAGER) ? "Eager" :
	     (rcv_ev->ptype == RCVHQ_RCV_TYPE_EXPECTED) ? "Expected" :
	     (rcv_ev->ptype == RCVHQ_RCV_TYPE_NON_KD) ? "Non-kd" : 
	     "<Error>",
	     op_code, rcv_ev->recvq->state->hdrq_head, pktmsg);

    if (!hdr_err) {
      uint32_t tid_recv_sessid;
      ptl_arg_t desc_id = p_hdr->data[0];
      psmi_seqnum_t sequence_num;
      uint32_t cur_flowgenseq, tfgen, tfseq;
      uint16_t kdeth_cksum;
      
      /* See if the KDETH checksum validates */
      kdeth_cksum = 
	(uint16_t) IPATH_LRH_BTH +
	(uint16_t) (__be16_to_cpu(p_hdr->lrh[2])) - 
	(uint16_t) ((__le32_to_cpu(p_hdr->iph.ver_context_tid_offset)>>16) & 
		    LOWER_16_BITS) -
	(uint16_t) (__le32_to_cpu(p_hdr->iph.ver_context_tid_offset) & 
		    LOWER_16_BITS) -
	(uint16_t) __le16_to_cpu(p_hdr->iph.pkt_flags);
      
      if (kdeth_cksum != __le16_to_cpu(p_hdr->iph.chksum)) {
	_IPATH_EPDBG("Data Error Pkt With Invalid KDETH Checksum: Computed: 0x%04x, IPH_CKSUM: 0x%04x %s", kdeth_cksum, __le16_to_cpu(p_hdr->iph.chksum), errmsg);
	return;
      }
      
      tid_recv_sessid = desc_id._desc_idx;
      tidrecvc = 
	psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
				     tid_recv_sessid);
      
      if_pf (tidrecvc == NULL) {
	_IPATH_EPDBG("Data Error Pkt and Invalid Recv Handle: %s", errmsg);
	return;
      }
      
      if_pf (psmi_mpool_get_obj_gen_count(tidrecvc) != desc_id._desc_genc) {
	/* Print this at very verbose level. Noisy links can have a few of
	 * these! */
	_IPATH_VDBG("Data Error Pkt and Recv Generation Mismatch: %s", errmsg);
	return; /* skip */
      }
     
      if (tidrecvc->state == TIDRECVC_STATE_DONE) {
	_IPATH_EPDBG("Data Error Pkt for a Completed Rendezvous: %s", errmsg);
	return; /* skip */
      }
      
      /* See if CRC error for a previous packet */
      cur_flowgenseq = ipath_tidflow_get(tidrecvc->context->ctrl,
			tidrecvc->tidflow_idx);
      tfgen = ipath_tidflow_get_genval(cur_flowgenseq);
      tfseq = ipath_tidflow_get_seqnum(cur_flowgenseq);
      
      sequence_num.val = __be32_to_cpu(p_hdr->bth[2]);
     
      if ((sequence_num.gen == tfgen) && (sequence_num.seq < tfseq)) {
	/* Try to recover the flow by restarting from previous known good 
	 * sequence (possible if the packet with CRC error is after the "known
	 * good PSN" else we can't restart the flow.
	 */
	if (tidrecvc->tidflow_genseq.seq < sequence_num.seq)
	  return ips_protoexp_handle_tf_seqerr(rcv_ev);
	else
	  _IPATH_EPDBG("ErrPkt: CRC Error for packet %d.%d. Currently at %d.%d. %s.\n", sequence_num.gen, sequence_num.seq, tfgen, tfseq, errmsg);
      }
      else {
	/* Print this at very verbose level */
	_IPATH_VDBG("Data Error Packet. GenMismatch: %s. Tidrecvc: %p. Pkt Gen.Seq: %d.%d, TF Gen.Seq: %d.%d. %s\n", (sequence_num.gen != tfgen) ? "Yes" : "No", tidrecvc, sequence_num.gen, sequence_num.seq, tfgen, tfseq, errmsg);
      }
      
    }
    else {
      _IPATH_VDBG("HDR_ERROR: %s\n", errmsg);
    }
    
}

psm_error_t
__fastpath
ips_protoexp_flow_newgen(struct ips_tid_recv_desc *tidrecvc)
{
  psmi_assert_always(tidrecvc->state != TIDRECVC_STATE_DONE);
  ips_tfgen_allocate(&tidrecvc->protoexp->tfctrl,
			   tidrecvc->tidflow_idx,
			   &tidrecvc->tidflow_active_gen);
  
  /* Update tidflow table with new generation number */
  tidrecvc->tidflow_genseq.gen = tidrecvc->tidflow_active_gen;
  ipath_tidflow_set_entry(tidrecvc->context->ctrl,
			  tidrecvc->tidflow_genseq.flow,
			  tidrecvc->tidflow_genseq.gen,
			  tidrecvc->tidflow_genseq.seq);
  
  /* Increment swapped generation count for tidflow */
  tidrecvc->tidflow_nswap_gen++;
  return PSM_OK;  
}

void
__fastpath
ips_protoexp_handle_tf_seqerr(const struct ips_recvhdrq_event *rcv_ev)
{
  struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
  struct ips_message_header *p_hdr = rcv_ev->p_hdr;
  struct ips_tid_recv_desc *tidrecvc;
  ptl_arg_t desc_id = rcv_ev->p_hdr->hdr_data[0];
  ptl_arg_t send_descid = rcv_ev->p_hdr->hdr_data[1];
  ptl_arg_t desc_tidrecvc;
  psmi_seqnum_t sequence_num;
  ptl_arg_t args[3] = {};
  psm_error_t err;

  psmi_assert_always(protoexp != NULL);
  
  desc_tidrecvc.u64 = 0;
  tidrecvc = (struct ips_tid_recv_desc *)
    psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
                                 desc_id._desc_idx);

  if (tidrecvc != NULL)
    psmi_mpool_get_obj_index_gen_count(tidrecvc,
                                       &desc_tidrecvc._desc_idx,
                                       &desc_tidrecvc._desc_genc);
  
  if (tidrecvc && desc_tidrecvc.u64 == desc_id.u64) {
      
    /* Update stats for sequence errors */
    tidrecvc->stats.nSeqErr++;
    
    if (tidrecvc->state != TIDRECVC_STATE_DONE) {
      
      sequence_num.val = __be32_to_cpu(p_hdr->bth[2]);
      
      /* Only care about sequence error for currently active generation */
      if (tidrecvc->tidflow_active_gen == sequence_num.gen) {
	
	/* For a sequence error we restart from where the last header
	 * was successfully delivered for us since this is the last
	 * known good state for this flow. The PSM version of the flow
	 * sequence is the "safe" sequence number to restart at.
	 */
	
	/* If a "large" number of swapped generation we are loosing packets
	 * for this flow. Request throttling of tidflow by generating a 
	 * BECN. With header suppression we will miss some FECN packet
	 * on QLE73XX hence keeping track of swapped generation is another
	 * mechanism to do congestion control for tidflows.
	 *
	 * For mismatched sender/receiver/link speeds we can get into a 
	 * deadly embrace where minimal progress is made due to generation
	 * mismatch errors. This can occur if we wrap around the generation
	 * count without making progress. Hence in cases where the swapped
	 * generation count is > 254 stop sending BECN (and the NAK) so the
	 * send -> receiver pipeline is flushed with an error check and things
	 * can sync up. This should be an extremely rare event.
	 */
	
	if_pf (tidrecvc->tidflow_nswap_gen >= 254)
	  goto fail; /* Do not send NAK. Let error check kick in. */
	
	if_pf ((tidrecvc->tidflow_nswap_gen > 4) &&
	       (protoexp->proto->flags & IPS_PROTO_FLAG_CCA)) {
	  _IPATH_CCADBG("Generating BECN. Number of swapped generations: %d.\n", tidrecvc->tidflow_nswap_gen);
	  /* Mark flow to generate BECN in control packet */
	  tidrecvc->ipsaddr->tidgr_flow.flags |= IPS_FLOW_FLAG_GEN_BECN;
	  
	  /* Update stats for congestion encountered */
	  if (rcv_ev->ipsaddr)
	    rcv_ev->ipsaddr->stats.congestion_pkts++;
	}
	
	/* Swap generation for the flow. */
	err = ips_protoexp_flow_newgen(tidrecvc);
	if (err != PSM_OK)
	  goto fail;
	
	/* NAK the tid flow. Note: We can generate the latest NAK for this flow
	 * based on the tidrecvc->tidflow_{active|passive}_gen fields. */
	args[0] = send_descid;
	args[1] = tidrecvc->tid_list.tsess_descid;
	args[2].u16w0 = sequence_num.gen; /* Older Gen to NAK */

	ips_proto_send_ctrl_message(&tidrecvc->ipsaddr->tidgr_flow, 
				    OPCODE_NAK,
				    &tidrecvc->ctrl_msg_queued, args);

	/* Update stats for retransmit */
	tidrecvc->stats.nReXmit++;
      }
    } /* tidrecvc->state != DONE */
  }
  
 fail:
  return;
}

void
__fastpath
ips_protoexp_handle_tf_generr(const struct ips_recvhdrq_event *rcv_ev)
{
  struct ips_protoexp *protoexp = rcv_ev->proto->protoexp;
  struct ips_message_header *p_hdr = rcv_ev->p_hdr;
  int tid = IPS_HDR_TID(p_hdr);
  struct ips_tid_recv_desc *tidrecvc;
  psmi_assert(rcv_ev->p_hdr->data != NULL);
  ptl_arg_t desc_id = rcv_ev->p_hdr->data[0];
  ptl_arg_t desc_tidrecvc;

  if (tid >= IPS_TID_MAX_TIDS || rcv_ev->ptype != RCVHQ_RCV_TYPE_EXPECTED) {
    _IPATH_ERROR("Unexpected tid value %d or ptype %d is not expected "
                 "in tid debugging\n", tid, rcv_ev->ptype);
    return;
  }

  /* For a generation error our NAK crossed on the wire or this is a stale
   * packet. Error recovery should sync things up again. Just drop this
   * packet.
   */
  desc_tidrecvc.u64 = 0;
  tidrecvc = (struct ips_tid_recv_desc *)
    psmi_mpool_find_obj_by_index(protoexp->tid_desc_recv_pool,
                                 desc_id._desc_idx);
  
  if (tidrecvc != NULL) {
    psmi_mpool_get_obj_index_gen_count(tidrecvc,
                                       &desc_tidrecvc._desc_idx,
                                       &desc_tidrecvc._desc_genc);
    if (desc_tidrecvc.u64 == desc_id.u64)  {
      tidrecvc->stats.nGenErr++;   /* Update stats for generation errors */
      
      /* TODO_CCA: If packet faced congestion we may want to generate a CN 
       * packet to rate control sender.
       */
    }
    
  }

}
