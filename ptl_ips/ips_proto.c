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
 * IPS - Interconnect Protocol Stack.
 */

#include <assert.h>
#include <sys/uio.h> /* writev */
#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_proto_help.h"

/*
 * host ipv4 and pid used in ERR_CHK messages to detect stray processes
 */
static uint32_t host_ipv4addr = 0;  /* be */
static uint32_t host_pid = 0;	    /* be */

/*
 * Control message types have their own flag to determine whether a message of
 * that type is queued or not.  These flags are kept in a state bitfield.
 */
#define CTRL_MSG_ACK_QUEUED                     0x0001
#define CTRL_MSG_NAK_QUEUED                     0x0002
#define CTRL_MSG_ERR_CHK_QUEUED                 0x0004
#define CTRL_MSG_ERR_CHK_PLS_QUEUED             0x0008
#define CTRL_MSG_CONNECT_REQUEST_QUEUED		0x0010
#define CTRL_MSG_CONNECT_REPLY_QUEUED		0x0020
#define CTRL_MSG_DISCONNECT_REQUEST_QUEUED	0x0040
#define CTRL_MSG_DISCONNECT_REPLY_QUEUED	0x0080
#define CTRL_MSG_TIDS_RELEASE_QUEUED            0x0100
#define CTRL_MSG_TIDS_RELEASE_CONFIRM_QUEUED    0x0200
#define CTRL_MSG_CLOSE_QUEUED                   0x0400
#define CTRL_MSG_CLOSE_ACK_QUEUED               0x0800
#define CTRL_MSG_ABORT_QUEUED                   0x1000
#define CTRL_MSG_TIDS_GRANT_QUEUED		0x2000
#define CTRL_MSG_TIDS_GRANT_ACK_QUEUED		0x4000
#define CTRL_MSG_ERR_CHK_GEN_QUEUED             0x8000
#define CTRL_MSG_FLOW_CCA_BECN                  0x10000

#define CTRL_MSG_QUEUE_ALWAYS 0x80000000

#define _desc_idx   u32w0
#define _desc_genc  u32w1

static void	   ctrlq_init(struct ips_ctrlq *ctrlq, int flowid, 
			      struct ips_proto *proto);
static psm_error_t proto_sdma_init(struct ips_proto *proto, 
				   const psmi_context_t *context);

psm_error_t
ips_proto_init(const psmi_context_t *context, const ptl_t *ptl, 
	       int num_of_send_bufs, int num_of_send_desc, uint32_t imm_size,
	       const struct psmi_timer_ctrl *timerq, 
	       const struct ips_epstate *epstate, 
	       const struct ips_spio *spioc, 
	       struct ips_proto *proto)
{
    const struct ipath_base_info *base_info = &context->base_info;
    uint32_t protoexp_flags, cksum_sz = 0;
    union psmi_envvar_val env_tid, env_cksum, env_mtu;
    psm_error_t err = PSM_OK;

    /*
     * Checksum packets within PSM. Default is off.
     * This is heavy weight and done in software so not recommended for 
     * production runs.
     */
    
    psmi_getenv("PSM_CHECKSUM", 
		"Enable checksum of messages (0 disables checksum)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) 0, 
		&env_cksum);
    
    memset(proto, 0, sizeof(struct ips_proto));
    proto->ptl = (ptl_t *) ptl;
    proto->ep  = context->ep;      /* cached */
    proto->mq  = context->ep->mq;  /* cached */
    proto->fd  = context->fd;      /* cached */
    proto->pend_sends.proto = proto;
    psmi_timer_entry_init(&proto->pend_sends.timer,
			 ips_proto_timer_pendq_callback, &proto->pend_sends);
    STAILQ_INIT(&proto->pend_sends.pendq);
    proto->epstate = (struct ips_epstate *) epstate;
    proto->timerq  = (struct psmi_timer_ctrl *) timerq;
    proto->spioc   = (struct ips_spio *) spioc;
    
    proto->epinfo.ep_baseqp = base_info->spi_qpair;
    proto->epinfo.ep_context = base_info->spi_context; /* "real" context */

    proto->epinfo.ep_subcontext = base_info->spi_subcontext;
    proto->epinfo.ep_hca_type = psmi_epid_hca_type(context->epid);
    
    proto->epinfo.ep_unit    = base_info->spi_unit;
    proto->epinfo.ep_hdrq_msg_size = (IPS_HEADER_QUEUE_HWORDS + 
				      IPS_HEADER_QUEUE_IWORDS + 
				      IPS_HEADER_QUEUE_UWORDS_MIN) << 2;
    
    /* If checksums enabled we insert checksum at end of packet */
    cksum_sz = env_cksum.e_uint ? PSM_CRC_SIZE_IN_BYTES : 0;

    proto->epinfo.ep_mtu     = base_info->spi_mtu - 
                               proto->epinfo.ep_hdrq_msg_size - 
                               CRC_SIZE_IN_BYTES - PCB_SIZE_IN_BYTES;
    proto->epinfo.ep_mtu = ips_next_low_pow2(proto->epinfo.ep_mtu);
    /* Decrement checksum accounting AFTER lowering power of two */
    proto->epinfo.ep_mtu -= cksum_sz; 
    
    /* See if user specifies a lower MTU to use */
    if (!psmi_getenv("PSM_MTU", "MTU specified by user: 1-5,256-4096[4/2048]",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
		(union psmi_envvar_val) -1,
		&env_mtu)) {
	if (env_mtu.e_int != 256 && env_mtu.e_int != 512
	&& env_mtu.e_int != 1024 && env_mtu.e_int != 2048
	&& env_mtu.e_int != 4096) {
	   if (env_mtu.e_int < 1 || env_mtu.e_int > 5) env_mtu.e_int = 4;
	   env_mtu.e_int = ibta_mtu_enum_to_int((enum ibta_mtu)env_mtu.e_int);
	}
	if (proto->epinfo.ep_mtu > env_mtu.e_int)
		proto->epinfo.ep_mtu = env_mtu.e_int;
    }

    proto->epinfo.ep_piosize = base_info->spi_piosize - 
			       proto->epinfo.ep_hdrq_msg_size -
			       CRC_SIZE_IN_BYTES - PCB_SIZE_IN_BYTES - cksum_sz;
    
    /* Keep PIO as multiple of cache line size */
    if (proto->epinfo.ep_piosize > PSM_CACHE_LINE_BYTES)
      proto->epinfo.ep_piosize &= ~(PSM_CACHE_LINE_BYTES - 1);
    
    
    proto->timeout_send      = us_2_cycles(IPS_PROTO_SPIO_RETRY_US_DEFAULT);

    proto->iovec_cntr_next_inflight = 0;
    proto->iovec_thresh_eager= proto->iovec_thresh_eager_blocking = ~0U;
    proto->scb_max_inflight  = 2*num_of_send_desc;
    proto->scb_bufsize	     = PSMI_ALIGNUP(max(base_info->spi_piosize, 
						base_info->spi_mtu),
					    PSMI_PAGESIZE),
    proto->t_init	     = get_cycles();
    proto->t_fini	     = 0;
    proto->flags             = env_cksum.e_uint ? 
				      IPS_PROTO_FLAG_CKSUM : 0;

    proto->num_connected_to   = 0;
    proto->num_connected_from = 0;
    proto->num_disconnect_requests = 0;
    proto->stray_warn_interval = (uint64_t) -1;
    proto->done_warning = 0;
    proto->done_once = 0;
    proto->num_bogus_warnings = 0;
    proto->psmi_logevent_tid_send_reqs.interval_secs = 15;
    proto->psmi_logevent_tid_send_reqs.next_warning = 0;
    proto->psmi_logevent_tid_send_reqs.count = 0;
    
    /* Initialize IBTA related stuff (path record, SL2VL, CCA etc.) */
    if ((err = ips_ibta_init(proto)))
      goto fail;

    {
      /* Disable coalesced ACKs? */
      union psmi_envvar_val env_coalesce_acks;
      
      psmi_getenv("PSM_COALESCE_ACKS", 
		  "Coalesce ACKs on the wire (default is enabled i.e. 1)",
		  PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		  (union psmi_envvar_val) 1,  /* Enabled by default */
		  &env_coalesce_acks);
      
      if (env_coalesce_acks.e_uint) 
	proto->flags |= IPS_PROTO_FLAG_COALESCE_ACKS;
    }
    
    {
      /* Number of credits per flow */
      union psmi_envvar_val env_flow_credits;
      int df_flow_credits = min(PSM_FLOW_CREDITS, num_of_send_desc);
      
      psmi_getenv("PSM_FLOW_CREDITS",
		 "Number of unacked packets (credits) per flow (default is 64)",
		  PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		  (union psmi_envvar_val) df_flow_credits,
		  &env_flow_credits);
      proto->flow_credits = env_flow_credits.e_uint;
    }
    
    if ((context->runtime_flags & IPATH_RUNTIME_SDMA)) 
	if ((err = proto_sdma_init(proto, context)))
	    goto fail;
    
    /* 
     * Clone sendreq mpool configuration for pend sends config
     */
    {
	uint32_t chunks, maxsz;

	psmi_assert_always(proto->ep->mq->sreq_pool != NULL);
	psmi_mpool_get_obj_info(proto->ep->mq->sreq_pool, &chunks, &maxsz);

	proto->pend_sends_pool = 
	    psmi_mpool_create(sizeof(struct ips_pend_sreq), chunks, maxsz, 
			      0, DESCRIPTORS, NULL, NULL);
	if (proto->pend_sends_pool == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
    }

    /*
     * Register ips protocol statistics
     *
     * We put a (*) in the output to denote stats that may cause a drop in
     * performance.
     *
     * We put a (**) in the output of those stats that "should never happen"
     */
    {
	struct psmi_stats_entry entries[] = {
	    PSMI_STATS_DECLU64("pio busy count", 
			       &proto->stats.pio_busy_cnt),
	    /* Throttling by kernel */
	    PSMI_STATS_DECLU64("writev busy cnt",
			       &proto->stats.writev_busy_cnt),
	    /* When local dma completion is in the way... */
	    PSMI_STATS_DECLU64("writev compl. eagain",
			       &proto->stats.writev_compl_eagain),
	    /* When remote completion happens before local completion */
	    PSMI_STATS_DECLU64("writev compl. delay (*)",
			       &proto->stats.writev_compl_delay),
	    PSMI_STATS_DECLU64("scb unavail eager count", 
			       &proto->stats.scb_egr_unavail_cnt),
	    PSMI_STATS_DECLU64("scb unavail exp count", 
			       &proto->stats.scb_exp_unavail_cnt),
	    PSMI_STATS_DECLU64("rcvhdr overflows", /* Normal egr/hdr ovflw */
			       &proto->stats.hdr_overflow),
	    PSMI_STATS_DECLU64("rcveager overflows", 
			       &proto->stats.egr_overflow),
	    PSMI_STATS_DECLU64("lid zero errs (**)", /* shouldn't happen */
			       &proto->stats.lid_zero_errs),
	    PSMI_STATS_DECLU64("unknown packets (**)", /* shouldn't happen */
			       &proto->stats.unknown_packets),
	    PSMI_STATS_DECLU64("stray packets (*)", 
			       &proto->stats.stray_packets),
	    PSMI_STATS_DECLU64("send dma misaligns (*)", 
			       &proto->stats.send_dma_misaligns),
	    PSMI_STATS_DECLU64("amreply no bufs (*)",
			       &proto->proto_am.amreply_nobufs),
	    PSMI_STATS_DECLU64("pio stalls (*)", /* shouldn't happen too often */ 
			       &proto->spioc->spio_num_stall_total),
	    PSMI_STATS_DECLU64("Invariant CRC error (*)",
			       &proto->error_stats.num_icrc_err),
	    PSMI_STATS_DECLU64("Variant CRC error (*)",
			       &proto->error_stats.num_vcrc_err),
	    PSMI_STATS_DECLU64("ECC error ",
			       &proto->error_stats.num_ecc_err),
	    PSMI_STATS_DECLU64("IB Len error",
			       &proto->error_stats.num_len_err),
	    PSMI_STATS_DECLU64("IB MTU error ",
			       &proto->error_stats.num_mtu_err),
	    PSMI_STATS_DECLU64("KDETH error ",
			       &proto->error_stats.num_khdr_err),
	    PSMI_STATS_DECLU64("TID error ",
			       &proto->error_stats.num_tid_err),
	    PSMI_STATS_DECLU64("MK error ",
			       &proto->error_stats.num_mk_err),
	    PSMI_STATS_DECLU64("IB error ",
			       &proto->error_stats.num_ib_err),
	    
	};

	err = psmi_stats_register_type("InfiniPath low-level protocol stats",
				       PSMI_STATSTYPE_IPSPROTO,
				       entries,
				       PSMI_STATS_HOWMANY(entries),
				       NULL);
	if (err != PSM_OK)
	    goto fail;
    }

    /* 
     * Control Queue and messaging 
     */
    {
      int idx;
      
      for (idx = 0; idx < EP_FLOW_LAST; idx++)
	ctrlq_init(&proto->ctrlq[idx], idx, proto);
    }
					     
    /*
     * Receive-side handling
     */
    if ((err = ips_proto_recv_init(proto)))
	goto fail;

    /* 
     * Eager buffers.  We don't care to receive a callback when eager buffers
     * are newly released since we actively poll for new bufs.
     */
    if ((err = ips_scbctrl_init(context, num_of_send_desc,
	        num_of_send_bufs, imm_size, proto->scb_bufsize,
		NULL, NULL, &proto->scbc_egr)))
	goto fail;

    /*
     * Expected protocol handling.
     * If we enable tid-based expected rendezvous, the expected protocol code
     * handles its own rv scb buffers.  If not, we have to enable eager-based
     * rendezvous and we allocate scb buffers for it.
     */
    psmi_getenv("PSM_TID", 
		"Tid proto flags (0 disables protocol)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) IPS_PROTOEXP_FLAGS_DEFAULT, 
		&env_tid);
    protoexp_flags = env_tid.e_uint;

    if (protoexp_flags & IPS_PROTOEXP_FLAG_ENABLED) {
	proto->scbc_rv = NULL;
	if ((err = ips_protoexp_init(context, proto, protoexp_flags,
				     num_of_send_bufs, num_of_send_desc,
				     &proto->protoexp)))
	    goto fail;
    }
    else {
	proto->protoexp = NULL;
	proto->scbc_rv = (struct ips_scbctrl *)
			psmi_calloc(proto->ep, DESCRIPTORS, 
				    1, sizeof(struct ips_scbctrl));
	if (proto->scbc_rv == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
	/* 
	 * Rendezvous buffers. We want to get a callback for rendezvous bufs
	 * since we asynchronously try to make progress on these sends and only
	 * schedule them on the timerq if there are pending sends and available
	 * bufs.
	 */
	if ((err = ips_scbctrl_init(context, num_of_send_desc, 0 /* no bufs */, 
		    0, 0 /* bufsize==0 */, ips_proto_rv_scbavail_callback,
		    proto, proto->scbc_rv)))
	    goto fail;
    }
        
    /*
     * Parse the tid error settings from the environment.
     * <interval_secs>:<max_count_before_exit>
     */
    {
	int tvals[2];
	char *tid_err;
	union psmi_envvar_val env_tiderr;

	tid_err = "-1:0"; /* no tiderr warnings, never exits */
	tvals[0] = -1;
	tvals[1] = 0;

	if (!psmi_getenv("PSM_TID_ERROR",
			 "Tid error control <intval_secs:max_errors>",
			 PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
			 (union psmi_envvar_val) tid_err,
			 &env_tiderr)) {
	    /* not using default values */
	    tid_err = env_tiderr.e_str;
	    psmi_parse_str_tuples(tid_err, 2, tvals);
	}
	if (tvals[0] >= 0)
		proto->tiderr_warn_interval = sec_2_cycles(tvals[0]);
	else
		proto->tiderr_warn_interval = UINT64_MAX;
	proto->tiderr_max = tvals[1];
	_IPATH_PRDBG("Tid error control: warning every %d secs%s, "
		     "fatal error after %d tid errors%s\n",
		     tvals[0], (tvals[0] < 0) ? " (no warnings)" : "",
		     tvals[1], (tvals[1] == 0) ? " (never fatal)" : "");
    }

    /*
     * Active Message interface.  AM requests compete with MQ for eager
     * buffers, since request establish the amount of buffering in the network
     * (maximum number of requests in flight).  AM replies use the same amount
     * of request buffers -- we can never run out of AM reply buffers because a
     * request handler can only be run if we have at least one reply buffer (or
     * else the AM request is dropped).
     */
    if ((err = ips_proto_am_init(proto, num_of_send_bufs, num_of_send_desc,
				 imm_size, &proto->proto_am)))
	goto fail;

    if (!host_pid) {
	char ipbuf[INET_ADDRSTRLEN], *p;
	host_pid = (uint32_t) getpid();
	host_ipv4addr = psmi_get_ipv4addr(); /* already be */
	if (host_ipv4addr == 0) {
	    _IPATH_DBG("Unable to obtain local IP address, "
                       "not fatal but some features may be disabled\n");
	}
	else if (host_ipv4addr == __cpu_to_be32(0x7f000001)) {
	    _IPATH_INFO("Localhost IP address is set to the "
		        "loopback address 127.0.0.1, "
		        "not fatal but some features may be disabled\n");
	}
	else {
	    p = (char *) inet_ntop(AF_INET, (const void *) &host_ipv4addr, 
			ipbuf, sizeof ipbuf);
	    _IPATH_PRDBG("Ethernet Host IP=%s and PID=%d\n", p, host_pid);
	}

	/* Store in big endian for use in ERR_CHK */
	host_pid = __cpu_to_be32(host_pid);
    }

fail:
    return err;
}

psm_error_t
ips_proto_fini(struct ips_proto *proto, int force, uint64_t timeout_in)
{
    struct psmi_eptab_iterator itor;
    uint64_t t_start;
    uint64_t t_grace_start, t_grace_time, t_grace_finish, t_grace_interval;
    psm_epaddr_t epaddr;
    psm_error_t err = PSM_OK;
    int i;
    union psmi_envvar_val grace_intval;

    psmi_getenv("PSM_CLOSE_GRACE_PERIOD",
		"Additional grace period in seconds for closing end-point.",
		PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 0,
		&grace_intval);

    if (getenv("PSM_CLOSE_GRACE_PERIOD")) {
        t_grace_time = grace_intval.e_uint * SEC_ULL;
    }
    else if (timeout_in > 0) {
        /* default to half of the close time-out */
        t_grace_time = timeout_in / 2;
    }
    else {
        /* propagate the infinite time-out case */
        t_grace_time = 0;
    }

    if (t_grace_time > 0 && t_grace_time < PSMI_MIN_EP_CLOSE_TIMEOUT)
        t_grace_time = PSMI_MIN_EP_CLOSE_TIMEOUT;

    /* At close we will busy wait for the grace interval to see if any
     * receive progress is made. If progress is made we will wait for
     * another grace interval, until either no progress is made or the
     * entire grace period has passed. If the grace interval is too low
     * we may miss traffic and exit too early. If the grace interval is
     * too large the additional time spent while closing the program
     * will become visible to the user. */
    psmi_getenv("PSM_CLOSE_GRACE_INTERVAL",
		"Grace interval in seconds for closing end-point.",
		PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 0,
		&grace_intval);

    if (getenv("PSM_CLOSE_GRACE_INTERVAL")) {
        t_grace_interval = grace_intval.e_uint * SEC_ULL;
    }
    else {
        /* A heuristic is used to scale up the timeout linearly with 
         * the number of endpoints, and we allow one second per 1000
         * endpoints. */
        t_grace_interval = (proto->ep->connections * SEC_ULL) / 1000;
    }

    if (t_grace_interval < PSMI_MIN_EP_CLOSE_GRACE_INTERVAL)
        t_grace_interval = PSMI_MIN_EP_CLOSE_GRACE_INTERVAL;
    if (t_grace_interval > PSMI_MAX_EP_CLOSE_GRACE_INTERVAL)
        t_grace_interval = PSMI_MAX_EP_CLOSE_GRACE_INTERVAL;

    PSMI_PLOCK_ASSERT();

    t_start = proto->t_fini = get_cycles();

    /* Close whatever has been left open */
    if (proto->num_connected_to > 0) {
        int num_disc = 0;
        int *mask;
        psm_error_t  *errs;
        psm_epaddr_t *epaddr_array;

        psmi_epid_itor_init(&itor, proto->ep);
        while ((epaddr = psmi_epid_itor_next(&itor))) {
            if (epaddr->ptl == proto->ptl)
		num_disc++;
        }
	psmi_epid_itor_fini(&itor);
	mask = (int *) psmi_calloc(proto->ep, UNDEFINED, num_disc, sizeof(int));
	errs = (psm_error_t *)
		psmi_calloc(proto->ep, UNDEFINED, num_disc, sizeof(psm_error_t));
	epaddr_array = (psm_epaddr_t *) 
            psmi_calloc(proto->ep, UNDEFINED, num_disc, sizeof(psm_epaddr_t));

	if (errs == NULL || epaddr_array == NULL || mask == NULL) {
	    if (epaddr_array) psmi_free(epaddr_array);
	    if (errs) psmi_free(errs);
	    if (mask) psmi_free(mask);
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
        psmi_epid_itor_init(&itor, proto->ep);
	i = 0;
        while ((epaddr = psmi_epid_itor_next(&itor))) {
            if (epaddr->ptl == proto->ptl) {
		mask[i] = 1;
                epaddr_array[i] = epaddr;
                i++;
		PSM_MCTXT_REMOVE(epaddr);
            }
        }
	psmi_epid_itor_fini(&itor);
	err = ips_proto_disconnect(proto, force, num_disc, epaddr_array, 
				   mask, errs, timeout_in);
        psmi_free(mask);
        psmi_free(errs);
        psmi_free(epaddr_array);
    }

    t_grace_start = get_cycles();

    while (psmi_cycles_left(t_grace_start, t_grace_time)) {
        uint64_t t_grace_interval_start = get_cycles();
	int num_disconnect_requests = proto->num_disconnect_requests;
        PSMI_BLOCKUNTIL(proto->ep, err, 
		        (proto->num_connected_from == 0 ||
		         !psmi_cycles_left(t_start, timeout_in)) &&
		        (!psmi_cycles_left(t_grace_interval_start, t_grace_interval) ||
                         !psmi_cycles_left(t_grace_start, t_grace_time)));
	if (num_disconnect_requests == proto->num_disconnect_requests) {
	    /* nothing happened in this grace interval so break out early */
	    break;
	}
    }

    t_grace_finish = get_cycles();

    _IPATH_PRDBG("Closing endpoint disconnect left to=%d,from=%d after %d millisec of grace (out of %d)\n",
	 	 proto->num_connected_to, proto->num_connected_from,
		 (int) (cycles_to_nanosecs(t_grace_finish - t_grace_start) / MSEC_ULL),
                 (int) (t_grace_time / MSEC_ULL));
    
    if ((err = ips_ibta_fini(proto)))
      goto fail;
        
    if ((err = ips_proto_am_fini(&proto->proto_am)))
	goto fail;
    
    if ((err = ips_scbctrl_fini(&proto->scbc_egr)))
	goto fail;
   
    ips_proto_recv_fini(proto);
    
    if (proto->protoexp) {
	if ((err = ips_protoexp_fini(proto->protoexp)))
	    goto fail;
    }
    else {
	ips_scbctrl_fini(proto->scbc_rv);
	psmi_free(proto->scbc_rv);
    }

    psmi_mpool_destroy(proto->pend_sends_pool);

fail:
    proto->t_fini = proto->t_init = 0;
    return err;
}

static
psm_error_t
proto_sdma_init(struct ips_proto *proto, const psmi_context_t *context)
{
    union psmi_envvar_val env_sdma, env_ipathegr;
    char *c;
    uint32_t defval = IPS_PROTO_FLAGS_DEFAULT & IPS_PROTO_FLAGS_ALL_SDMA;
    psm_error_t err = PSM_OK;
    int egrmode;

    /*
     * Only initialize if RUNTIME_SDMA is enabled.
     */
    psmi_assert_always(context->runtime_flags & IPATH_RUNTIME_SDMA);

    if ((c = getenv("PSM_SDMA")) && *c && !strncmp("always", c, 7))
	defval = IPS_PROTO_FLAGS_ALL_SDMA;

    psmi_getenv("PSM_SDMA",
		"ipath send dma flags (0 disables send dma)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) defval,
		&env_sdma);

    if(env_sdma.e_uint != 1)
      proto->flags |= env_sdma.e_uint & IPS_PROTO_FLAGS_ALL_SDMA;

    /* If anything uses send dma, figure out our max packet threshold to call
     * send dma with */
    proto->scb_max_sdma = IPS_SDMA_MAX_SCB;
    if (proto->flags & IPS_PROTO_FLAGS_ALL_SDMA) {
	psmi_getenv("PSM_SDMA_THRESH",
		    "ipath send dma max packet per call",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
		    (union psmi_envvar_val) proto->scb_max_sdma,
		    &env_sdma);
	proto->scb_max_sdma = env_sdma.e_uint;
	if (proto->scb_max_sdma < 1) {
	    _IPATH_ERROR("Overriding PSM_SDMA_THRESH=%u to be '%u'\n",
		    proto->scb_max_sdma, 1);
	    proto->scb_max_sdma = 1;
	}
    }

    egrmode = proto->flags & 
	      (IPS_PROTO_FLAG_MQ_ENVELOPE_SDMA|IPS_PROTO_FLAG_MQ_EAGER_SDMA);
    
    /* Some modes don't make sense or at least, MQ doesn't expect them to
     * be a functional mode.  For example, it's not possible to use DMA
     * message envelopes with PIO eager data.
     */
    if (egrmode == IPS_PROTO_FLAG_MQ_ENVELOPE_SDMA) {
	err = psmi_handle_error(proto->ep, PSM_PARAM_ERR,
		"Unsupported Send DMA mode 0x%x: dma envelopes and pio eager",
		proto->flags);
	goto fail;
    }
    /* Only bother with switchover for pio-envelope,dma-eagerdata */
    else if (egrmode == IPS_PROTO_FLAG_MQ_EAGER_SDMA) {
        /* Reduce threshold to use SDMA for QLE73XX as we are PIO limited for
         * medium message sizes on it.
         */
        uint32_t hca_type = psmi_get_hca_type((psmi_context_t*) context);
	
	defval = (hca_type == PSMI_HCA_TYPE_QLE73XX) ? 
	  MQ_IPATH_THRESH_EGR_SDMA_SQ : MQ_IPATH_THRESH_EGR_SDMA;
	psmi_getenv("PSM_MQ_EAGER_SDMA_SZ",
		"ipath pio-to-sdma eager switchover",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) defval, &env_ipathegr);

	/* Has to be at least 1 MTU */
	proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking = 
	  max(proto->epinfo.ep_piosize, env_ipathegr.e_uint);
	
	/* For QLE73XX bump up the eager SDMA threshold for blocking sends if
	 * the user has not explicitly set one.
	 */
	if ((hca_type == PSMI_HCA_TYPE_QLE73XX) && 
	    (proto->iovec_thresh_eager == defval))
	  proto->iovec_thresh_eager_blocking = MQ_IPATH_THRESH_EGR_SDMA;
    }
    else if (egrmode == 
	     (IPS_PROTO_FLAG_MQ_ENVELOPE_SDMA|IPS_PROTO_FLAG_MQ_EAGER_SDMA))
    {
	/* Has to be 0 so we never try to split pio and dma */
	proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking = 0;
    }
    else if (egrmode == 0) { /* all pio */
	proto->iovec_thresh_eager = proto->iovec_thresh_eager_blocking = ~0U;
    }

fail:
    return err;
}

static
void
ctrlq_init(struct ips_ctrlq *ctrlq, int flowid, struct ips_proto *proto)
{
    // clear the ctrl send queue
    memset(ctrlq, 0, sizeof(*ctrlq));

    proto->message_type_to_index[OPCODE_ACK] = CTRL_MSG_ACK_QUEUED;
    proto->message_type_to_index[OPCODE_NAK] = CTRL_MSG_NAK_QUEUED;
    proto->message_type_to_index[OPCODE_ERR_CHK] = CTRL_MSG_ERR_CHK_QUEUED;
    proto->message_type_to_index[OPCODE_ERR_CHK_PLS] = CTRL_MSG_ERR_CHK_PLS_QUEUED;
    proto->message_type_to_index[OPCODE_CONNECT_REQUEST] = 
		CTRL_MSG_CONNECT_REQUEST_QUEUED;
    proto->message_type_to_index[OPCODE_CONNECT_REPLY] = 
		CTRL_MSG_CONNECT_REPLY_QUEUED;
    proto->message_type_to_index[OPCODE_DISCONNECT_REQUEST] = 
		CTRL_MSG_DISCONNECT_REQUEST_QUEUED;
    proto->message_type_to_index[OPCODE_DISCONNECT_REPLY] = 
		CTRL_MSG_DISCONNECT_REPLY_QUEUED;
    proto->message_type_to_index[OPCODE_CLOSE] = CTRL_MSG_CLOSE_QUEUED;
    proto->message_type_to_index[OPCODE_CLOSE_ACK] = CTRL_MSG_CLOSE_ACK_QUEUED;
    proto->message_type_to_index[OPCODE_ABORT] = CTRL_MSG_ABORT_QUEUED;
    proto->message_type_to_index[OPCODE_TIDS_GRANT] = CTRL_MSG_TIDS_GRANT_QUEUED;
    proto->message_type_to_index[OPCODE_TIDS_GRANT_ACK] = CTRL_MSG_TIDS_GRANT_ACK_QUEUED;
    proto->message_type_to_index[OPCODE_ERR_CHK_GEN] = CTRL_MSG_ERR_CHK_GEN_QUEUED;
    proto->message_type_to_index[OPCODE_FLOW_CCA_BECN] = CTRL_MSG_FLOW_CCA_BECN;

    ctrlq->ctrlq_head = ctrlq->ctrlq_tail = 0;
    ctrlq->ctrlq_overflow = 0;
    ctrlq->ctrlq_proto = proto;
    ctrlq->ctrlq_flowid = flowid;
    /* We never enqueue connect messages.  They require 512 bytes and we don't
     * want to stack allocate 512 bytes just when sending back acks.
     */
    proto->ctrl_msg_queue_never_enqueue = CTRL_MSG_CONNECT_REQUEST_QUEUED |
				   CTRL_MSG_CONNECT_REPLY_QUEUED |
				   CTRL_MSG_DISCONNECT_REQUEST_QUEUED |
                                   CTRL_MSG_DISCONNECT_REPLY_QUEUED |
                                   CTRL_MSG_ERR_CHK_GEN_QUEUED |
                                   CTRL_MSG_TIDS_GRANT_QUEUED;

    psmi_timer_entry_init(&ctrlq->ctrlq_timer,
			 ips_proto_timer_ctrlq_callback, ctrlq);

    return;
}

static int inline 
_build_ctrl_message(struct ips_proto *proto,
		    struct ips_proto_ctrl_message *msg,
		    ips_epaddr_t *ipsaddr, uint8_t message_type,
		    struct ips_flow *flow,
		    void *payload, uint8_t *discard_msg)
{
    uint32_t tot_paywords = sizeof(struct ips_message_header) >> 2;
    struct ips_epinfo *epinfo = &proto->epinfo;
    struct ips_epinfo_remote *epr = &ipsaddr->epr;
    uint16_t pkt_flags = IPS_EPSTATE_COMMIDX_PACK(epr->epr_commidx_to);
    struct ips_message_header *p_hdr = &msg->pbc_hdr.hdr;
    ips_path_rec_t *ctrl_path = ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][ipsaddr->epr.epr_hpp_index];
    int paylen = 0;
    
    if ((proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE)  &&
	(++ipsaddr->epr.epr_hpp_index >=
	 ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY]))
      ipsaddr->epr.epr_hpp_index = 0;
    
    /* Control messages go over the control path. */
    p_hdr->lrh[0] = __cpu_to_be16(IPATH_LRH_BTH | 
				  (ctrl_path->epr_sl << 4) |
				  (proto->sl2vl[ctrl_path->epr_sl] << LRH_VL_SHIFT));
    p_hdr->lrh[1] = ctrl_path->epr_dlid;
    p_hdr->lrh[2] = __cpu_to_be16(tot_paywords + SIZE_OF_CRC);
    p_hdr->lrh[3] = ctrl_path->epr_slid;

    p_hdr->bth[0] = __cpu_to_be32((IPATH_OPCODE_USER1 << 24) + 
				  ctrl_path->epr_pkey);

    /* If flow is congested then generate a BECN for path. */
    if_pf (flow->flags & IPS_FLOW_FLAG_GEN_BECN) {
      _IPATH_CCADBG("Generating BECN for flow %x ----> %x. Num congested packets: 0x%"PRIx64". Msg type: %d\n", __be16_to_cpu(flow->path->epr_slid), __be16_to_cpu(flow->path->epr_dlid), ipsaddr->stats.congestion_pkts, message_type);
      p_hdr->bth[1] = __cpu_to_be32(epr->epr_qp | 1 << BTH_BECN_SHIFT);
      flow->flags &= ~IPS_FLOW_FLAG_GEN_BECN;
    }
    else
      p_hdr->bth[1] = __cpu_to_be32(epr->epr_qp);
    p_hdr->bth[2] = 0;

    p_hdr->commidx = epr->epr_commidx_to;
    p_hdr->sub_opcode = message_type;
    p_hdr->ack_seq_num = 0;
    IPS_HEADER_SRCCONTEXT_SET(p_hdr, epinfo->ep_context);
    p_hdr->src_subcontext = epinfo->ep_subcontext;
    p_hdr->dst_subcontext = epr->epr_subcontext;
    p_hdr->flags = 0;
    p_hdr->mqhdr = 0;
    p_hdr->flowid = flow->flowid;

    switch (message_type) {
    case OPCODE_ACK:
      if_pt (flow->protocol != PSM_PROTOCOL_TIDFLOW) 
        p_hdr->ack_seq_num = flow->recv_seq_num.psn;
      else {
	ptl_arg_t *args = (ptl_arg_t*) payload;
	uint32_t tid_recv_sessid;
	struct ips_tid_recv_desc *tidrecvc;
	
	/* TIDFLOW ACK. 
	 * args[0] = send descriptor id
	 * args[1] = receive descriptor id
	 */
	ips_ptladdr_lock(ipsaddr);
	
	tid_recv_sessid = args[1]._desc_idx;
	tidrecvc = 
	  psmi_mpool_find_obj_by_index(proto->protoexp->tid_desc_recv_pool,
				       tid_recv_sessid);
	if (tidrecvc == NULL) {
	  *discard_msg = 1;
	  ips_ptladdr_unlock(ipsaddr);
	  break;
	}
	if_pf (psmi_mpool_get_obj_gen_count(tidrecvc) != args[1]._desc_genc) {
	  *discard_msg = 1;
	  ips_ptladdr_unlock(ipsaddr);
	  break;
	}
	
	p_hdr->data[0].u64 = args[0].u64;
	p_hdr->ack_seq_num = tidrecvc->tidflow_genseq.psn;
	ips_ptladdr_unlock(ipsaddr);
      }
      break;

    case OPCODE_NAK:
      if_pf (flow->protocol != PSM_PROTOCOL_TIDFLOW) {
	p_hdr->ack_seq_num = flow->recv_seq_num.psn;
      }
      else {
	ptl_arg_t *args = (ptl_arg_t*) payload;
	uint32_t tid_recv_sessid;
	struct ips_tid_recv_desc *tidrecvc;
	psmi_seqnum_t ack_seq_num;
	
	/* TIDFLOW NAK.
	 * args[0] = send descriptor id
	 * args[1] = receive descriptor id
	 * args[2].u16w0 = Old generation to NAK
	 */
	ips_ptladdr_lock(ipsaddr);
	
	tid_recv_sessid = args[1]._desc_idx;
	tidrecvc = 
	  psmi_mpool_find_obj_by_index(proto->protoexp->tid_desc_recv_pool,
				       tid_recv_sessid);
	if (tidrecvc == NULL) {
	  *discard_msg = 1;
	  ips_ptladdr_unlock(ipsaddr);
	  break;
	}
	if_pf (psmi_mpool_get_obj_gen_count(tidrecvc) != args[1]._desc_genc) {
	  *discard_msg = 1;
	  ips_ptladdr_unlock(ipsaddr);
	  break;
	}

	p_hdr->data[0].u64 = args[0].u64; /* Send descriptor id */
	p_hdr->data[1].u32w0 = tidrecvc->tidflow_genseq.val; /*New flowgenseq*/
	
	/* Ack seqnum contains the old generation we are acking for */
	ack_seq_num = tidrecvc->tidflow_genseq;
	ack_seq_num.gen = args[2].u16w0;
	p_hdr->ack_seq_num = ack_seq_num.psn;
	
	ips_ptladdr_unlock(ipsaddr);
      }
      break;
      
    case OPCODE_ERR_CHK:
      {
	psmi_seqnum_t err_chk_seq;
	ips_ptladdr_lock(ipsaddr);

	err_chk_seq = (SLIST_EMPTY(&flow->scb_pend)) ?
	    flow->xmit_seq_num : SLIST_FIRST(&flow->scb_pend)->seq_num;
	err_chk_seq.pkt -= 1;
	p_hdr->bth[2] = __cpu_to_be32(err_chk_seq.psn);
	ips_ptladdr_unlock(ipsaddr);
	p_hdr->data[0].u32w0 = host_ipv4addr;
	p_hdr->data[0].u32w1 = host_pid;

	if (ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD)
	    pkt_flags |= INFINIPATH_KPF_INTR;
      }
      break;
	
    case OPCODE_ERR_CHK_GEN:
      {
	struct ips_scb_unackedq *unackedq = &flow->scb_unacked;
	
	/* TIDFLOW ERR_CHK_GEN
	 * args[0] = receive descriptor id
	 * args[1] = send descriptor id
	 */
	if (!STAILQ_EMPTY(unackedq)) {
	  ips_scb_t *scb = STAILQ_FIRST(unackedq);
	  psmi_seqnum_t err_chk_seq;
	  
	  ips_ptladdr_lock(ipsaddr);
	  
	  psmi_assert_always(scb->tidsendc);
	  
	  err_chk_seq = (SLIST_EMPTY(&flow->scb_pend)) ?
	    flow->xmit_seq_num : SLIST_FIRST(&flow->scb_pend)->seq_num;
	  err_chk_seq.seq -= 1;
	  
	  /* NOTE: If error check gen is cached and we get a NAK 
	   * the scbs are flushed again. This can increase the DMA counter
	   * as scb's are retransmitted which we don't check for here.
	   * One way is never cache the ERR_CHK_GEN messages so it's only
	   * called from the ack timeout callback. Other way is that we
	   * send the ERR_CHK_GEN message over SDMA so they are serialized with
	   * respect to each other. Note: In this case we don't need to 
	   * wait for the DMA completion counters in the ack timeout.
	   */
	  p_hdr->bth[2] = __cpu_to_be32(err_chk_seq.psn);
	  
	  /* Receive descriptor index */
	  p_hdr->data[0].u64 = scb->tidsendc->tid_list.tsess_descid.u64;
	  /* Send descriptor index */
	  p_hdr->data[1].u64 = scb->tidsendc->descid.u64;
	  
	  ips_ptladdr_unlock(ipsaddr);
	  
	  if (ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD)
	    pkt_flags |= INFINIPATH_KPF_INTR;  
	}
	else
	  *discard_msg = 1;
      }
      break;
      
    case OPCODE_FLOW_CCA_BECN:
      _IPATH_CCADBG("Generating Explicit BECN for flow %x ----> %x. Num congested packets: 0x%"PRIx64"\n", __be16_to_cpu(flow->path->epr_slid), __be16_to_cpu(flow->path->epr_dlid), ipsaddr->stats.congestion_pkts);
      p_hdr->bth[1] = __cpu_to_be32(epr->epr_qp | 1 << BTH_BECN_SHIFT);
      p_hdr->data[0].u32w0 = flow->cca_ooo_pkts;
      break;
      
    case OPCODE_ERR_CHK_BAD:
	p_hdr->data[0].u32w0 = host_ipv4addr;
	p_hdr->data[0].u32w1 = host_pid;
	break;

    case OPCODE_STARTUP:
    case OPCODE_STARTUP_ACK:
    case OPCODE_STARTUP_EXT:
    case OPCODE_STARTUP_ACK_EXT:
	psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
	    "Unexpected use of old connect protocol");
        break;

    case OPCODE_CONNECT_REQUEST:
    case OPCODE_CONNECT_REPLY: 
	p_hdr->hdr_dlen = (epinfo->ep_hdrq_msg_size>>2) -
	    IPS_HEADER_QUEUE_IWORDS - IPS_HEADER_QUEUE_HWORDS;
        p_hdr->bth[0] = __cpu_to_be32((IPATH_OPCODE_USER1 << 24) + 
				      ctrl_path->epr_pkey);
	paylen = 
	    ips_proto_build_connect_message(proto, msg, ipsaddr, 
					    message_type, payload);
	/* Rewrite packet length since this subopcode has an eager payload */
	tot_paywords += paylen >> 2;
	p_hdr->lrh[2] = __cpu_to_be16(tot_paywords + SIZE_OF_CRC);

#if 0	/* MARKDEBBAGE - disabled this as it slows down connect at scale */
	/* On request message, always set the kpf flag.  If reply, only set it
	 * if we know that the recvthread is running */
	if (message_type == OPCODE_CONNECT_REQUEST || 
	    ipsaddr->flags & SESS_FLAG_HAS_RCVTHREAD)
		pkt_flags |= INFINIPATH_KPF_INTR;
#endif
	break;

    case OPCODE_DISCONNECT_REQUEST:
    case OPCODE_DISCONNECT_REPLY:
	paylen = 
	    ips_proto_build_connect_message(proto, msg, ipsaddr, 
					    message_type, payload);
	tot_paywords += paylen >> 2;
	p_hdr->hdr_dlen = (epinfo->ep_hdrq_msg_size>>2) -
	    IPS_HEADER_QUEUE_IWORDS - IPS_HEADER_QUEUE_HWORDS;
	p_hdr->lrh[2] = __cpu_to_be16(tot_paywords + SIZE_OF_CRC);
	break;

    case OPCODE_TIDS_RELEASE:
    case OPCODE_TIDS_RELEASE_CONFIRM:
    case OPCODE_TIDS_GRANT_ACK:
    case OPCODE_TIDS_GRANT: 
	paylen = ips_protoexp_build_ctrl_message(proto->protoexp, ipsaddr, 
			p_hdr->data, &pkt_flags, message_type, payload);
	if (paylen < 0) {
	  *discard_msg = 1;
	  break;
	}
	tot_paywords += paylen >> 2;
	p_hdr->lrh[2] = __cpu_to_be16(tot_paywords + SIZE_OF_CRC);
    break;
    
    default:
	break;
    }

    p_hdr->iph.ver_context_tid_offset = __cpu_to_le32(
        (IPS_PROTO_VERSION << INFINIPATH_I_VERS_SHIFT) +
        (epr->epr_pkt_context << INFINIPATH_I_CONTEXT_SHIFT) +
        (IPATH_EAGER_TID_ID << INFINIPATH_I_TID_SHIFT));
    p_hdr->iph.pkt_flags = __cpu_to_le16(pkt_flags);
    
    ips_kdeth_cksum(p_hdr);  // Generate KDETH  checksum
    
    /* Require 4-byte alignment always */
    psmi_assert(!(paylen & 0x3));
    return paylen;
}

psm_error_t ips_proto_timer_ctrlq_callback(struct psmi_timer *, uint64_t);

psm_error_t __recvpath
ips_proto_send_ctrl_message(struct ips_flow *flow, uint8_t message_type, 
			    uint32_t *msg_queue_mask, void *payload)
{
    struct ips_proto_ctrl_message msg;
    psm_error_t err = PSM_EP_NO_RESOURCES;
    ptl_arg_t *args = (ptl_arg_t *) payload;
    ips_epaddr_t *ipsaddr = flow->ipsaddr;
    struct ips_proto *proto = ipsaddr->proto;
    struct ips_ctrlq *ctrlq = &proto->ctrlq[IPS_FLOWID2INDEX(flow->flowid)&0x3];
    struct ips_ctrlq_elem *cqe = ctrlq->ctrlq_cqe;
    uint32_t cksum = 0;
    int paylen;
    uint8_t discard_msg = 0;
    
    /* Drain queue if non-empty */
    if (cqe[ctrlq->ctrlq_tail].ipsaddr)
      ips_proto_timer_ctrlq_callback(&ctrlq->ctrlq_timer, 0ULL);
    
    if (!cqe[ctrlq->ctrlq_tail].ipsaddr) {
      paylen = _build_ctrl_message(proto, &msg, ipsaddr, message_type, 
				   flow, payload, &discard_msg);
      
      if_pt (!discard_msg) {
	/* If enabled checksum control message */
	ips_do_cksum(proto, &msg.pbc_hdr.hdr, payload, paylen, &cksum);
	
	/* Error check messages are serialized with respect to the underlying
	 * transfer mechanism.
	 */
	if ((message_type == OPCODE_ERR_CHK) ||
	    (message_type == OPCODE_ERR_CHK_GEN) ||
	    (message_type == OPCODE_ERR_CHK_BAD)) {
	  switch(flow->transfer) {
	  case PSM_TRANSFER_PIO:
	  case PSM_TRANSFER_LAST:
	    err = ips_spio_transfer_frame(proto->spioc, flow, &msg.pbc_hdr.hdr, 
					  payload, paylen, PSMI_TRUE,
					  (proto->flags & IPS_PROTO_FLAG_CKSUM),
					  cksum);
	    break;
	  case PSM_TRANSFER_DMA:
	    err = ips_dma_transfer_frame(proto, flow, &msg.pbc_hdr, payload, 
					 paylen, cksum);
	    break;
	  }
	}
	else
	  if (proto->flags & IPS_PROTO_FLAG_CTRL_SDMA)
	    err = ips_dma_transfer_frame(proto, flow, &msg.pbc_hdr, payload, 
					 paylen, cksum);
	  else
	    err = ips_spio_transfer_frame(proto->spioc, flow, &msg.pbc_hdr.hdr, 
					  payload, paylen, PSMI_TRUE,
					  (proto->flags & IPS_PROTO_FLAG_CKSUM),
					  cksum);

	if (err == PSM_OK) 
	  ips_epaddr_stats_send(ipsaddr, message_type);
      }
      else
	err = PSM_OK; /* Ctrl message is discarded. May want to add stats */
      
      _IPATH_VDBG("transfer_frame of opcode=0x%x,remote_lid=%d,"
		  "src=%p,len=%d returns %d\n", (int) msg.pbc_hdr.hdr.sub_opcode, 
		  __be16_to_cpu(msg.pbc_hdr.hdr.lrh[1]), payload, paylen, err);
    }
    if (err != PSM_EP_NO_RESOURCES)
      return err;
    if (proto->flags & IPS_PROTO_FLAG_CTRL_SDMA)
      proto->stats.writev_busy_cnt++;
    else
      proto->stats.pio_busy_cnt++;

    if (!(proto->ctrl_msg_queue_never_enqueue & proto->message_type_to_index[message_type])) {
      
      if ((*msg_queue_mask) & proto->message_type_to_index[message_type]) {
	/* This type of control message is already queued, skip it */
	err = PSM_OK;
      } else if (cqe[ctrlq->ctrlq_head].ipsaddr == NULL) {
	// entry is free
	*msg_queue_mask |= message_type2index(proto, message_type);
	
	cqe[ctrlq->ctrlq_head].ipsaddr = ipsaddr;
	cqe[ctrlq->ctrlq_head].message_type = message_type;
	cqe[ctrlq->ctrlq_head].msg_queue_mask = msg_queue_mask;
	cqe[ctrlq->ctrlq_head].flow = flow;
	
	if (args) {
	  cqe[ctrlq->ctrlq_head].args[0].u64w0 = args[0].u64w0;
	  cqe[ctrlq->ctrlq_head].args[1].u64w0 = args[1].u64w0;
	  cqe[ctrlq->ctrlq_head].args[2].u64w0 = args[2].u64w0;
	}
	
	ctrlq->ctrlq_head = (ctrlq->ctrlq_head + 1) % CTRL_MSG_QEUEUE_SIZE;
	//_IPATH_INFO("requesting ctrlq timer for msgtype=%d!\n", message_type);
	psmi_timer_request(proto->timerq, &ctrlq->ctrlq_timer, 
			   PSMI_TIMER_PRIO_0);
	
	err = PSM_OK;
      } else {
	proto->ctrl_msg_queue_overflow++;
      }
    }

    return err;
}

psm_error_t __recvpath
ips_proto_timer_ctrlq_callback(struct psmi_timer *timer, uint64_t t_cyc_expire)
{
    struct ips_ctrlq *ctrlq = (struct ips_ctrlq *) timer->context;
    struct ips_proto *proto = ctrlq->ctrlq_proto;
    struct ips_proto_ctrl_message msg;
    struct ips_ctrlq_elem *cqe = ctrlq->ctrlq_cqe;
    struct ips_flow *flow;
    uint8_t msg_type;
    psm_error_t err;
    struct ptl_epaddr *ipsaddr;
    uint32_t cksum = 0;
    int paylen;
    uint8_t discard_msg = 0;
    
    // service ctrl send queue first
    while (cqe[ctrlq->ctrlq_tail].ipsaddr) {
	msg_type = cqe[ctrlq->ctrlq_tail].message_type;
	ipsaddr = cqe[ctrlq->ctrlq_tail].ipsaddr;
	flow = cqe[ctrlq->ctrlq_tail].flow;
	
        paylen = _build_ctrl_message(proto, &msg,
				     ipsaddr, msg_type, flow,
				     cqe[ctrlq->ctrlq_tail].args,
				     &discard_msg);
	
	psmi_assert_always(paylen == 0);

	if_pt (!discard_msg) {
	  /* If enabled checksum control message */
	  ips_do_cksum(proto, &msg.pbc_hdr.hdr, NULL, 0, &cksum);

	  /* Error check messages are serialized with respect to the underlying
	   * transfer mechanism.
	   */
	  if ((msg_type == OPCODE_ERR_CHK) ||
	      (msg_type == OPCODE_ERR_CHK_GEN) ||
	      (msg_type == OPCODE_ERR_CHK_BAD)) {
	    switch(flow->transfer) {
	    case PSM_TRANSFER_DMA:
	      err = ips_dma_transfer_frame(proto,flow,&msg.pbc_hdr,0,0, cksum); 
	      break;
	    case PSM_TRANSFER_PIO:
	    default:
	      err = 
		ips_spio_transfer_frame(proto->spioc, flow, &msg.pbc_hdr.hdr, 
					NULL, 0, PSMI_TRUE,
					(proto->flags & IPS_PROTO_FLAG_CKSUM),
					cksum);
	      break;
	    }
	  }
	  else
	    if (proto->flags & IPS_PROTO_FLAG_CTRL_SDMA)
	      err = ips_dma_transfer_frame(proto,flow,&msg.pbc_hdr,NULL,0,cksum); 
	    else
	      err = 
		ips_spio_transfer_frame(proto->spioc, flow, &msg.pbc_hdr.hdr, 
					0, 0, PSMI_TRUE,
					(proto->flags & IPS_PROTO_FLAG_CKSUM),
					cksum);
	}
	else
	  err = PSM_OK; /* Discard ctrl message */

	if (err == PSM_OK) {
	  ips_epaddr_stats_send(ipsaddr, msg_type);
	  *cqe[ctrlq->ctrlq_tail].msg_queue_mask &=
	    ~message_type2index(proto, cqe[ctrlq->ctrlq_tail].message_type);
	  cqe[ctrlq->ctrlq_tail].ipsaddr = NULL;
	  ctrlq->ctrlq_tail = (ctrlq->ctrlq_tail + 1) % CTRL_MSG_QEUEUE_SIZE;
        } else {
	    psmi_assert(err == PSM_EP_NO_RESOURCES);

	    if (proto->flags & IPS_PROTO_FLAG_CTRL_SDMA)
	      proto->stats.writev_busy_cnt++;
	    else
	      proto->stats.pio_busy_cnt++;
	    /* re-request a timer expiration */
	    psmi_timer_request(proto->timerq, &ctrlq->ctrlq_timer, 
			      PSMI_TIMER_PRIO_0);
	    return PSM_OK;
	}
    }

    return PSM_OK;
}

void __sendpath
ips_proto_flow_enqueue(struct ips_flow *flow, ips_scb_t *scb)
{
    ips_epaddr_t  *ipsaddr = flow->ipsaddr;
    
    /* Don't support send to self */
    psmi_assert(flow->path->epr_dlid != flow->path->epr_slid);

    ips_scb_prepare_flow_inner(scb, flow->epinfo, &ipsaddr->epr, flow);
    ips_do_cksum(ipsaddr->proto, &scb->ips_lrh, 
		 scb->payload, scb->payload_size, &scb->cksum);

    STAILQ_INSERT_TAIL(&flow->scb_unacked, scb, nextq);
    flow->scb_num_pending++;
    flow->scb_num_unacked++;

    /* Every ipsaddr has a pending head that points into the unacked queue.
     * If sends are already pending, process those first */
    if (SLIST_EMPTY(&flow->scb_pend))
	SLIST_FIRST(&flow->scb_pend) = scb;
}

/* 
 * This function attempts to flush the current list of pending 
 * packets through PIO.
 *
 * Recoverable errors:
 * PSM_OK: Packet triggered through PIO.
 * PSM_EP_NO_RESOURCES: No PIO bufs available or cable pulled.
 *
 * Unrecoverable errors:
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 * PSM_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 */
psm_error_t __sendpath
ips_proto_flow_flush_pio(struct ips_flow *flow, int *nflushed)
{
    struct ips_proto *proto = flow->ipsaddr->proto;
    struct ips_scb_pendlist *scb_pend = &flow->scb_pend;
    int num_sent = 0;
    uint64_t t_cyc;
    ips_scb_t *scb;
    psm_error_t err = PSM_OK;

    /* Out of credits - ACKs/NAKs reclaim recredit or congested flow */
    if_pf ((!flow->credits) || (flow->flags & IPS_FLOW_FLAG_CONGESTED))
      return PSM_OK;

    while (!SLIST_EMPTY(scb_pend) && flow->credits) {
	scb = SLIST_FIRST(scb_pend);
	
	if ((err = ips_spio_transfer_frame(proto->spioc, flow, &scb->ips_lrh, 
					   scb->payload, scb->payload_size, 
					   PSMI_FALSE,
					   (proto->flags & IPS_PROTO_FLAG_CKSUM) && (scb->tid == IPATH_EAGER_TID_ID),
					   scb->cksum)) == PSM_OK) 
	{
	    t_cyc = get_cycles();
	    scb->flags &= ~IPS_SEND_FLAG_PENDING;
	    scb->ack_timeout = flow->path->epr_timeout_ack; 
	    scb->abs_timeout = flow->path->epr_timeout_ack + t_cyc;
	    psmi_timer_request(proto->timerq, &flow->timer_ack,
			       scb->abs_timeout);
	    num_sent++;
	    flow->scb_num_pending--;
	    flow->credits--;
	    SLIST_REMOVE_HEAD(scb_pend, next);
	    	    
	}
	else
	  break;
    }

    /* If out of flow credits re-schedule send timer */
    if (!SLIST_EMPTY(scb_pend)) {
      proto->stats.pio_busy_cnt++;
      psmi_timer_request(proto->timerq, &flow->timer_send, 
			 get_cycles() + proto->timeout_send);
    }
    
    if (nflushed != NULL)
	*nflushed = num_sent;

    return err;
}

/*
 * Flush all packets currently marked as pending
 */
static psm_error_t scb_dma_send(struct ips_proto *proto, struct ips_flow *flow,
				struct ips_scb_pendlist *slist, int num,
				int *num_sent);

#ifdef PSM_DEBUG
#define PSM_DEBUG_CHECK_INFLIGHT_CNTR(proto)				\
    do  {								\
	uint32_t cntr_inflight;						\
	ipath_sdma_inflight(proto->ptl->context->ctrl, &cntr_inflight);	\
	VALGRIND_MAKE_MEM_DEFINED(&cntr_inflight, sizeof(uint32_t));	\
	psmi_assert_always(cntr_inflight ==				\
			   proto->iovec_cntr_next_inflight);		\
    } while (0)
#else
#define PSM_DEBUG_CHECK_INFLIGHT_CNTR(proto)
#endif

/*
 * Flush all packets queued up on a flow via send DMA.
 *
 * Recoverable errors:
 * PSM_OK: Able to flush entire pending queue for DMA.
 * PSM_OK_NO_PROGRESS: Flushed at least 1 but not all pending packets for DMA.
 * PSM_EP_NO_RESOURCES: No scb's available to handle unaligned packets
 *                      or writev returned a recoverable error (no mem for
 *                      descriptors, dma interrupted or no space left in dma
 *                      queue).
 *
 * Unrecoverable errors:
 * PSM_EP_DEVICE_FAILURE: Unexpected error calling writev(), chip failure,
 *			  rxe/txe parity error.
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 */
psm_error_t __sendpath
ips_proto_flow_flush_dma(struct ips_flow *flow, int *nflushed)
{
    struct ips_proto *proto = flow->ipsaddr->proto;
    struct ips_scb_pendlist *scb_pend = &flow->scb_pend;
    uint32_t cntr_init;
    ips_scb_t *scb;
    psm_error_t err = PSM_OK;
    int howmany = 0;
    int nsent = 0;

    /* Out of credits - ACKs/NAKs reclaim recredit or congested flow */
    if_pf ((!flow->credits) || (flow->flags & IPS_FLOW_FLAG_CONGESTED)) {
      if (nflushed)
	*nflushed = 0;
      return PSM_EP_NO_RESOURCES;
    }
    
    if (SLIST_EMPTY(scb_pend))
	goto success;

    /* 
     * Count how many are to be sent and fire dma.
     */
#ifdef PSM_DEBUG
    SLIST_FOREACH(scb, scb_pend, next)
	howmany++;
    psmi_assert_always(howmany == flow->scb_num_pending);
#else
    howmany = min(flow->scb_num_pending, flow->credits);
#endif
    
    howmany = min(howmany, proto->scb_max_sdma);
    
    if (howmany == 0)
      goto success;

    PSM_DEBUG_CHECK_INFLIGHT_CNTR(proto); /* Pre-check */

    cntr_init = proto->iovec_cntr_next_inflight;
    err = scb_dma_send(proto, flow, scb_pend, howmany, &nsent);
    if (err != PSM_OK && err != PSM_EP_NO_RESOURCES && 
	err != PSM_OK_NO_PROGRESS)
	goto fail;

    /* scb_dma_send shouldn't modify iovec_cntr_next_inflight */
    psmi_assert_always(cntr_init == proto->iovec_cntr_next_inflight);

    if (nsent > 0) {
	uint64_t t_cyc = get_cycles();
	uint32_t new_inflight = proto->iovec_cntr_next_inflight + nsent;
	int i = 0;

	/* We have to ensure that the inflight counter doesn't drift away too
	 * far from the completion counter or else our wraparound arithmetic
	 * in ips_proto_dma_wait_until will fail.
	 */
	if ((int) new_inflight - (int) proto->iovec_cntr_last_completed < 0)
	    ips_proto_dma_wait_until(proto, 
				     proto->iovec_cntr_last_completed + nsent);

	flow->scb_num_pending -= nsent;
	flow->credits = max((int) flow->credits - nsent, 0);
	
	SLIST_FOREACH(scb, scb_pend, next) {
	    if (++i > nsent) 
		break;
	    scb->flags &= ~IPS_SEND_FLAG_PENDING;
	    scb->ack_timeout = scb->nfrag*flow->path->epr_timeout_ack;
	    scb->abs_timeout = scb->nfrag*flow->path->epr_timeout_ack + t_cyc;
	    scb->dma_ctr = proto->iovec_cntr_next_inflight++;
	    if (scb->tidsendc)
	      ips_protoexp_scb_inflight(scb);
	}
	SLIST_FIRST(scb_pend) = scb;
    }

    PSM_DEBUG_CHECK_INFLIGHT_CNTR(proto); /* Post Check */

    if (SLIST_FIRST(scb_pend) != NULL) {
	psmi_assert(flow->scb_num_pending > 0);

	switch(flow->protocol) {
	case PSM_PROTOCOL_TIDFLOW:
	  /* For Tidflow we can cancel the ack timer if we have flow credits
	   * available and schedule the send timer. If we are out of flow
	   * credits then the ack timer is scheduled as we are waiting for 
	   * an ACK to reclaim credits. This is required since multiple
	   * tidflows may be active concurrently.
	   */
	  if (flow->credits) {  
	    /* Cancel ack timer and reschedule send timer. Increment 
	     * writev_busy_cnt as this really is DMA buffer exhaustion.
	     */
	    psmi_timer_cancel(proto->timerq, &flow->timer_ack);
	    psmi_timer_request(proto->timerq, &flow->timer_send,
			       get_cycles() + (proto->timeout_send << 1));
	    proto->stats.writev_busy_cnt++;
	  }
	  else {
	    /* Re-instate ACK timer to reap flow credits */
	    psmi_timer_request(proto->timerq, &flow->timer_ack,
			       get_cycles() + (flow->path->epr_timeout_ack>>2));
	  }
	  
	  break;
	case PSM_PROTOCOL_GO_BACK_N:
	default:
	  if (flow->credits) {
	    /* Schedule send timer and increment writev_busy_cnt */
	    psmi_timer_request(proto->timerq, &flow->timer_send,
			       get_cycles() + (proto->timeout_send << 1));
	    proto->stats.writev_busy_cnt++;
	  }
	  else {
	    /* Schedule ACK timer to reap flow credits */
	    psmi_timer_request(proto->timerq, &flow->timer_ack,
			       get_cycles() + (flow->path->epr_timeout_ack>>2));
	  }
	  break;
	}
    }
    else {
      /* Schedule ack timer */
      psmi_timer_cancel(proto->timerq, &flow->timer_send);
      psmi_timer_request(proto->timerq, &flow->timer_ack,
			 get_cycles() + flow->path->epr_timeout_ack);
    }
    
    /* We overwrite error with its new meaning for flushing packets */
    if (nsent > 0)
        if (nsent < howmany)
	    err = PSM_OK_NO_PROGRESS; /* partial flush */
	else
	    err = PSM_OK; /* complete flush */
    else
	err = PSM_EP_NO_RESOURCES; /* no flush at all */

success:
fail:
    if (nflushed)
	*nflushed = nsent;

    return err;
}

/* 
 * Fault injection in dma sends. Since DMA through writev() is all-or-nothing,
 * we don't inject faults on a packet-per-packet basis since the code gets
 * quite complex.  Instead, each call to flush_dma or transfer_frame is treated
 * as an "event" and faults are generated according to the IPS_FAULTINJ_DMASEND
 * setting.
 *
 * The effect is as if the event was successful but dropped on the wire
 * somewhere.
 */
PSMI_ALWAYS_INLINE(
int
dma_do_fault())
{
  
  if_pf (PSMI_FAULTINJ_ENABLED()) {
    PSMI_FAULTINJ_STATIC_DECL(fi, "dmalost", 1, IPS_FAULTINJ_DMALOST);
    return psmi_faultinj_is_fault(fi);
  }
  else
    return 0;
}

/* ips_dma_transfer_frame is used only for control messages, and is
 * not enabled by default, and not tested by QA; expected send
 * dma goes through scb_dma_send() */
psm_error_t __sendpath
ips_dma_transfer_frame(struct ips_proto *proto, struct ips_flow *flow, 
		       struct ips_pbc_header *pbc_hdr_i,
		       void *payload, uint32_t paylen, uint32_t cksum)
{
    struct iovec iovec;
    ssize_t ret;
    psm_error_t err;
    uint32_t have_cksum = 
      ((proto->flags & IPS_PROTO_FLAG_CKSUM) &&
       (((__le32_to_cpu(pbc_hdr_i->hdr.iph.ver_context_tid_offset) >> INFINIPATH_I_TID_SHIFT) & INFINIPATH_I_TID_MASK) == IPATH_EAGER_TID_ID) && (pbc_hdr_i->hdr.mqhdr != MQ_MSG_DATA_BLK) && (pbc_hdr_i->hdr.mqhdr != MQ_MSG_DATA_REQ_BLK));
    
    psmi_assert((paylen & 0x3) == 0);		 /* require 4-byte multiple */
    psmi_assert(((uintptr_t) payload & 0x3) == 0); /* require 4-byte alignment */
    psmi_assert(paylen < proto->epinfo.ep_mtu);
    
    /* See comments above for fault injection */
    if_pf (dma_do_fault())
	return PSM_OK;

    ips_proto_pbc_update(proto, flow, PSMI_TRUE,  &pbc_hdr_i->pbc, 
			 sizeof(struct ips_message_header), 
			 payload, paylen + 
			 (have_cksum ? PSM_CRC_SIZE_IN_BYTES : 0));

    /* If we have a payload, we need to copy it inline to a single element to
     * ensure that the driver copies it out completely as part of the writev
     * call since the payload can be stack-allocated memory.
     */
    if (paylen > 0) {
	uint32_t len = sizeof(struct ips_pbc_header) + 
	  paylen + (have_cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
	struct ips_pbc_header *pbc_hdr = alloca(len);

	if_pf (pbc_hdr == NULL) {
	    err = psmi_handle_error(PSMI_EP_NORETURN, PSM_NO_MEMORY,
		    "alloca for %d bytes failed in writev", len);
	    goto fail;
	}
	
	psmi_mq_mtucpy(pbc_hdr, pbc_hdr_i, sizeof(struct ips_pbc_header));
	psmi_mq_mtucpy(pbc_hdr+1, payload, paylen);
	
	if (have_cksum) {
	  uint32_t *ckptr = (uint32_t*) ((uint8_t*) pbc_hdr + 
					 (len - PSM_CRC_SIZE_IN_BYTES));
	  *ckptr = cksum;
	  ckptr++;
	  *ckptr = cksum;
	}
	
	iovec.iov_base = pbc_hdr;
	iovec.iov_len  = len;
	ret = ipath_cmd_writev(proto->fd, &iovec, 1);
    }
    else {
        uint32_t len = sizeof(struct ips_pbc_header) + 
	  (have_cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
	struct ips_pbc_header *pbc_hdr = have_cksum ? alloca(len) : pbc_hdr_i;
	
	if_pf (pbc_hdr == NULL) {
	    err = psmi_handle_error(PSMI_EP_NORETURN, PSM_NO_MEMORY,
		    "alloca for %d bytes failed in writev", len);
	    goto fail;
	}
	
	if (have_cksum) {
	  uint32_t *ckptr = (uint32_t*) (pbc_hdr + 1);
	  psmi_mq_mtucpy(pbc_hdr, pbc_hdr_i, sizeof(struct ips_pbc_header));
	  *ckptr = cksum;
	  ckptr++;
	  *ckptr = cksum;
	}
	
	iovec.iov_base = pbc_hdr;
	iovec.iov_len  = len;
	ret = ipath_cmd_writev(proto->fd, &iovec, 1);
    }

    if (ret > 0) {
	/* Even though we won't care about a completion in this frame send, we
	 * still increment the iovec packet counter */
	proto->iovec_cntr_next_inflight += ret;
	err = PSM_OK;
	psmi_assert_always(ret == 1);
    }
    else {
	/* 
	 * ret == 0: Driver did not queue packet. Try later.
	 * ENOMEM: No kernel memory to queue request, try later? *
	 * ECOMM: Link may have gone down
	 * EINTR: Got interrupt while in writev
	 */
	if (ret == 0 || errno == ENOMEM || errno == ECOMM || errno == EINTR)
	    err = PSM_EP_NO_RESOURCES;
	else 
	    err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
		  "Unhandled error in writev(): %s (fd=%d,iovec=%p,len=%d)", 
		  strerror(errno), proto->fd, &iovec, 1);
    }

fail:
    return err;
}

/*
 * Caller still expects num_sent to always be correctly set in case of an
 * error.
 *
 * Recoverable errors:
 * PSM_OK: At least one packet was successfully queued up for DMA.
 * PSM_EP_NO_RESOURCES: No scb's available to handle unaligned packets
 *                      or writev returned a recoverable error (no mem for
 *                      descriptors, dma interrupted or no space left in dma
 *                      queue).
 * PSM_OK_NO_PROGRESS: Cable pulled.
 *
 * Unrecoverable errors:
 * PSM_EP_DEVICE_FAILURE: Error calling ipath_sdma_inflight() or unexpected
 *                        error in calling writev(), or chip failure, rxe/txe
 *                        parity error.
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 */
static
psm_error_t  __sendpath
scb_dma_send(struct ips_proto *proto, struct ips_flow *flow,
	     struct ips_scb_pendlist *slist, int num, int *num_sent)
{
    ssize_t ret;
    struct ips_scb *scb = SLIST_FIRST(slist);
    unsigned int vec_idx = 0, scb_idx = 0, scb_sent = 0;
    unsigned int max_elem;
    struct iovec *iovec;
    psm_error_t err = PSM_OK;
    uint32_t cksum;

    psmi_assert(num > 0);
    psmi_assert(scb != NULL);

    /* See comments above for fault injection */
    if_pf (dma_do_fault()) 
      goto fail;

    max_elem = 3*num;
    iovec = alloca(sizeof(struct iovec) * max_elem);

    if_pf (iovec == NULL) {
	err = psmi_handle_error(PSMI_EP_NORETURN, PSM_NO_MEMORY,
		"alloca for %d bytes failed in writev",
		(int)(sizeof(struct iovec) * max_elem));
	goto fail;
    }

writev_again:
    vec_idx = 0;

    SLIST_FOREACH(scb, slist, next) {
	/* Can't exceed posix max writev count */
	if (vec_idx + (int) !!(scb->payload_size > 0) >= UIO_MAXIOV)
	    break;
   	
	psmi_assert(vec_idx < max_elem);
	psmi_assert_always((scb->payload_size & 0x3) == 0);
	
	/* Checksum all eager packets */
	cksum = ((proto->flags & IPS_PROTO_FLAG_CKSUM) && 
		 (scb->tid == IPATH_EAGER_TID_ID) &&
		 (scb->ips_lrh.mqhdr != MQ_MSG_DATA_BLK) &&
		 (scb->ips_lrh.mqhdr != MQ_MSG_DATA_REQ_BLK));
	
	ips_proto_pbc_update(proto, flow, PSMI_FALSE, &scb->pbc, 
			     sizeof(struct ips_message_header),
			     scb->payload, 
			     scb->payload_size + 
			     (cksum ? PSM_CRC_SIZE_IN_BYTES : 0));

	iovec[vec_idx].iov_base = &scb->pbc;
	iovec[vec_idx].iov_len  = sizeof(struct ips_message_header) + 
			          sizeof(union ipath_pbc);
	vec_idx++;
	
	if (scb->payload_size > 0) {
	    /* 
	     * Payloads must be 4-byte aligned.  If not, we need a bounce
	     * buffer for them.  This should be rare, but may be a performance
	     * penalty, so we log it as a stat in case we need to narrow in 
	     * on a performance problem.
	     *
	     * If checksum is enabled use a bounce buffer.
	     */
	    if ((((uintptr_t) scb->payload) & 0x3) || cksum) {
		void *buf = scb->payload;
		uint32_t len = scb->payload_size;
	     
		if (scb->nfrag > 1) {
		  err = psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			"buffer alignment for sdma error");
		  goto fail;
		}

		/* Only allocate buffer if current buffer is a user buffer */
		if (!((scb->payload >= scb->scbc->sbuf_buf_base) &&
		      (scb->payload <= scb->scbc->sbuf_buf_last))){
		  
		  if (!ips_scbctrl_bufalloc(scb)) {
		    err = PSM_EP_NO_RESOURCES;
		    if (--vec_idx == 0) /* Remove header, nothing to send */
		      goto fail;
		    else    /* send what we have so far, but no more */
		      break;
		  }
		  
		  /* Only need to copy if bounce buffer is used. */
		  psmi_mq_mtucpy(scb->payload, buf, len);
		  scb->payload_size = len;
		}
		
		/* If checksum then update checksum */
		if (cksum) {
		  uint32_t *ckptr = (uint32_t*) ((uint8_t*) scb->payload + len);
		  *ckptr = scb->cksum;
		  ckptr++;
		  *ckptr = scb->cksum;
		}
		
		if (((uintptr_t) buf) & 0x3)
		  proto->stats.send_dma_misaligns++;
	    }
	
	    iovec[vec_idx].iov_base = scb->payload;
	    iovec[vec_idx].iov_len  = scb->payload_size + 
	      (cksum ? PSM_CRC_SIZE_IN_BYTES : 0);
	    vec_idx++;

	    _IPATH_VDBG("seqno=%d hdr=%p,%d payload=%p,%d\n", 
		scb->seq_num.psn,
		iovec[vec_idx-2].iov_base, (int) iovec[vec_idx-2].iov_len,
		iovec[vec_idx-1].iov_base, (int) iovec[vec_idx-1].iov_len);

	    /*
	     * if there are multiple frag payload, set the right frag size.
	     */
	    if (scb->nfrag > 1) {
		scb->pbc.fill1 = __cpu_to_le16(scb->frag_size);   

		/* give tidinfo to qib driver */
		if (scb->tidsendc) {
		    iovec[vec_idx].iov_base = scb->tsess;
		    iovec[vec_idx].iov_len  = scb->tsess_length;
		    vec_idx++;
		}
	    }
	}
	else {
	  /* If checksum enabled need to send checksum at end of header 
	   * as we have no payload.
	   */
	  if (cksum) {
	    char *pbc_hdr = alloca(iovec[vec_idx-1].iov_len + 
				   PSM_CRC_SIZE_IN_BYTES);
	    uint32_t *ckptr = (uint32_t*) 
	      ((uint8_t*) pbc_hdr + iovec[vec_idx-1].iov_len);
	    
	    psmi_mq_mtucpy(pbc_hdr, iovec[vec_idx-1].iov_base,iovec[vec_idx-1].iov_len);
	    *ckptr = scb->cksum;
	    ckptr++;
	    *ckptr = scb->cksum;
	    
	    iovec[vec_idx-1].iov_base = pbc_hdr;
	    iovec[vec_idx-1].iov_len += PSM_CRC_SIZE_IN_BYTES;
       
	  }
	  
	  _IPATH_VDBG("hdr=%p,%d\n",
	  iovec[vec_idx-1].iov_base, (int) iovec[vec_idx-1].iov_len);
	}

	/* Can bound the number to send by 'num' */
	if (++scb_idx == num)
	    break;
    }
    psmi_assert(vec_idx > 0);
    ret = ipath_cmd_writev(proto->fd, iovec, vec_idx);
    
    /* 
     * Successfully wrote entire vector 
     */
    if (ret == scb_idx) {
	scb_sent += ret;
	/* scbs are left if we didn't want to send less and didn't have
	 * to break out of scbctrl_bufalloc */
	if (scb != NULL && scb_idx < num && err == PSM_OK) 
	    goto writev_again;
    }
    else {
	if (ret < 0) {
	    uint32_t cntr_fini;

	    /* ENOMEM: No kernel memory to queue request, try later? 
	     * ECOMM: Link may have gone down
	     * EINTR: Got interrupt while in writev
	     */
	    if (errno == ENOMEM || errno == ECOMM || errno == EINTR) {
		err = psmi_context_check_status(
			    (const psmi_context_t *) &proto->ep->context);
		if (err == PSM_OK)
		    err = PSM_EP_NO_RESOURCES;
	    }
	    else {
		err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
			"Unexpected error in writev(): %s (errno=%d) "
			"(fd=%d,iovec=%p,len=%d)", strerror(errno), errno,
			proto->fd, iovec, vec_idx);
		goto fail;
	    }
	    /* Find out the latest packet that we were able to put in flight */
	    if (ipath_sdma_inflight(proto->ptl->context->ctrl, &cntr_fini) < 0)
	    {
	      err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
			"Unable to retrieve inflight sdma counter: %s",
			strerror(errno));
		goto fail;
	    }

	    /* Re-write ret to actual inflight count */
	    scb_sent += cntr_fini - proto->iovec_cntr_next_inflight;
	}
	else {
	    /* No need for inflight system call, we can infer it's value from
	     * writev's return value */
	    scb_sent += ret;
	}
    }

fail:
    *num_sent = scb_sent;
    psmi_assert(*num_sent <= num && *num_sent >= 0);
    return err;
}

/*
 * Because we only lazily reap send dma completions, it's possible that we
 * receive a packet's remote acknowledgement before seeing that packet's local
 * completion.  As part of processing ack packets and releasing scbs, we issue
 * a wait for the local completion if the scb is marked as having been sent via
 * send dma.
 */
psm_error_t __sendpath
ips_proto_dma_wait_until(struct ips_proto *proto, uint32_t dma_cntr)
{
    psm_error_t err = PSM_OK;
    int spin_cnt = 0;
    int did_yield = 0;

    PSM_DEBUG_CHECK_INFLIGHT_CNTR(proto);

    if ((int) proto->iovec_cntr_last_completed - (int) dma_cntr >= 0) 
	return PSM_OK;

    PSMI_PROFILE_BLOCK();

    while ((int) proto->iovec_cntr_last_completed - (int) dma_cntr < 0) 
    {
	if (spin_cnt++ == proto->ep->yield_spin_cnt) {
	    /* Have to yield holding the PSM lock, mostly because we don't
	     * support another thread changing internal state at this point in
	     * the code.
	     */
	    did_yield = 1;
	    sched_yield();
	}

	/* Not there yet in completion count. Update our view of
	 * last_completed. */
	if (ipath_sdma_complete(proto->ptl->context->ctrl, 
			        &proto->iovec_cntr_last_completed) == -1) 
	{
		err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
		    "unable to retrieve completion sdma counter: %s",
		    strerror(errno));
		break;
	}
    }

    if (did_yield) 
	proto->stats.writev_compl_delay++;

    PSMI_PROFILE_UNBLOCK();

    return err;
}

#define ERRCHK_NOT_SERIALIZED	1

psm_error_t 
ips_proto_timer_ack_callback(struct psmi_timer *current_timer, uint64_t current)
{
    struct ips_flow *flow = (struct ips_flow *) current_timer->context;
    ips_epaddr_t *ipsaddr = flow->ipsaddr;
    struct ips_proto *proto = ipsaddr->proto;
    uint64_t t_cyc_next = get_cycles();
    ips_scb_t *scb;

    if (STAILQ_EMPTY(&flow->scb_unacked))
	return PSM_OK;

    scb = STAILQ_FIRST(&flow->scb_unacked);
        
    if (current >= scb->abs_timeout) {
	int done_local;

#if ERRCHK_NOT_SERIALIZED
	/* We have to ensure that the send is at least locally complete before
	 * sending an error check or else earlier data can get to the
	 * destination *after* we pio this err_chk. 
	 */
	if (flow->transfer == PSM_TRANSFER_DMA) {
	  uint32_t dma_cntr;
	  uint32_t scb_cntr = 
	    STAILQ_LAST(&flow->scb_unacked, ips_scb, nextq)->dma_ctr;
	  done_local = 
	    (ipath_sdma_complete(proto->ptl->context->ctrl, &dma_cntr) > 0 &&
	     ((int) dma_cntr - (int) scb_cntr >= 0));
	  if (!done_local)
	    proto->stats.writev_compl_eagain++;
	}
	else
	  done_local = 1; /* Always done for PIO flows */
#else
	done_local = 1; /* Otherwise always done */
#endif

	scb->ack_timeout = 
	    min(scb->ack_timeout * flow->path->epr_timeout_ack_factor, 
		flow->path->epr_timeout_ack_max);
	scb->abs_timeout = t_cyc_next + scb->ack_timeout;
	
	if (done_local) {
	    _IPATH_VDBG("sending err_chk flow=%d with first=%d,last=%d\n",
		flow->flowid, STAILQ_FIRST(&flow->scb_unacked)->seq_num.psn,
		STAILQ_LAST(&flow->scb_unacked, ips_scb, nextq)->seq_num.psn);
	  
	    if (flow->protocol == PSM_PROTOCOL_TIDFLOW)
	      ips_proto_send_ctrl_message(flow, 
					  OPCODE_ERR_CHK_GEN,
					  &scb->tidsendc->ctrl_msg_queued,
					  NULL);
	    else
	      ips_proto_send_ctrl_message(flow,
					  OPCODE_ERR_CHK,
					  &flow->ipsaddr->ctrl_msg_queued,
					  NULL);
	}

	t_cyc_next = get_cycles() + scb->ack_timeout;
    }
    else 
	t_cyc_next += (scb->abs_timeout - current);

    psmi_timer_request(proto->timerq, current_timer, t_cyc_next);

    return PSM_OK;
}

psm_error_t 
ips_proto_timer_send_callback(struct psmi_timer *current_timer, uint64_t current)
{
    struct ips_flow *flow = (struct ips_flow *) current_timer->context;
    
    /* If flow is marked as congested adjust injection rate - see process nak
     * when a congestion NAK is received.
     */
    if_pf (flow->flags & IPS_FLOW_FLAG_CONGESTED) {
      struct ips_proto *proto = flow->ipsaddr->proto;

      /* Clear congestion flag and decrease injection rate */
      flow->flags &= ~IPS_FLOW_FLAG_CONGESTED;
      if ((flow->path->epr_ccti +
      proto->cace[flow->path->epr_sl].ccti_increase) <=
      proto->ccti_limit)
	ips_cca_adjust_rate(flow->path,
		proto->cace[flow->path->epr_sl].ccti_increase);
    }

    flow->fn.xfer.flush(flow, NULL);    
    return PSM_OK;
}

psm_error_t
ips_cca_adjust_rate(ips_path_rec_t *path_rec, int cct_increment)
{
  struct ips_proto *proto = path_rec->proto;
  uint16_t prev_ipd, prev_divisor;

  /* Increment/decrement ccti for path */
  psmi_assert_always(path_rec->epr_ccti >= path_rec->epr_ccti_min);
  path_rec->epr_ccti += cct_increment;
  
  /* Determine new active IPD.  */
  prev_ipd = path_rec->epr_active_ipd;
  prev_divisor = path_rec->epr_cca_divisor;
  if ((path_rec->epr_static_ipd) && 
      ((path_rec->epr_static_ipd + 1) > 
       (proto->cct[path_rec->epr_ccti] & CCA_IPD_MASK))) {
    path_rec->epr_active_ipd = path_rec->epr_static_ipd + 1;
    path_rec->epr_cca_divisor = 0;
  }
  else {
    path_rec->epr_active_ipd = proto->cct[path_rec->epr_ccti] & CCA_IPD_MASK;
    path_rec->epr_cca_divisor = 
      proto->cct[path_rec->epr_ccti] >> CCA_DIVISOR_SHIFT;
  }
  
  _IPATH_CCADBG("CCA: %s injection rate to <%x.%x> from <%x.%x>\n", (cct_increment > 0) ? "Decreasing" : "Increasing", path_rec->epr_cca_divisor, path_rec->epr_active_ipd, prev_divisor, prev_ipd);
  
  /* Reschedule CCA timer if this path is still marked as congested */
  if (path_rec->epr_ccti > path_rec->epr_ccti_min) {
    psmi_timer_request(proto->timerq,
		       &path_rec->epr_timer_cca,
		       get_cycles() + 
		       proto->cace[path_rec->epr_sl].ccti_timer_cycles);
  }
  
  return PSM_OK;
}

psm_error_t
ips_cca_timer_callback(struct psmi_timer *current_timer, uint64_t current) 
{
  ips_path_rec_t *path_rec = (ips_path_rec_t *) current_timer->context;
  
  /* Increase injection rate for flow. Decrement CCTI */
  if (path_rec->epr_ccti > path_rec->epr_ccti_min)
    return ips_cca_adjust_rate(path_rec, -1);
  else
    return PSM_OK;
}
