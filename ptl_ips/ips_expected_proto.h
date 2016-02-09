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
 * Control and state structure for one instance of the expected protocol.  The
 * protocol depends on some upcalls from internal portions of the receive
 * protocol (such as opcodes dedicated for expected protocol handling)
 */

/* Generate an expected header every 16 packets */
#define PSM_DEFAULT_EXPECTED_HEADER 16

struct ips_protoexp {
    const struct ptl	  *ptl;
    struct ips_proto	  *proto;
    struct psmi_timer_ctrl *timerq;
    struct ips_tid	  tidc;
    struct ips_tfctrl      tfctrl;

    unsigned int           tidflow_seed;
    ptl_epaddr_flow_t      tid_ep_flow;
    uint32_t		   tid_flags;
    psm_transfer_type_t    tid_xfer_type;
    struct ips_scbctrl	   tid_scbc_rv;
    mpool_t		   tid_desc_send_pool;
    mpool_t		   tid_desc_recv_pool;
    mpool_t		   tid_getreq_pool;
    mpool_t		   tid_sreq_pool; /* backptr into proto->ep->mq */
    mpool_t		   tid_rreq_pool; /* backptr into proto->ep->mq */
    uint32_t		   tid_send_fragsize;
    uint32_t		   tid_page_offset_mask;
    uint64_t		   tid_page_mask;
    uint64_t		   tid_to_cyc_min;
    uint64_t		   tid_to_cyc_max; 
    uint32_t		   tid_to_intr;
    uint32_t		   tid_min_expsend_cnt;
    uint32_t               hdr_pkt_interval; 
    struct ips_tidinfo     *tid_info;
    
    STAILQ_HEAD(ips_tid_send_pend,		    /* pending exp. sends */
		ips_tid_send_desc)   pend_sendq;
    struct psmi_timer		     timer_send;

    STAILQ_HEAD(ips_tid_get_pend, 
		ips_tid_get_request)	pend_getreqsq; /* pending tid reqs */
    struct psmi_timer			timer_getreqs;

    /* stats */
    uint64_t tid_grant_resends;
    uint64_t tid_release_resends;
    uint64_t tid_intr_reqs;
};

/*
 * TID member list format used in communication.  The receiver associates
 * physical pages to tids and communicates a list of tid,offset,length for 
 * each registered page.
 *
 * This format is currently the only one we support, although it is not as
 * compact as we would like and other formats are planned in the near future
 */
#define IPS_TID_SESSTYPE_MEMBER_LIST    1

typedef struct {
	uint16_t tid;
	uint16_t offset;
	uint16_t length;
} 
ips_tid_session_member;

typedef struct {
	uint16_t    tsess_type;
	uint16_t    tsess_tidcount;
	uint16_t    tsess_tidlist_length;
	uint16_t    tsess_unaligned_start;
	uint16_t    tsess_unaligned_end;

	ptl_arg_t   tsess_descid;
	uint32_t    tsess_seqno;
	uint32_t    tsess_srcoff;
	uint32_t    tsess_length;

	ips_tid_session_member tsess_list[0];	/* must be last in struct */
} 
ips_tid_session_list;

/*
 * Send-side expected send descriptors.
 *
 * Descriptors are allocated when tid grant requests are received (the 'target'
 * side of an RDMA get request).  Descriptors are added to a pending queue of
 * expected sends and processed one at a time (scb's are requested and messages
 * sent until all fragments of the descriptor's length are put on the wire).
 *
 */
#define TIDSENDC_SDMA_VEC_DEFAULT	260

struct ips_tid_send_desc {
    struct ips_protoexp		    *protoexp;
    STAILQ_ENTRY(ips_tid_send_desc) next;

    /* Filled in at allocation time */
    ptl_arg_t	  descid;
    uint32_t	  length;
    ips_epaddr_t *ipsaddr;
    psm_mq_req_t  mqreq;
    struct ips_flow tidflow;
    
    uint32_t ctrl_msg_queued; /* bitmap of queued control messages for flow */
    uint32_t completion_counter;
				    
    /* Iterated during send progress */
    void	*buffer;
    void	*bounce_buf;
    int		tid_idx; 
    int		is_complete;
    uint32_t	remaining_bytes;   
    uint32_t	remaining_bytes_in_page;				    
    uint32_t	frame_send;
    uint32_t	offset;
    uint32_t	iovec_cntr_last;
    uint32_t	release_cnt;
    uint32_t    unaligned_sent;
    uint32_t    pad;
				    
    psmi_timer   timer_tidrelease;

    union {
        ips_tid_session_list tid_list;
        uint8_t filler[2096]; 
    };
};

#define TIDRECVC_STATE_FREE      0
#define TIDRECVC_STATE_GRANT     1
#define TIDRECVC_STATE_GRANT_ACK 2
#define TIDRECVC_STATE_DONE      3

struct ips_expected_recv_stats {
  uint32_t     nSeqErr;
  uint32_t     nGenErr;
  uint32_t     nReXmit;
  uint32_t     nErrChkReceived;
};

struct ips_tid_recv_desc {
    const psmi_context_t *context;
    struct ips_protoexp	 *protoexp;
    ips_epaddr_t	 *ipsaddr;
    STAILQ_ENTRY(ips_tid_recv_desc) next;
				    
    /* desc id held in tid_list below */
    void	*buffer;
    uint32_t    num_recv_hdrs;
    uint32_t	recv_msglen;
    uint32_t	grant_cnt;    
    uint32_t    state;
    uint32_t    cksum;
    uint16_t	recv_framecnt;
    uint16_t	flags;

    /* TF protocol state (recv) */
    uint32_t    tidflow_idx;
    uint32_t    tidflow_active_gen;
				    
    psmi_seqnum_t tidflow_genseq;
    uint16_t    tidflow_nswap_gen;
    uint16_t    pad;

    uint32_t ctrl_msg_queued; /* bitmap of queued control messages for */
    struct ips_expected_recv_stats stats;				    
    			    
    struct ips_tid_get_request	*getreq;
    psmi_timer   timer_tidreq;

    ips_tidmap_t	 ts_map;
    union {
	ips_tid_session_list tid_list; 
	uint8_t		 filler[2096];
    };
};

/*
 * Get requests, issued by MQ when there's a match on a large message.  Unlike
 * an RDMA get, the initiator identifies the location of the data at the target
 * using a 'send token' instead of a virtual address.  This, of course, assumes
 * that the target has already registered the token and communicated it to the
 * initiator beforehand (it actually sends the token as part of the initial
 * MQ message that contains the MQ tag).
 *
 * The operation is semantically a two-sided RDMA get.
 */
struct ips_tid_get_request {
    STAILQ_ENTRY(ips_tid_get_request)	tidgr_next;
    struct ips_protoexp		*tidgr_protoexp;
    psm_epaddr_t		 tidgr_epaddr;
					
    void			 *tidgr_lbuf;
    uint32_t			  tidgr_length;
    uint32_t			  tidgr_rndv_winsz;
    uint32_t			  tidgr_sendtoken;
    ips_tid_completion_callback_t tidgr_callback;
    void			 *tidgr_ucontext;

    uint32_t	tidgr_offset;	/* offset in bytes */
    uint32_t	tidgr_bytesdone;
    uint32_t	tidgr_desc_seqno;
    uint32_t	tidgr_flags;
};

/*
 * For debug and/or other reasons, we can log the state of each tid and
 * optionally associate it to a particular receive descriptor
 */

#define TIDSTATE_FREE	0
#define TIDSTATE_USED	1

struct ips_tidinfo {
    uint16_t tid;
    uint16_t state;
    struct ips_tid_recv_desc *tidrecvc;
};

/*
 * Descriptor limits, structure contents of struct psmi_rlimit_mpool for
 * normal, min and large configurations.
 */
#define TID_SENDSESSIONS_LIMITS {				\
	    .env = "PSM_TID_SENDSESSIONS_MAX",			\
	    .descr = "Tid max send session descriptors",	\
	    .env_level = PSMI_ENVVAR_LEVEL_HIDDEN,		\
	    .minval = 1,					\
	    .maxval = 1<<30,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 256, 4096 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = {   1,    1 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 512, 8192 }		\
	}

#define TID_RECVSESSIONS_LIMITS {				\
	    .env = "PSM_TID_RECVSESSIONS_MAX",			\
	    .descr = "Tid max receive session descriptors",	\
	    .env_level = PSMI_ENVVAR_LEVEL_HIDDEN,		\
	    .minval = 1,					\
	    .maxval = 512,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = {  32, 512 },		\
	    .mode[PSMI_MEMMODE_MINIMAL] = {   1,   1 },		\
	    .mode[PSMI_MEMMODE_LARGE]   = {  32, 512 }		\
	}
