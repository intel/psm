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

#ifndef _IPS_PROTO_H
#define _IPS_PROTO_H

#include "psm_user.h"

#include "ips_recvhdrq.h"
#include "ips_tid.h"
#include "ips_scb.h"
#include "ips_epstate.h"
#include "ips_spio.h"
#include "ips_stats.h"
#include "ips_proto_am.h"
#include "ips_tidflow.h"
#include "ips_path_rec.h"

typedef enum ips_path_type {
  IPS_PATH_LOW_PRIORITY,
  IPS_PATH_NORMAL_PRIORITY,
  IPS_PATH_HIGH_PRIORITY,
  IPS_PATH_MAX_PRIORITY
} ips_path_type_t;

/* 
 * Local Endpoint info.
 *
 * Contains information necessary for composing packets for the local endpoint
 */
struct ips_epinfo {
  uint32_t	ep_baseqp;
  uint16_t      ep_base_lid;
  uint8_t       ep_lmc;
  uint8_t       ep_pad;
  ibta_rate     ep_link_rate;
  uint16_t	ep_context;
  uint16_t	ep_subcontext;
  uint16_t      ep_hca_type;
  uint16_t      ep_sl;     /* IPATH_SL only when path record not used */
  uint16_t	ep_unit;
  uint16_t	ep_mtu;
  uint16_t	ep_piosize;
  uint16_t      ep_hdrq_msg_size;
  uint16_t	ep_pkey;  /* PSM_PKEY only when path record not used */
  uint64_t	ep_timeout_ack; /* PSM_ERRCHK_TIMEOUT if no path record */
  uint64_t	ep_timeout_ack_max;
  uint32_t	ep_timeout_ack_factor;
};

/*
 * Remote Endpoint info.
 *
 * Contains information necessary for composing packets for a remote endpoint
 */
#define IPS_MAX_PATH_LMC 3
struct ips_epinfo_remote {
  uint32_t	epr_qp;		    /* qp+context encoding */
  uint32_t	epr_commidx_to;
  uint32_t	epr_commidx_from;    
  uint16_t	epr_piosize;
  uint16_t	epr_context;      /* Real context value */
  uint16_t	epr_subcontext;
  uint8_t       epr_hca_type;
  uint8_t       epr_hpp_index;
  
  /* For LMC/Torus keep list of base and max dlid. Used for pkt verification */
  uint16_t      epr_base_lid;
  uint16_t      epr_pkt_context;  /* Context encoding in packet header */
  uint16_t      epr_max_lid;
  uint8_t       epr_num_paths[IPS_PATH_MAX_PRIORITY];
  uint8_t       epr_next_path[IPS_PATH_MAX_PRIORITY];
  ips_path_rec_t *epr_path[IPS_PATH_MAX_PRIORITY][1 << IPS_MAX_PATH_LMC];
};

/*
 * Control messages.
 *
 * ips low-level control messages to ensure reliability of eager packets.
 *
 */
struct ips_proto;
psm_error_t
ips_proto_init(const psmi_context_t *context, 
	       const struct ptl *ptl, 
	       int num_of_send_bufs, int num_of_send_desc, uint32_t imm_size,
	       const struct psmi_timer_ctrl *timerq, /* PTL's timerq */
	       const struct ips_epstate *epstate, /* PTL's epstate */
	       const struct ips_spio *spioc, /* PTL's spio control */
	       struct ips_proto *proto); /* output protocol */

psm_error_t ips_proto_fini(struct ips_proto *proto, int force,
			   uint64_t timeout);

/*
 * For writev support, we need to pass the pbc along with the message header
 */
struct ips_pbc_header {
    union ipath_pbc		pbc;
    struct ips_message_header	hdr;
} PSMI_CACHEALIGN;

/*
 * Control message structures
 */
#define CTRL_MSG_QEUEUE_SIZE 32  /* power of two */

struct ips_proto_ctrl_message {
    struct ips_pbc_header	pbc_hdr;
    uint8_t _hdr_uwords[IPS_HEADER_QUEUE_UWORDS_MAX<<2];
} PSMI_CACHEALIGN;

/* Control messages saved in the control queue.  Even though we only
 * always send 2 ptl_args on the wire, some message types will save
 * more than 16 bytes in arguments.
 */
struct ips_flow;
struct ips_tid_recv_desc;

struct ips_ctrlq_elem {
    struct ptl_epaddr *ipsaddr;
    uint8_t	       message_type;
    uint8_t	       flowid;
    uint16_t           pad;
    uint32_t          *msg_queue_mask;
    struct ips_flow   *flow;
    ptl_arg_t	       args[3];
};

struct ips_ctrlq {
    /* Queued control messages, queued when pio is busy */
    struct ips_proto *ctrlq_proto;

    int		ctrlq_flowid;
    uint32_t	ctrlq_head;
    uint32_t	ctrlq_tail;
    uint32_t	ctrlq_overflow;
    uint32_t	ctrlq_never_enqueue;

    struct ips_ctrlq_elem   ctrlq_cqe[CTRL_MSG_QEUEUE_SIZE]  PSMI_CACHEALIGN;
    struct psmi_timer	    ctrlq_timer;    /* when in timerq */
};

/* 
 * Connect/disconnect, as implemented by ips 
 */
psm_error_t ips_proto_connect(struct ips_proto *proto, int numep, 
			    const psm_epid_t *array_of_epid, 
			    const int *array_of_epid_mask, 
			    psm_error_t *array_of_errors, 
			    psm_epaddr_t *array_of_epaddr, 
			    uint64_t timeout_in);

psm_error_t ips_proto_disconnect(struct ips_proto *proto, int force, int numep, 
			       const psm_epaddr_t array_of_epaddr[],
			       const int array_of_epaddr_mask[], 
			       psm_error_t array_of_errors[], 
			       uint64_t timeout_in);

int ips_proto_isconnected(struct ptl_epaddr *ipsaddr);

/*
 * Pending operation structures
 */
struct ips_pend_sreq {
    STAILQ_ENTRY(ips_pend_sreq)	next;
    psm_mq_req_t		req;
    uint32_t			type;
};

#define IPS_PENDSEND_EAGER_DATA	1
#define IPS_PENDSEND_EAGER_REQ	2
#define IPS_PENDSEND_EXP_TIDS	3
#define IPS_PENDSEND_EXP_SENDS	4

STAILQ_HEAD(ips_pendsendq, ips_pend_sreq);

struct ips_pend_sends {
    struct ips_proto	 *proto; /* back ptr */
    struct psmi_timer	 timer;
    struct ips_pendsendq pendq;
};

/*
 * One instance of the protocol
 */

struct ips_protoexp;

struct ips_proto_stats {
    uint64_t	pio_busy_cnt;
    uint64_t	writev_busy_cnt;
    uint64_t    writev_compl_eagain;
    uint64_t    writev_compl_delay;
    uint64_t	scb_egr_unavail_cnt;
    uint64_t	scb_exp_unavail_cnt;
    uint64_t	hdr_overflow;
    uint64_t	egr_overflow;
    uint64_t	lid_zero_errs;
    uint64_t	unknown_packets;
    uint64_t	stray_packets;
    uint64_t	send_dma_misaligns;
};

struct ips_proto_error_stats {
  uint64_t      num_icrc_err;
  uint64_t      num_vcrc_err;
  uint64_t      num_ecc_err;
  uint64_t      num_len_err;
  uint64_t      num_mtu_err;
  uint64_t      num_khdr_err;
  uint64_t      num_tid_err;
  uint64_t      num_mk_err;
  uint64_t      num_ib_err;
};

// OPP support structure.
struct opp_api {
  void* (*op_path_find_hca)(const char*name, void **device);
  void* (*op_path_open)(void *device, int port_num);
  void (*op_path_close)(void *context);
  int (*op_path_get_path_by_rec)(void *context, ibta_path_rec_t *query, ibta_path_rec_t *response);
  /* TODO: Need symbol to ibv_close_device. */
};

struct ips_ibta_compliance_fn {
  psm_error_t (*get_path_rec)(struct ips_proto *proto, uint16_t slid, 
			      uint16_t dlid, uint16_t desthca_type,
			      unsigned long timeout, 
			      ips_epaddr_t *ipsaddr);
  psm_error_t (*fini)(struct ips_proto *proto);
};

typedef enum ptl_epaddr_flow {
  EP_FLOW_GO_BACK_N_PIO,
  EP_FLOW_GO_BACK_N_DMA,
  EP_FLOW_GO_BACK_N_AM_REQ,
  EP_FLOW_GO_BACK_N_AM_RSP,
  EP_FLOW_LAST         /* Keep this the last endpoint flow */
} ptl_epaddr_flow_t;

struct ips_proto {
    struct ptl	      *ptl;	/* cached */
    psm_ep_t	       ep;	/* cached, for errors */
    psm_mq_t	       mq;	/* cached, for mq handling */
    int		       fd;	/* cached, for writev ops */

    /* Pending sends */
    struct ips_pend_sends   pend_sends;
    struct ips_epstate	    *epstate; 
    struct psmi_timer_ctrl   *timerq;

    struct ips_protoexp *protoexp; 
    struct ips_scbctrl	*scbc_rv;
    struct ips_spio	*spioc;
    struct ips_scbctrl	scbc_egr;
    struct ips_epinfo	epinfo;
    uint64_t	timeout_send;
    uint32_t	flags;
    uint32_t	iovec_cntr_next_inflight;
    uint32_t	iovec_cntr_last_completed;
    uint32_t	iovec_thresh_eager;
    uint32_t    iovec_thresh_eager_blocking;
    uint32_t	scb_max_sdma;
    uint32_t	scb_bufsize;
    uint16_t	scb_max_inflight;
    uint16_t    flow_credits;
    mpool_t	pend_sends_pool;
    struct ips_ibta_compliance_fn ibta;
    struct ips_proto_stats  stats;
    struct ips_proto_error_stats error_stats;
  
    struct ips_proto_am	proto_am;

    struct ips_ctrlq	ctrlq[EP_FLOW_LAST];

    /* Handling tid errors */
    uint32_t	tiderr_cnt;
    uint32_t	tiderr_max;
    uint64_t	tiderr_tnext;
    uint64_t	tiderr_warn_interval;
    uint32_t	tiderr_context_tid_off;
    psm_epid_t	tiderr_epid;

    uint64_t	t_init;
    uint64_t	t_fini;
    uint32_t	runid_key;

    int		    num_connected_to; 
    int		    num_connected_from;
    int		    num_disconnect_requests;

    /* misc state variables. */
// Smallest interval in cycles between which we warn about stray messages
// This is a per-endpoint quantity, overridable with PSM_STRAY_WARN_INTERVAL
// We use the same interval to send the "die" message.
    uint64_t	    stray_warn_interval;
    int		    done_warning;
    int		    done_once;
    int		    num_bogus_warnings;
    struct {
	uint32_t    interval_secs;
	uint64_t    next_warning;
	uint64_t    count;
    } psmi_logevent_tid_send_reqs;

    /* SL2VL table for protocol */
    int         sl2vl[16];

    /* CCA per port */
    uint16_t *cct; /* cct table */
    uint16_t  ccti_size; /* ccti table size */
    uint16_t  ccti_limit; /* should be <= size-1 */

    uint16_t  ccti_portctrl; /* QP or SL CC */
    uint16_t  ccti_ctrlmap; /* map for valid sl */
    struct cace { /* CACongestionEntry */
	uint8_t   ccti_increase; /* steps to increase */
	//uint16_t  ccti_timer; /* CCTI Timer in units of 1.024 usec */
	uint64_t  ccti_timer_cycles; /* coverted from us_2_cycles() */
	uint8_t   ccti_threshold; /* threshod to make log */
	uint8_t   ccti_min; /* min value for ccti */
    } cace[16]; /* 16 service level */

    /* Path record support */
    uint8_t ips_ipd_delay[IBTA_RATE_120_GBPS + 1];
    struct hsearch_data ips_path_rec_hash;
    void *opp_lib;
    void *hndl;
    void *device;
    void *opp_ctxt;
    struct opp_api opp_fn;

/*
 * Control message queue for pending messages.
 *
 * Control messages are queued as pending when no PIO is available for sending
 * the message.  They are composed on the fly and do not need buffering. 
 *
 * Variables here are write once (at init) and read afterwards (except the msg
 * queue overflow counters).
 */
    uint32_t ctrl_msg_queue_overflow;
    uint32_t ctrl_msg_queue_never_enqueue;
    uint32_t message_type_to_index[256];
#define message_type2index(proto, msg_type) (proto->message_type_to_index[(msg_type)] & ~CTRL_MSG_QUEUE_ALWAYS)

};

/* 
 * Updates to these stats must be reflected in ips_ptl_epaddr_stats_init
 */
struct ptl_epaddr_stats {
    uint64_t	err_chk_send;
    uint64_t	err_chk_recv;
    uint64_t	nak_send;
    uint64_t	nak_recv;
    uint64_t	connect_req;
    uint64_t	disconnect_req;
    uint64_t	tids_grant_send;
    uint64_t	tids_grant_recv;
    uint64_t	send_rexmit;
    uint64_t    congestion_pkts;  /* IB CCA FECN packets */
};

/*
 * Endpoint address, encapsulates per-endpoint protocol metadata
 *
 * Directly implements the ptl epaddr.
 */

/* 
 * Flow index (6 bits) encodes the following:
 *
 * Protocol: 3 bits
 * Flow Index:   3 bits
 *
 * Currently only two protocols supported: Go Back N (the "original" flow)
 * and the TIDFLOW. We may look at adding other protocols like 
 * Selective ACK and maybe even STCP.
 *
 * The Flow index is protocol specific. For a Go Back N protocol this usually
 * refers to the index of the flow between two endpoints. For TIDFLOWS
 * this is not currently used.
 */

#define IPS_MAX_PROTOCOL	8
#define IPS_MAX_FLOWINDEX	8
 
#define IPS_FLOWID_PACK(protocol,flowindex)   \
  ( ((((uint16_t)protocol)&0x7) << 3) |	      \
    (((uint16_t)flowindex)&0x7) )

#define IPS_FLOWID_GET_PROTO(flow)    (((flow)>>3)&0x7)
#define IPS_FLOWID_GET_INDEX(flow)    ((flow) % 4)

#define IPS_FLOWID2INDEX(flow)	\
   ((flow)&0x7)

typedef void (*ips_flow_enqueue_fn_t)(struct ips_flow *flow, ips_scb_t *scb);
typedef psm_error_t (*ips_flow_flush_fn_t)(struct ips_flow *, int *nflushed);
typedef void (*ips_flow_nak_postprocess_fn_t)(struct ips_flow *, struct ips_message_header *p_hdr);

typedef enum psm_transfer_type {
  PSM_TRANSFER_PIO,
  PSM_TRANSFER_DMA,
  PSM_TRANSFER_LAST    /* Keep this the last transfer type */
} psm_transfer_type_t;

typedef enum psm_protocol_type {
  PSM_PROTOCOL_GO_BACK_N,
  PSM_PROTOCOL_TIDFLOW,
  PSM_PROTOCOL_LAST   /* Keep this the last protocol type */
} psm_protocol_type_t;

struct ips_transfer_fn {
  /* Functions dealing with enqueuing and flushing scbs to the network */
  ips_flow_enqueue_fn_t enqueue;
  ips_flow_flush_fn_t   flush;
};

struct ips_protocol_fn {
  /* FLOW_ADD: Other functions for is_valid etc. */
  ips_flow_nak_postprocess_fn_t nak_post_process;
};

struct ips_flow_fn {
  struct ips_transfer_fn xfer;
  struct ips_protocol_fn protocol;
};

#define PIO_TRANSFER_FUNCTIONS {		\
    .enqueue = ips_proto_flow_enqueue,		\
    .flush   = ips_proto_flow_flush_pio		\
}

#define DMA_TRANSFER_FUNCTIONS {		\
    .enqueue = ips_proto_flow_enqueue,		\
    .flush   = ips_proto_flow_flush_dma	        \
}

#define GO_BACK_N_PROTOCOL_FUNCTIONS {		\
    .nak_post_process = NULL			\
}

#define TIDFLOW_PROTOCOL_FUNCTIONS {		\
    .nak_post_process = ips_tidflow_nak_post_process \
}

struct ips_flow {
    SLIST_ENTRY(ips_flow)   next; /* List of flows with pending acks */
    struct ips_flow_fn fn;
	      
    struct ptl_epaddr *ipsaddr;	/* back pointer, remote endpoint */
    struct ips_epinfo *epinfo;  /* back pointer, local epinfo */
    ips_path_rec_t    *path; 	/* Path to use for flow */
    psm_transfer_type_t transfer;
    psm_protocol_type_t protocol;

    uint32_t flowid;
    uint32_t frag_size;
    uint16_t flags;
    uint16_t sl;
    uint16_t cca_ooo_pkts;			   
    uint16_t credits;           /* Current credits available to send on flow */
    uint16_t cwin;              /* Size of congestion window */
    uint16_t ack_interval;
    uint16_t msg_ooo_toggle;	/* toggle for OOO message */
    uint16_t msg_ooo_seqnum;	/* seqnum for OOO message */

    psmi_seqnum_t xmit_seq_num;
    psmi_seqnum_t xmit_ack_num;
    psmi_seqnum_t recv_seq_num;
    psmi_seqnum_t last_seq_num;

    uint32_t scb_num_pending;
    uint32_t scb_num_unacked;

    psmi_timer timer_send;   /* timer for frames that got a busy PIO */
    psmi_timer timer_ack;    /* timer for unacked frames */

    STAILQ_HEAD(ips_scb_unackedq, ips_scb)  scb_unacked;
    SLIST_HEAD(ips_scb_pendlist, ips_scb)   scb_pend;
};

struct ptl_epaddr {
    struct ptl	      *ptl;	/* cached */
    psm_epaddr_t       epaddr;	/* back pointer to psm top-level epaddr */
    struct ips_proto  *proto;	/* back pointer to protocol */
    psm_mq_t	       mq;	/* cached */

    uint16_t			flags;	/* per-endpoint flags */
    struct ips_epinfo_remote	epr;	/* remote endpoint params */
    struct ips_flow		flows[EP_FLOW_LAST]	    PSMI_CACHEALIGN;
    struct ips_flow		tidgr_flow; /* tidflow */

    uint32_t ctrl_msg_queued; /* bitmap of queued control messages to be send */
    uint32_t delay_in_ms;   /* used in close */
    uint64_t s_timeout;	    /* used as a time in close */
    int credit;
    
    pthread_mutex_t sesslock;
    struct ptl_epaddr_stats stats;

    uint32_t runid_key;
    uint16_t psm_verno;	    
    uint16_t connect_verno; /* The lowest connect version we can support */
    uint16_t cstate_to;
    uint16_t cstate_from;
    psm_error_t cerror_to;
    psm_error_t cerror_from;
} 
__attribute__((aligned(64)));


/*
 * Send support on scbs.
 *
 */
void ips_flow_init(struct ips_flow *flow, ips_path_rec_t *path, 
		   ips_epaddr_t *ipsaddr, 
		   psm_transfer_type_t transfer_type, 
		   psm_protocol_type_t protocol, ips_path_type_t path_type,
		   uint32_t flow_index);

void ips_scb_prepare_flow(ips_scb_t *scb, struct ips_epinfo *epinfo, 
		          struct ips_epinfo_remote *epr, struct ips_flow *flow);

void ips_proto_flow_enqueue(struct ips_flow *flow, ips_scb_t *scb);

psm_error_t ips_proto_flow_flush_pio(struct ips_flow *flow, int *nflushed);
psm_error_t ips_proto_flow_flush_dma(struct ips_flow *flow, int *nflushed);

/* Wrapper for enqueue + flush */
psm_error_t ips_proto_scb_pio_send(struct ips_flow *flow, ips_scb_t *scb);

void	    ips_proto_scb_dma_enqueue(struct ips_proto *proto, ips_scb_t *scb);
psm_error_t ips_proto_scb_dma_flush(struct ips_proto *proto, ips_epaddr_t *ipsaddr,
				    int *nflushed);
psm_error_t ips_proto_dma_wait_until(struct ips_proto *proto, uint32_t dma_ctr);
psm_error_t ips_proto_dma_wait(struct ips_proto *proto, uint32_t dma_ctr,
			       uint32_t *dma_ctr_out);

psm_error_t ips_dma_transfer_frame(struct ips_proto *proto, 
				   struct ips_flow *flow,
				   struct ips_pbc_header *pbc_hdr,
				   void *payload, uint32_t paylen, 
				   uint32_t cksum);

/* Special-case for expected sends */
void	    ips_protoexp_scb_inflight(ips_scb_t *scb);

/*
 * Protocol receive processing
 *
 */
/* NAK post processing for tidflows */
void ips_tidflow_nak_post_process(struct ips_flow *flow, 
				  struct ips_message_header *p_hdr);
/* Actual receive processing is an inline in ips_proto_help.h */
int ips_proto_process_packet_inner(struct ips_recvhdrq_event *rcv_ev);
/* Error handling for unknown packet, packet is unknown when epid doesn't match
 * in epstate table */
int ips_proto_process_unknown(const struct ips_recvhdrq_event *rcv_ev);
/* Exposed for fastpath only */
void ips_proto_process_ack(struct ips_recvhdrq_event *rcv_ev);
/* Handling error cases */
int ips_proto_process_packet_error(struct ips_recvhdrq_event *rcv_ev);

/*
 * Protocol exception handling and frame dumps
 */
void ips_proto_get_rhf_errstring(uint32_t err, char *msg, size_t len);
void ips_proto_dump_err_stats(struct ips_proto *proto);
void ips_proto_show_rhf_errors(const uint32_t *rhdr);
void ips_proto_show_header(struct ips_message_header *p_hdr, char *msg);
void ips_proto_dump_frame(void *frame, int lenght, char *message);
void ips_proto_dump_data(void *data, int data_length);
void ips_proto_dump_eager(uint32_t *curr_rcv_hdr);

/*
 * Checksum of ips packets
 */
uint32_t ips_crc_calculate(uint32_t len, uint8_t *data, uint32_t crc);

/*
 * Expected send support
 */
/*
 * The expsend token is currently always a pointer to a MQ request.  It is
 * echoed on the wire throughout various phases of the expected send protocol
 * to identify a particular send.
 */
typedef void (*ips_tid_completion_callback_t)(void *);

psm_error_t ips_protoexp_init(const psmi_context_t *context,
			      const struct ips_proto *proto,
			      uint32_t protoexp_flags,
			      int num_of_send_bufs,
			      int num_of_send_desc,
			      struct ips_protoexp **protoexp_o);

psm_error_t ips_protoexp_fini(struct ips_protoexp *protoexp);
void ips_protoexp_handle_tiderr(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_data_err(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_tf_seqerr(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_handle_tf_generr(const struct ips_recvhdrq_event *rcv_ev);

void ips_protoexp_recv_unaligned_data(struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_data(struct ips_recvhdrq_event *rcv_ev);

void ips_protoexp_tid_grant(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_tid_grant_ack(const struct ips_recvhdrq_event *rcv_ev);
int  ips_protoexp_tid_release(const struct ips_recvhdrq_event *rcv_ev);
void ips_protoexp_tid_release_ack(const struct ips_recvhdrq_event *rcv_ev);

int  ips_protoexp_build_ctrl_message(struct ips_protoexp *protoexp, 
				     struct ptl_epaddr *ipsaddr,
				     ptl_arg_t *args,
				     uint16_t *pkt_flags,
			             uint8_t opcode, void *payload);
psm_error_t ips_protoexp_flow_newgen(struct ips_tid_recv_desc *tidrecvc);

/*
 * Peer is waiting (blocked) for this request
 */
#define IPS_PROTOEXP_TIDGET_WAIT	0x1
#define IPS_PROTOEXP_TIDGET_PEERWAIT	0x2
psm_error_t ips_protoexp_tid_get_from_token(struct ips_protoexp *protoexp,
				 void *buf, uint32_t length, 
				 psm_epaddr_t epaddr,
				 uint32_t remote_tok, uint32_t flags,
				 ips_tid_completion_callback_t callback,
				 void *context);

/*
 * Matched-Queue processing and sends
 */
psm_error_t ips_proto_mq_push_eager_req(struct ips_proto *proto, 
					psm_mq_req_t req);
psm_error_t ips_proto_mq_push_eager_data(struct ips_proto *proto, 
					 psm_mq_req_t req);

int ips_proto_mq_handle_cts(struct ips_proto *proto, ptl_arg_t *args);

int ips_proto_mq_handle_rts_envelope(psm_mq_t mq, int mode, psm_epaddr_t epaddr, 
			     uint64_t tag, uint32_t reqidx_peer, 
			     uint32_t msglen);
int ips_proto_mq_handle_rts_envelope_outoforder(psm_mq_t mq, int mode,
			     psm_epaddr_t epaddr, uint16_t msg_seqnum,
			     uint64_t tag, uint32_t reqidx_peer, 
			     uint32_t msglen);

psm_error_t ips_proto_mq_send(psm_mq_t mq, psm_epaddr_t epaddr, 
			      uint32_t flags, uint64_t tag, const void *ubuf, 
			      uint32_t len);

psm_error_t ips_proto_mq_isend(psm_mq_t mq, psm_epaddr_t epaddr, 
			       uint32_t flags, uint64_t tag, const void *ubuf, 
			       uint32_t len, void *context, psm_mq_req_t *req_o);

int ips_proto_am(struct ips_recvhdrq_event *rcv_ev);

/* IBTA feature related functions (path record, sl2vl etc.) */
psm_error_t ips_ibta_init_sl2vl_table(struct ips_proto *proto);
psm_error_t ips_ibta_link_updown_event(struct ips_proto *proto);
psm_error_t ips_ibta_init(struct ips_proto *proto);
psm_error_t ips_ibta_fini(struct ips_proto *proto);

#endif /* _IPS_PROTO_H */
