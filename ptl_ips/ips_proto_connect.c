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

#define COMMIDX_MAX	65535	    /* Last valid communication idx is 65535 */

/* Connections are not pairwise but we keep a single 'epaddr' for messages from
 * and messages to a remote 'epaddr'.  State transitions for connecting TO and
 * FROM 'epaddrs' are the following:
 * Connect TO:
 *   NONE -> WAITING -> ESTABLISHED -> WAITING_DISC -> DISCONNECTED -> NONE
 *
 * Connect FROM (we receive a connect request)
 *   NONE -> ESTABLISHED -> NONE
 */
#define CSTATE_ESTABLISHED	1
#define CSTATE_NONE		2 
#define CSTATE_TO_DISCONNECTED	3
#define CSTATE_TO_WAITING	4
#define CSTATE_TO_WAITING_DISC	5

#define IPS_CONNECT_VERNO    0x0201 /* major,major,minor,minor */
#define BIG_ENDIAN_TEST_WORD 0xA5A5

/* We can use up to 16-bits of features, we only use 5 of them for now. */
#define EP_FEATURES_ENDIAN_BIG    0x0001
#define EP_FEATURES_ENDIAN_LITTLE 0x0002
#define EP_FEATURES_BITWIDTH_32   0x0004
#define EP_FEATURES_BITWIDTH_64   0x0008
#define EP_FEATURES_RCVTHREAD	  0x8000
#define EP_FEATURES_MULTIFLOW     0x4000

#define EP_FEATURES_NODETYPE	  0x0f

struct connect_msghdr {
    uint8_t	opcode;		
    uint8_t	_unused1;		

    uint16_t	connect_verno;	/* be */
    uint16_t	psm_verno;	/* be */
    uint16_t	phase;		/* be connect/disconnect phase (unused now) */
  
    uint16_t    hca_type;       /* HCA type of remote endpoint */
    uint16_t    sl;             /* Default SL request for remote endpoint*/
    uint32_t	_unused[1];

    psm_uuid_t	uuid; 
};
#define IPS_CONNECT_MSGHDR_SIZE	32   /* 16 + 16-byte-uuid */

struct ips_connect_reqrep {
    struct connect_msghdr  hdr;
    uint32_t	flags;		    /* unused */
    uint16_t	connect_result;	    /* be */

    /* Per-job info */
    uint32_t	commidx;	    /* ignore if 0xffffffff */
    uint32_t	runid_key;	    /* one-time stamp connect key */
    uint16_t	job_pkey;	    /* (future use) */
    uint64_t	_unused1[4];

    /* Per-node characteristics */
    uint32_t	features;	    /* be - endpoint desc (endian + bidwidth) */
    uint16_t	hdrq_msg_size;	    /* where is the header/eager cutoff */
    uint16_t	mtu;		    /* receive payload */
    char	hostname[128];	    /* always NULL-terminated */
    uint64_t	_unused2[4];

    uint8_t	version_1_offset[0];
};

/* Used for sanity checking in processing message arrivals */
#define IPS_CONNECT_REQREP_MINIMUM_SIZE	\
	(offsetof(struct ips_connect_reqrep, version_1_offset))
#define IPS_MAX_CONNECT_PAYLEN 512

struct ips_disconnect_reqrep {
    struct connect_msghdr  hdr;
    uint32_t	flags;		    /* unused */

    uint16_t	mode;
    uint16_t	_unused1[3];
    uint64_t	_unused2[4];
    uint8_t	version_1_offset[0];
};
/* Used for sanity checking in processing message arrivals */
#define IPS_DISCONNECT_REQREP_MINIMUM_SIZE	\
	(offsetof(struct ips_disconnect_reqrep, version_1_offset))

const struct ips_transfer_fn psmi_xfer_fn[PSM_TRANSFER_LAST] = 
  {
    PIO_TRANSFER_FUNCTIONS,
    DMA_TRANSFER_FUNCTIONS
  };

const struct ips_protocol_fn psmi_protocol_fn[PSM_PROTOCOL_LAST] = 
  {
    GO_BACK_N_PROTOCOL_FUNCTIONS,
    TIDFLOW_PROTOCOL_FUNCTIONS
  };

/* Startup protocol in PSM/IPS
 *
 * Start timer.
 *
 * For all nodes to connect to:
 *   Grab connect lock
 *   Look up epid in table
 *      MATCH.
 *         assert cstate_to != CONNECT_WAITING (no re-entrancy)
 *         If cstate_to == CONNECT_DONE
 *            return the already connected address.
 *         else
 *            assert cstate_to == CONNECT_NONE
 *            assert cstate_from == CONNECT_DONE
 *            cstate_to := CONNECT_WAITING
 *            assert commidx_to != UNKNOWN && commidx_from != UNKNOWN
 *            req->commidx := epaddr->commidx_from 
 *            add to list of pending connect.
 *      NO MATCH
 *         allocate epaddr and put in table
 *         cstate_to := CONNECT_WAITING
 *         cstate_from := CONNECT_NONE
 *         commidx_to := UNKNOWN
 *         req->commidx := epaddr->commidx_from := NEW commidx integer
 *         add to list of pending connect
 *   Release connect lock
 *
 * expected_connect_count = ep->total_connect_count + num_to_connect
 * while (expected_connect_count != ep->total_connect_count)
 *    check for timeout
 *    progress();
 *
 * For all connection requests received (within progress loop)
 *   If uuid doesn't match, NAK the connect and skip request
 *   Grab connect lock
 *   Lock up epid in table
 *      MATCH
 *	   if cstate_from == CONNECT_DONE
 *	      req->commidx := epaddr->commidx_from
 *            compose reply and send again (this is a dupe request).
 *         else
 *            assert cstate_from == CONNECT_NONE
 *            assert cstate_to == (CONNECT_WAITING | CONNECT_DONE)
 *            cstate_from := CONNECT_DONE
 *            epaddr->commidx_to := req->commidx
 *            req->commidx := epaddr->commidx_from
 *      NO MATCH
 *         allocate epaddr and put in table
 *         cstate_from := CONNECT_DONE
 *         epaddr->commidx_to = req->commidx;
 *         rep->commidx := epaddr->commidx_from := NEW commidx integer
 *         compose connect reply and send
 *   Release connect lock
 *
 * For all connection replies received:
 *    If connect_result != 0, process error and skip.
 *    assert cstate_to == CONNECT_WAITING
 *    if cstate_from == CONNECT_DONE
 *       assert rep->commidx == epaddr->commidx_to
 *    else
 *	 epaddr->commidx_to := rep->commidx
 *    cstate_to := CONNECT_DONE
 *    ep->total_connect_count ++
 *
 *   * Fill in a connection request:
 *      1. Set connect protocol version and PSM versions
 *      2. Set the uuid attached to current endpoint and add the job_pkey
 *         the node wishes to communicate post-connect.
 *      3. Set our mtu, bitwidth and endianess to detect inconsistencies
 *
 */

/* Due to an oversight in the inital protocol, only 16 of the 32 bits can
 * actually be used because the little-to-big endian conversion was done with
 * 16 bits from the first version in 2.0. */
static
uint32_t
psmi_ips_node_features(psm_ep_t ep)
{
    uint32_t features = 0;
    if (BIG_ENDIAN_TEST_WORD == __cpu_to_be16(BIG_ENDIAN_TEST_WORD))
	features |= EP_FEATURES_ENDIAN_BIG;
    else
	features |= EP_FEATURES_ENDIAN_LITTLE;
    if (sizeof(uintptr_t) == 8)
	features |= EP_FEATURES_BITWIDTH_64;
    else
	features |= EP_FEATURES_BITWIDTH_32;
    if (ep->context.runtime_flags & PSMI_RUNTIME_RCVTHREAD)
	features |= EP_FEATURES_RCVTHREAD;
    features |= EP_FEATURES_MULTIFLOW;

    return features;
}

static
int
node_matches_bitendian(psm_ep_t ep, uint32_t features)
{
    if ((features & EP_FEATURES_NODETYPE) ==
	(psmi_ips_node_features(ep) & EP_FEATURES_NODETYPE))
	return 1;
    else
	return 0;
}

/*
 * Given a connection request, set mtu, communication index and hdr length
 * parameters.
 *
 * The most subtle parameter is the mtu.  When set as 'req->mtu', the mtu 
 * is our connecting peer's declared mtu (which may not be the same as our
 * mtu).  The approach is to take the smaller of both mtus when communicating
 * with that peer.  Also, when using pio, the size can be further restricted by
 * the pio send buffer sizes (i.e. 4K IB MTU but only 2K PIO buffers).
 */
static
psm_error_t
ips_ipsaddr_set_req_params(struct ips_proto *proto,
			   ips_epaddr_t *ipsaddr, 
			   const struct ips_connect_reqrep *req,
			   uint32_t paylen)
{
    psmi_assert_always(req->mtu > 0);

    uint32_t peer_mtu = min(req->mtu, proto->epinfo.ep_mtu);
    
    ipsaddr->epr.epr_piosize = min(peer_mtu, proto->epinfo.ep_piosize);
    ipsaddr->epr.epr_hca_type= req->hdr.hca_type;
    
    if (ipsaddr->epr.epr_piosize > PSM_CACHE_LINE_BYTES)
      ipsaddr->epr.epr_piosize &= ~(PSM_CACHE_LINE_BYTES - 1);
    
    /* 
     * DMA is bounded by the peer's mtu put also our local PIO send size
     */
    ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO].frag_size = ipsaddr->epr.epr_piosize;
    ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA].frag_size = peer_mtu;
    ipsaddr->flows[EP_FLOW_GO_BACK_N_AM_REQ].frag_size=ipsaddr->epr.epr_piosize;
    ipsaddr->flows[EP_FLOW_GO_BACK_N_AM_RSP].frag_size=ipsaddr->epr.epr_piosize;

    ipsaddr->epr.epr_commidx_to = req->commidx;

    /* 
     * For static routes i.e. "none" path resolution update all paths to
     * have the same profile (mtu, sl etc.).
     *
     * For path record queries the epr_mtu and epr_sl are setup correctly
     * from the path itself.
     */
    if (proto->ep->path_res_type == PSM_PATH_RES_NONE) {
      int ptype, pidx;
      for (ptype = IPS_PATH_LOW_PRIORITY; ptype < IPS_PATH_MAX_PRIORITY;ptype++)
	for (pidx = 0; pidx < ipsaddr->epr.epr_num_paths[ptype]; pidx++) {
	  ipsaddr->epr.epr_path[ptype][pidx]->epr_mtu = peer_mtu;
	  ipsaddr->epr.epr_path[ptype][pidx]->epr_sl = req->hdr.sl;
	}
    }
    
    if (paylen > sizeof(struct ips_connect_reqrep)) {
	int count;
	char *p = (char *)(req + 1);
	paylen -= sizeof(struct ips_connect_reqrep);
	if (paylen%(sizeof(uint64_t)+sizeof(psm_epid_t))) {
	    return PSM_INTERNAL_ERR;
	}
	count = paylen / (sizeof(uint64_t)+sizeof(psm_epid_t));
	if (count > IPATH_MAX_UNIT) return PSM_INTERNAL_ERR;

	memcpy(ipsaddr->epaddr->mctxt_gidhi, p, count*sizeof(uint64_t));
	p += count*sizeof(uint64_t);
	memcpy(ipsaddr->epaddr->mctxt_epid, p, count*sizeof(psm_epid_t));
	ipsaddr->epaddr->mctxt_epcount = count;
    }

    return psmi_epid_set_hostname(psm_epid_nid(ipsaddr->epaddr->epid), 
				       (char*) req->hostname, 0);
}

static psm_error_t __recvpath
ips_proto_send_ctrl_message_request(struct ips_proto *proto,
                                    struct ips_flow *flow, uint8_t message_type, 
                                    uint32_t *msg_queue_mask, void *payload,
				    uint64_t timeout)
{
    psm_error_t err = PSM_OK;

    while (get_cycles() < timeout) {
        err = ips_proto_send_ctrl_message(flow, message_type,
                                          msg_queue_mask, payload);
        if (err == PSM_OK) {
	    break;
        }
        if ((err = psmi_err_only(psmi_poll_internal(proto->ep, 1)))) {
	    break;
	}
    }
    return err;
}

static psm_error_t __recvpath
ips_proto_send_ctrl_message_reply(struct ips_flow *flow, uint8_t message_type, 
                                  uint32_t *msg_queue_mask, void *payload)
{
    /* This will try up to 100 times until the message is sent. The code
     * is persistent becausing dropping replies will lead to a lack of
     * overall progress on the connection/disconnection. We do not want
     * to poll from here, and we cannot afford a lengthy timeout, since 
     * this is called from the receive path.
     */
    psm_error_t err = PSM_OK;
    int i;
    for (i = 0; i < 100; i++) {
        err = ips_proto_send_ctrl_message(flow, message_type,
                                          msg_queue_mask, payload);
        if (err == PSM_OK) {
	    break;
        }
    }
    return err;
}

int
ips_proto_build_connect_message(struct ips_proto *proto, 
			       struct ips_proto_ctrl_message *msg, 
			       ips_epaddr_t *ipsaddr, uint8_t opcode,
			       void *payload)
{
    struct connect_msghdr *hdr = (struct connect_msghdr *) payload;
    struct ips_connect_reqrep *req = 
		(struct ips_connect_reqrep *) payload;
    uint32_t paylen = sizeof(struct connect_msghdr);

    /* Write standard header that goes out on all connect msgs */
    hdr->connect_verno = __cpu_to_be16(IPS_CONNECT_VERNO);
    hdr->psm_verno     = __cpu_to_be16(PSMI_VERNO);
    hdr->opcode        = opcode;
    hdr->phase         = 0;
    hdr->hca_type      = proto->epinfo.ep_hca_type;
    hdr->sl            = ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_sl;

    /* Some times we simply echo disconnect requests since we can get dupe
     * disconnect requests.  Unless that's the case, we always send the full
     * uuid */
    psmi_assert_always(proto != NULL);
    memcpy(&hdr->uuid, &proto->ep->key, sizeof(psm_uuid_t));

    switch (opcode) {
	case OPCODE_CONNECT_REPLY:
	case OPCODE_CONNECT_REQUEST: 
#if 0
	    psmi_assert_always(ipsaddr->cerror_from != PSM_OK ||
			    !COMMIDX_IS_UNKNOWN(proto, ipsaddr->commidx_from));
#endif
	    if (opcode == OPCODE_CONNECT_REQUEST) {
		req->connect_result = __cpu_to_be16(PSM_OK);
		req->runid_key = proto->runid_key;
	    }
	    else {
		req->connect_result = __cpu_to_be16(ipsaddr->cerror_from);
		req->runid_key = ipsaddr->runid_key;
	    }
	    req->flags     = 0;
	    req->commidx   = (uint32_t) ipsaddr->epr.epr_commidx_from;
	    req->job_pkey  = ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_pkey;

	    req->features      = 
		    __cpu_to_be16(psmi_ips_node_features(proto->ep));
	    req->hdrq_msg_size = proto->epinfo.ep_hdrq_msg_size;
	    req->mtu = ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_mtu;
	    strncpy(req->hostname, psmi_gethostname(),
		sizeof(req->hostname) - 1);
	    req->hostname[sizeof(req->hostname) - 1] = '\0';
	    paylen	      = sizeof(struct ips_connect_reqrep);

	    /* Attach all multi-context subnetids and epids. */
	    if (proto->ep->mctxt_master == proto->ep) {
		psm_epid_t *epid;
		psm_ep_t ep = proto->ep->mctxt_next;
		uint64_t *subnetid = (uint64_t *)(req + 1);
		/* first all subnetids */
		while (ep != proto->ep) {
			*subnetid = ep->gid_hi;
			subnetid++;
			ep = ep->mctxt_next;
			paylen += sizeof(uint64_t);
		}
		ep = proto->ep->mctxt_next;
		epid = (psm_epid_t *)subnetid;
		/* second all epids */
		while (ep != proto->ep) {
			*epid = ep->epid;
			epid++;
			ep = ep->mctxt_next;
			paylen += sizeof(psm_epid_t);
		}
	    }
	    psmi_assert_always(paylen <= IPS_MAX_CONNECT_PAYLEN); 
	break;

	case OPCODE_DISCONNECT_REQUEST:
	case OPCODE_DISCONNECT_REPLY:
	    paylen	   = sizeof(struct ips_disconnect_reqrep);
	    break;
	default:
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		"Unexpected/unhandled connection opcode 0x%x\n",
		opcode);
	    break;
    }
    return paylen;
}

void
ips_flow_init(struct ips_flow *flow, ips_path_rec_t *path, ips_epaddr_t *ipsaddr, psm_transfer_type_t transfer_type, psm_protocol_type_t protocol, ips_path_type_t path_type, uint32_t flow_index)
{
    struct ips_proto *proto = ipsaddr->proto;
    
    psmi_assert_always(protocol < IPS_MAX_PROTOCOL);
    psmi_assert_always(flow_index < IPS_MAX_FLOWINDEX);

    SLIST_NEXT(flow, next) = NULL;
    flow->fn.xfer = psmi_xfer_fn[transfer_type];
    flow->fn.protocol = psmi_protocol_fn[protocol];
    
    /* If path is not specified pick one accordingly */
    if (!path)
      path = ips_select_path(proto, path_type, ipsaddr);
    
    flow->path = path;
    flow->ipsaddr = ipsaddr;
    flow->epinfo  = &proto->epinfo;
    flow->transfer= transfer_type;
    flow->protocol= protocol;
    flow->flowid  = IPS_FLOWID_PACK(protocol, flow_index);
    flow->xmit_seq_num.val = 0;
    flow->xmit_ack_num.val = 0;
    flow->xmit_ack_num.pkt--; /* last acked */
    flow->recv_seq_num.val = 0;
    flow->flags = 0;
    flow->sl    = flow->path->epr_sl;
    flow->cca_ooo_pkts = 0;			    
    flow->credits = flow->cwin = proto->flow_credits;
    flow->ack_interval = max((proto->flow_credits >> 2) - 1, 1);
    flow->scb_num_pending = 0;
    flow->scb_num_unacked = 0;

    psmi_timer_entry_init(&(flow->timer_ack),
			  ips_proto_timer_ack_callback, flow);

    psmi_timer_entry_init(&(flow->timer_send),
			  ips_proto_timer_send_callback, flow);

    STAILQ_INIT(&flow->scb_unacked);
    SLIST_INIT(&flow->scb_pend);
    return;
}

static
size_t
epaddr_size()
{
    return (size_t) (sizeof(struct psm_epaddr) + sizeof(struct ptl_epaddr));
}

static
psm_error_t
ips_init_ep_qp_and_pkt_context(uint16_t hca_type, uint32_t qp, 
                               uint32_t context, ips_epaddr_t *ipsaddr)
{
    psm_error_t err = PSM_OK;
    switch(hca_type) {
    case PSMI_HCA_TYPE_QLE73XX:
        /* Bit 5 of the context is inserted into bit 0 of QP */
        ipsaddr->epr.epr_qp = (qp & ~0x1) | (context >> 4);
        ipsaddr->epr.epr_pkt_context = context & 0xf;
        break;
    case PSMI_HCA_TYPE_QLE72XX:
        if (context == 16) {
	    /* For context 16, the bottom bit of qp is toggled */
	    ipsaddr->epr.epr_qp = qp ^ 1;
	    ipsaddr->epr.epr_pkt_context = 15;
        }
        else {
	    ipsaddr->epr.epr_qp = qp;
	    ipsaddr->epr.epr_pkt_context = context;
        }
        break;
    case PSMI_HCA_TYPE_QLE71XX:
        ipsaddr->epr.epr_qp = qp;
        ipsaddr->epr.epr_pkt_context = context;
        break;
    default: 
        err = PSM_PARAM_ERR;
        break;
    }
    return err;
}

static
psm_epaddr_t
ips_alloc_epaddr(struct ips_proto *proto, psm_epid_t epid, 
		 const char *hostname, unsigned long timeout)
{
    psm_error_t err = PSM_OK;
    psm_epaddr_t epaddr;
    ips_epaddr_t *ipsaddr;
    uint64_t lid, context, subcontext;
    uint16_t hca_type, path_dlid;
    uint16_t lmc_mask = ~((1 << proto->epinfo.ep_lmc) - 1);
    int i;
    ips_path_type_t prio;
    
    /* The PSM/PTL-level and ips-level epaddr structures are colocated in
     * memory for performance reasons -- this is why ips allocates memory for
     * both the PSM/PTL-level and ips-level epaddr structure.
     * 
     * The PSM/PTL structure data is filled in upon successfuly ep connect in
     * ips_ptl_connect().
     */
    epaddr = (psm_epaddr_t) psmi_calloc(proto->ep, PER_PEER_ENDPOINT, 
					1, epaddr_size());
    if (epaddr == NULL)
	return NULL;

    epaddr->ptl  = proto->ptl;
    epaddr->ptlctl = proto->ptl->ctl;
    epaddr->ep = proto->ep;
    STAILQ_INIT(&epaddr->egrlong);
    STAILQ_INIT(&epaddr->egrdata);
    epaddr->xmit_egrlong.egr_data = 0;
    epaddr->outoforder_q.first = NULL;
    epaddr->outoforder_q.lastp = &epaddr->outoforder_q.first;
    epaddr->mctxt_master = epaddr;
    epaddr->mctxt_current = epaddr;
    epaddr->mctxt_prev = epaddr->mctxt_next = epaddr;
    
    /* IPS-level epaddr */
    ipsaddr = (ips_epaddr_t *)(epaddr+1);
    epaddr->ptladdr = ipsaddr;
    
    ipsaddr->ptl    = proto->ptl;
    ipsaddr->mq	    = proto->mq;
    ipsaddr->epaddr = epaddr;
    ipsaddr->proto  = proto;
    
    /* Setup base fields for remote epid before doing path record lookup:
     */
    lid = PSMI_EPID_GET_LID(epid);
    context = PSMI_EPID_GET_CONTEXT(epid);
    subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
    hca_type = PSMI_EPID_GET_HCATYPE(epid);
    /* Actual context of peer */
    ipsaddr->epr.epr_context = context; 
    
    /* Setup remote endpoint <context,sucontext> */
    err = ips_init_ep_qp_and_pkt_context(hca_type, proto->epinfo.ep_baseqp,
					 context, ipsaddr);
    if (err != PSM_OK) {
	_IPATH_ERROR("Connect: Warning! unknown HCA type %d. Assuming remote HCA is same as local.\n", hca_type);
        ips_init_ep_qp_and_pkt_context(hca_type, proto->epinfo.ep_baseqp,
                          PSMI_EPID_GET_CONTEXT(proto->ep->epid), ipsaddr);
    }

    /* Subcontext */
    ipsaddr->epr.epr_subcontext = subcontext;

    /* Get path record for <service, slid, dlid> tuple */
    err = proto->ibta.get_path_rec(proto, proto->epinfo.ep_base_lid, 
				   __cpu_to_be16(lid), hca_type, timeout,
				   ipsaddr);
    if (err != PSM_OK) {
      psmi_free(epaddr);
      return NULL;
    }
  
    /* Determine base lid across all paths */
    ipsaddr->epr.epr_base_lid = 
      __be16_to_cpu(ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_dlid);

    for (prio = IPS_PATH_LOW_PRIORITY; prio < IPS_PATH_MAX_PRIORITY; prio++)
      for (i = 0; i < ipsaddr->epr.epr_num_paths[prio]; i++) {
	path_dlid = __be16_to_cpu(ipsaddr->epr.epr_path[prio][i]->epr_dlid);
	if (path_dlid < ipsaddr->epr.epr_base_lid)
	  ipsaddr->epr.epr_base_lid = path_dlid;
      }
    

    /* Finally construct the resolved epaddr->epid for this peer (For torus
     * SL and even the lid may be different!) 
     */
    path_dlid = ipsaddr->epr.epr_base_lid & lmc_mask;

    epaddr->epid = 
      PSMI_EPID_PACK_EXT(path_dlid,
			 context, subcontext,
			 hca_type, 
			 ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_sl);
        
    /* Add this epid as a known hostname to our epid hostname db */
    if (psmi_epid_set_hostname(psm_epid_nid(epid), hostname, 0))
	return NULL;
    
    ipsaddr->flags = 0;
    
    /* All flows are over BULK path. Only control messages use the high
     * priority CONTROL path.
     */
    ips_flow_init(&ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO], NULL,
		  ipsaddr, PSM_TRANSFER_PIO, PSM_PROTOCOL_GO_BACK_N,
		  IPS_PATH_NORMAL_PRIORITY, EP_FLOW_GO_BACK_N_PIO);
    
    /* DMA flow uses the same path as PIO flow due to multi MTU sized
     * eager messages. If we use separate paths we are more likely to have
     * payload arrive out of order with respect to envelope leading to 
     * un-necessary NAKs.
     */
    ips_flow_init(&ipsaddr->flows[EP_FLOW_GO_BACK_N_DMA],
		  ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO].path,
		  ipsaddr, PSM_TRANSFER_DMA, PSM_PROTOCOL_GO_BACK_N,
		  IPS_PATH_NORMAL_PRIORITY, EP_FLOW_GO_BACK_N_DMA);
    
    /* AM Request messages also use the same path as the PIO flow as they
     * also require order with respect to the MPI request messages.
     */
    ips_flow_init(&ipsaddr->flows[EP_FLOW_GO_BACK_N_AM_REQ],
		  ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO].path,
		  ipsaddr, PSM_TRANSFER_PIO, PSM_PROTOCOL_GO_BACK_N,
		  IPS_PATH_NORMAL_PRIORITY, EP_FLOW_GO_BACK_N_AM_REQ);
    
    ips_flow_init(&ipsaddr->flows[EP_FLOW_GO_BACK_N_AM_RSP], NULL,
		  ipsaddr, PSM_TRANSFER_PIO, PSM_PROTOCOL_GO_BACK_N,
		  IPS_PATH_NORMAL_PRIORITY, EP_FLOW_GO_BACK_N_AM_RSP);

    /* tidflow for tid get request */
    ips_flow_init(&ipsaddr->tidgr_flow, NULL, ipsaddr,
		  PSM_TRANSFER_DMA, PSM_PROTOCOL_TIDFLOW,
		  IPS_PATH_LOW_PRIORITY, 0);

    ipsaddr->cstate_to   = CSTATE_NONE;
    ipsaddr->cstate_from = CSTATE_NONE;

    /* For now, set these to our PSM versions and connect versions.  They will
     * be overwritten to the peer's versions in handling connection reqs 
     */
    ipsaddr->psm_verno     = PSMI_VERNO;
    ipsaddr->connect_verno = IPS_CONNECT_VERNO;

    /* Add epaddr to PSM's epid table */
    psmi_epid_add(proto->ep, epaddr->epid, epaddr);
    psmi_assert_always(psmi_epid_lookup(proto->ep, epaddr->epid) == epaddr);

    return epaddr;
}

static
void
ips_free_epaddr(ips_epaddr_t *ipsaddr)
{
    psm_epaddr_t epaddr = ipsaddr->epaddr;
    _IPATH_VDBG("epaddr=%p,ipsaddr=%p,commidx_from=%d\n", epaddr, ipsaddr,
	    ipsaddr->epr.epr_commidx_from);
    psmi_epid_remove(ipsaddr->proto->ep, epaddr->epid);
    ips_epstate_del(ipsaddr->proto->epstate, ipsaddr->epr.epr_commidx_from);
    psmi_free(epaddr);
    return;
}

static psm_error_t ips_get_addr_from_epid(struct ips_proto *proto,
					  psm_epid_t epid, 
					  unsigned long timeout,
					  psm_epaddr_t *epaddr)
{
  psm_error_t err;
  uint64_t lid, context, subcontext;
  uint16_t hca_type, path_dlid;
  psm_epid_t path_epid;
  psm_epaddr_t ep_address = NULL;
  uint16_t lmc_mask = ~((1 << proto->epinfo.ep_lmc) - 1);
  ips_epaddr_t ipsaddr;
  
  /* First unpack to get slid/dlid. */
  lid = PSMI_EPID_GET_LID(epid);
  context = PSMI_EPID_GET_CONTEXT(epid);
  subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
  hca_type = PSMI_EPID_GET_HCATYPE(epid);
  
  /* Get path record for <service, slid, dlid> tuple */
  err = proto->ibta.get_path_rec(proto, proto->epinfo.ep_base_lid, 
				 __cpu_to_be16(lid), hca_type,
				 timeout, &ipsaddr);
  if (err != PSM_OK)
    goto fail;
    
  /* Generate path epid to do lookup on - uses the SL from the path record. 
   */
  path_dlid = (__be16_to_cpu(ipsaddr.epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_dlid)) & lmc_mask;

  path_epid = 
    PSMI_EPID_PACK_EXT(path_dlid,
		       context, subcontext, hca_type, 
		       ipsaddr.epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_sl);
  ep_address = psmi_epid_lookup(proto->ep, path_epid);
  
 fail:
  *epaddr = ep_address;
  return err;
}

static 
psm_error_t 
ptl_handle_connect_req(struct ips_proto *proto, psm_epid_t epid, 
		       psm_epaddr_t epaddr, struct ips_connect_reqrep *req, 
		       uint32_t paylen, int uuid_valid);

psm_error_t
ips_proto_process_connect(struct ips_proto *proto, psm_epid_t epid, 
			  uint8_t opcode, struct ips_message_header *p_hdr, 
			  void *payload, uint32_t paylen)
{
    psm_epaddr_t epaddr;
    ips_epaddr_t *ipsaddr;
    struct connect_msghdr *hdr;
    uint16_t connect_result;
    psm_ep_t ep = proto->ep;
    int uuid_valid;
    int uwords = (proto->epinfo.ep_hdrq_msg_size>>2) -
	IPS_HEADER_QUEUE_IWORDS - IPS_HEADER_QUEUE_HWORDS;
    int hdrq_extra;
    uint32_t lid, context, subcontext;
    uint16_t lmc_mask = ~((1 << proto->epinfo.ep_lmc) - 1);

    PSMI_PLOCK_ASSERT();
    
    struct ips_connect_reqrep *req;
    psm_error_t err = PSM_OK;
    
    /* If the sender doesn't have the same header/eager cutoff, we need to make
     * sure we copy the connect data into a contiguous buffer */
    char buf[IPS_MAX_CONNECT_PAYLEN] PSMI_CACHEALIGN;
    
    hdrq_extra = uwords - p_hdr->hdr_dlen;
    if (hdrq_extra != 0) {
	uint32_t *bufp = (uint32_t *) buf;
	uint32_t *payp = (uint32_t *) payload;
	_IPATH_VDBG("hdrq_extra is %d, uwords=%d, inwords=%d\n",
		    hdrq_extra, uwords, p_hdr->hdr_dlen);
	int hdrq_extra = uwords - p_hdr->hdr_dlen;
	if (hdrq_extra > 0) { /* some of it went into our hdrq */
	    psmi_mq_mtucpy(bufp, &p_hdr->data[0].u32w0 + p_hdr->hdr_dlen, 
			   hdrq_extra<<2);
	    psmi_mq_mtucpy(bufp+hdrq_extra, payload, paylen);
	    paylen += (hdrq_extra<<2);
	}
	else { /* we got some useless padding in eager */
	    hdrq_extra = -hdrq_extra;
	    paylen -= (hdrq_extra<<2);
	    psmi_mq_mtucpy(bufp, payp + hdrq_extra, paylen);
	}
	payload = buf;
    }

    hdr = (struct connect_msghdr *) payload;
    if (paylen < sizeof(struct connect_msghdr)) { /* drop */
	_IPATH_PRDBG("dropping unknown connect message of length %d\n", paylen);
	return PSM_OK;
    }
    
    /* Obtain HCA type and SL from request and regenerate epid */
    lid = PSMI_EPID_GET_LID(epid);
    context = PSMI_EPID_GET_CONTEXT(epid);
    subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
    epid = PSMI_EPID_PACK_EXT(lid & lmc_mask, context, subcontext, hdr->hca_type, hdr->sl);

    /* Don't need to call ips_get_addr_from_epid as the epid cache is keyed
     * of the IPS_PATH_HIGH_PRIORITY dlid and the SL which we already have from
     * the connect request (as all control messages uses the CONTROL path).
     */
    epaddr = psmi_epid_lookup(proto->ep, epid);
    ipsaddr = epaddr ? epaddr->ptladdr : NULL;

    uuid_valid = (psmi_uuid_compare(ep->key, hdr->uuid) == 0);

    if ((opcode == OPCODE_CONNECT_REQUEST || opcode == OPCODE_CONNECT_REPLY) &&
	paylen < IPS_CONNECT_REQREP_MINIMUM_SIZE) 
    {
	uint64_t lid, context, subcontext;
	char *type = opcode == OPCODE_CONNECT_REQUEST ? "request" : "reply";
	lid = PSMI_EPID_GET_LID(epid);
	context = PSMI_EPID_GET_CONTEXT(epid);
	subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
	psmi_syslog(proto->ep, 1, LOG_INFO,
	    "Unrecognized connect %s (size is %d instead of %d) "
	    "from epid %ld:%ld:%ld\n", type, paylen, 
	    (int) IPS_CONNECT_REQREP_MINIMUM_SIZE,
	    (long) lid, (long) context, (long) subcontext);
	goto fail; /* Not fatal, just drop the packet */
    }

    switch (opcode) {
	case OPCODE_CONNECT_REQUEST:
	    err = ptl_handle_connect_req(proto, epid, epaddr, 
		    (struct ips_connect_reqrep *) payload, paylen, uuid_valid);
	    break;

	case OPCODE_CONNECT_REPLY:
	    req = (struct ips_connect_reqrep *) payload;
	    if (!ipsaddr || req->runid_key != proto->runid_key) {
		uint64_t lid, context, subcontext;

		lid = PSMI_EPID_GET_LID(epid);
		context = PSMI_EPID_GET_CONTEXT(epid);
		subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
		_IPATH_PRDBG("Unknown connectrep (ipsaddr=%p, %d,%d) "
			"from epid %ld:%ld:%ld bad_uuid=%s\n",
			ipsaddr, req->runid_key, proto->runid_key,
			(long) lid, (long) context, (long) subcontext,
			uuid_valid ? "NO" : "YES");
		break;
	    }
	    if (ipsaddr->cstate_to != CSTATE_TO_WAITING) {
		/* possible dupe */
		_IPATH_VDBG("connect dupe, expected %d got %d\n",
			    CSTATE_TO_WAITING, ipsaddr->cstate_to);
		break;
	    }
	    connect_result = __be16_to_cpu(req->connect_result);

	    /* Reply to our request for connection (i.e. outgoing connection) */
	    if (ipsaddr->cstate_from != CSTATE_ESTABLISHED) {
		err = ips_ipsaddr_set_req_params(proto, ipsaddr, req, paylen);
		if (err) goto fail;
	    }
	    ipsaddr->cstate_to  = CSTATE_ESTABLISHED;
	    ipsaddr->cerror_to  = connect_result;

	    break;

	case OPCODE_DISCONNECT_REQUEST:
	{
	    ips_epaddr_t ipsaddr_f; /* fake a ptl addr */
	    int ipsaddr_do_free = 0;
	    psmi_assert_always(paylen >= IPS_DISCONNECT_REQREP_MINIMUM_SIZE);
	    _IPATH_VDBG("Got a disconnect from %s\n", psmi_epaddr_get_name(epid));
	    proto->num_disconnect_requests++;
	    /* It's possible to get a disconnection request on a ipsaddr that
	     * we've since removed if the request is a dupe.  Instead of
	     * silently dropping the packet, we "echo" the request in the
	     * reply. */
	    if (ipsaddr == NULL) {
		uint16_t src_context = IPS_HEADER_SRCCONTEXT_GET(p_hdr);
		uint32_t qp;

		ipsaddr = &ipsaddr_f;
		memset(&ipsaddr_f, 0, sizeof(ips_epaddr_t));
		ipsaddr_f.epr.epr_context = src_context;
		ipsaddr_f.epr.epr_subcontext = p_hdr->src_subcontext;
	
		/* QLE72XX is special for context 16 */
		if ((hdr->hca_type == PSMI_HCA_TYPE_QLE72XX) && 
		    (src_context == 16))
		        ipsaddr_f.epr.epr_pkt_context = 15;

		/* Get path record for peer */
		err = proto->ibta.get_path_rec(proto, 
					       proto->epinfo.ep_base_lid, 
					       __cpu_to_be16(lid), 
					       hdr->hca_type,
					       3000, &ipsaddr_f);
		if (err != PSM_OK)
		  goto fail;

		qp =  proto->epinfo.ep_baseqp;
                err = ips_init_ep_qp_and_pkt_context(hdr->hca_type, qp,
						     src_context, &ipsaddr_f);
		if (err != PSM_OK) {
	            _IPATH_ERROR("Disconnect: Warning! unknown HCA type %d.\n", hdr->hca_type);
		    goto fail;
		}
		
		ipsaddr_f.proto = proto;
		ipsaddr_f.ptl = (ptl_t *) -1;
		/* If the send fails because of pio_busy, don't let ips queue
		 * the request on an invalid ipsaddr, just drop the reply */
		ipsaddr_f.ctrl_msg_queued = ~0;
		ips_flow_init(&ipsaddr_f.flows[EP_FLOW_GO_BACK_N_PIO], NULL,
			      &ipsaddr_f, PSM_TRANSFER_PIO, 
			      PSM_PROTOCOL_GO_BACK_N, IPS_PATH_LOW_PRIORITY,
			      EP_FLOW_GO_BACK_N_PIO);
		_IPATH_VDBG("Disconnect on unknown epaddr, just echo request\n");
	    }
	    else if (ipsaddr->cstate_from != CSTATE_NONE) {
		ipsaddr->cstate_from = CSTATE_NONE;
		proto->num_connected_from--;
		if (ipsaddr->cstate_to == CSTATE_NONE) {
		    ipsaddr_do_free = 1;
		}
		if (!uuid_valid) {
		    uint64_t lid, context, subcontext;

		    lid = PSMI_EPID_GET_LID(epid);
		    context = PSMI_EPID_GET_CONTEXT(epid);
		    subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
		    _IPATH_VDBG("Unknown disconnect request from epid %d:%d.%d "
			"bad_uuid=%s\n", (int) lid, 
			(int) context, (int) subcontext, uuid_valid ? "NO" : "YES");
		}
	    }

	    memset(buf, 0, sizeof buf);
	    ips_proto_send_ctrl_message_reply(&ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO], 
					      OPCODE_DISCONNECT_REPLY,
					      &ipsaddr->ctrl_msg_queued, buf);
	    /* We can safely free the ipsaddr if required since disconnect
	     * messages are never enqueued so no reference to ipsaddr is kept */
	    if (ipsaddr_do_free)
		ips_free_epaddr(ipsaddr);
	}
	break;

	case OPCODE_DISCONNECT_REPLY:
	    if (!ipsaddr || !uuid_valid) {
		uint64_t lid, context, subcontext;
		lid = PSMI_EPID_GET_LID(epid);
		context = PSMI_EPID_GET_CONTEXT(epid);
		subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
		_IPATH_VDBG("Unknown disconnect reply from epid %d:%d.%d bad_uuid=%s\n",
			(int) lid, (int) context, (int) subcontext,
			uuid_valid ? "NO" : "YES");
		break;
	    }
            else if (ipsaddr->cstate_to == CSTATE_TO_WAITING_DISC) {
		ipsaddr->cstate_to = CSTATE_TO_DISCONNECTED;
		/* Freed in disconnect() if cstate_from == NONE */
	    } /* else dupe reply */
	    break;

	default:
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		"Unexpected/unhandled connect opcode 0x%x\n",
		opcode);
    }
fail:
    return err;
}

static 
psm_error_t 
ptl_handle_connect_req(struct ips_proto *proto, psm_epid_t epid, 
		       psm_epaddr_t epaddr, struct ips_connect_reqrep *req, 
		       uint32_t paylen, int uuid_valid)
{
    ips_epaddr_t *ipsaddr;
    psm_error_t	err = PSM_OK;
    uint16_t connect_result = PSM_OK;
    uint16_t psm_verno;
    uint16_t c_verno;
    uint16_t features;
    int newconnect = 0;
    char buf[IPS_MAX_CONNECT_PAYLEN] PSMI_CACHEALIGN;

    if (epid == proto->ep->epid) {
	/* For 2.0, we won't expose handling for this error */
	psmi_handle_error(PSMI_EP_NORETURN, PSM_EPID_NETWORK_ERROR,
		"Network connectivity problem: Locally detected duplicate "
		"LIDs 0x%04x on hosts %s and %s. (Exiting)",
		(uint32_t) psm_epid_nid(epid),
		psmi_epaddr_get_hostname(epid),
		psmi_gethostname());
	/* XXX no return */
	abort();
    }
    else if (epaddr == NULL) { /* new ep connect before we call into connect */
	newconnect = 1;
	if ((epaddr = ips_alloc_epaddr(proto, epid, req->hostname, 
				       5000)) == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
    }
    ipsaddr = epaddr->ptladdr;
    if (ipsaddr->cstate_from  == CSTATE_ESTABLISHED) {
	/* Duplicate lid detection.  */
	if (ipsaddr->runid_key == req->runid_key && uuid_valid)
	    goto do_reply; /* duplicate request, not duplicate lid */
	else if (uuid_valid) { 
	    /* True blue duplicate lid, both connect messages are part of the
	     * same context since they use the same uuid */ 
	    /* For 2.0, we won't expose handling for this error */
	    psmi_handle_error(PSMI_EP_NORETURN, PSM_EPID_NETWORK_ERROR,
		"Network connectivity problem: Detected duplicate "
		"LIDs 0x%x on hosts %s (key=%d) and %s (key=%d). (Exiting)",
		(uint32_t) psm_epid_nid(ipsaddr->epaddr->epid), 
		psmi_epaddr_get_hostname(epid),
		ipsaddr->runid_key,
		req->hostname,
		req->runid_key);
	}
	else { /* Some out of context message.  Just drop it */
	    if (!proto->done_warning) {
		psmi_syslog(proto->ep, 1, LOG_INFO, 
		    "Non-fatal connection problem: Received an out-of-context "
		    "connection message from host %s LID=0x%x context=%d. (Ignoring)",
		    req->hostname, (int) psm_epid_nid(epid), psm_epid_context(epid));
		proto->done_warning = 1;
	    }
	    goto no_reply;
	}
    }
    psmi_assert_always(ipsaddr->cstate_from == CSTATE_NONE);

    /* Save requestor's connection and psm version numbers */
    c_verno   = __be16_to_cpu(req->hdr.connect_verno);
    psm_verno = __be16_to_cpu(req->hdr.psm_verno);
    features  = __be16_to_cpu(req->features);

    /* On PSM pre-2.0, just print message and exit if the connect version
     * number is not at least 0x0201 */
    if (c_verno < 0x0201) {
	psmi_handle_error(PSMI_EP_NORETURN, PSM_EPID_INVALID_VERSION,
	    "Connect protocol (%x,%x) is obsolete and incompatible",
	    (c_verno >> 8) & 0xff, c_verno & 0xff);
	connect_result = PSM_EPID_INVALID_CONNECT;
    }
    /* Whenever there's a protocol change, adjust handling here */
    else if ((IPS_CONNECT_VERNO & 0xff00) != (ipsaddr->connect_verno & 0xff00)) {
	connect_result = PSM_EPID_INVALID_VERSION;
    }
    else if (!node_matches_bitendian(proto->ep, features))
	connect_result = PSM_EPID_INVALID_NODE;
    else if (!psmi_verno_isinteroperable(__be16_to_cpu(req->hdr.psm_verno))) {
	connect_result = PSM_EPID_INVALID_VERSION;
    }
    else if (!(proto->flags & IPS_PROTO_FLAG_QUERY_PATH_REC) && 
	     proto->epinfo.ep_pkey != IPATH_DEFAULT_P_KEY && 
	     proto->epinfo.ep_pkey != req->job_pkey) {
	connect_result = PSM_EPID_INVALID_PKEY;
    }
    else if (!uuid_valid) {
	char ep_key[37], req_key[37];
	connect_result = PSM_EPID_INVALID_UUID_KEY;
	psmi_uuid_unparse(proto->ep->key, ep_key);
	psmi_uuid_unparse(req->hdr.uuid, req_key);
	_IPATH_PRDBG("UUID key mismatch request key=%s endpoint key=%s\n",
		    req_key, ep_key);
    }
    else if (!psmi_verno_isinteroperable(ipsaddr->psm_verno)) {
	connect_result = PSM_INIT_BAD_API_VERSION;
    }
    else {
	connect_result = PSM_OK;
	if (ipsaddr->cstate_to == CSTATE_NONE) {
	    ips_epstate_idx idx;
	    psmi_assert_always(newconnect == 1);
	    err = ips_epstate_add(proto->epstate, ipsaddr, &idx);
	    if (err)
		goto fail;
	    ipsaddr->epr.epr_commidx_from = idx;
	}
    }
    ipsaddr->connect_verno = c_verno;
    ipsaddr->psm_verno = psm_verno;

    /* Incoming connection request */
    if (ipsaddr->cstate_to != CSTATE_ESTABLISHED) {
	err = ips_ipsaddr_set_req_params(proto, ipsaddr, req, paylen);
	if (err) goto fail;
    }
    ipsaddr->cstate_from = CSTATE_ESTABLISHED;
    ipsaddr->cerror_from = connect_result;

    ipsaddr->runid_key  = req->runid_key;
    ipsaddr->flags |= features & EP_FEATURES_RCVTHREAD ?
		      SESS_FLAG_HAS_RCVTHREAD : 0;
    ipsaddr->flags |= proto->ep->context.runtime_flags & PSMI_RUNTIME_RCVTHREAD ?
		      SESS_FLAG_LOCK_SESS : 0;
    ipsaddr->flags |= features & EP_FEATURES_MULTIFLOW ?
		      SESS_FLAG_HAS_FLOWID : 0;

    pthread_mutex_init(&ipsaddr->sesslock, NULL);

    proto->num_connected_from++;

do_reply:
    ips_proto_send_ctrl_message_reply(&ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO], 
				      OPCODE_CONNECT_REPLY,
				      &ipsaddr->ctrl_msg_queued, buf);
no_reply:
fail:
    return err;
}

psm_error_t
ips_proto_connect(struct ips_proto *proto, int numep, 
		const psm_epid_t *array_of_epid, 
		const int *array_of_epid_mask, psm_error_t *array_of_errors, 
		psm_epaddr_t *array_of_epaddr, uint64_t timeout_in)
{
    int i, n, n_first;
    psm_error_t err = PSM_OK;
    psm_epaddr_t epaddr;
    ips_epaddr_t *ipsaddr = NULL;
    int numep_toconnect = 0, numep_left;
    char buf[IPS_MAX_CONNECT_PAYLEN] PSMI_CACHEALIGN;
    union psmi_envvar_val credits_intval;
    int connect_credits;

    psmi_getenv("PSM_CONNECT_CREDITS",
                "End-point connect request credits.",
                PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) 100,
                &credits_intval);

    connect_credits = credits_intval.e_uint;

    PSMI_PLOCK_ASSERT();

    /* All timeout values are in cycles */ 
    uint64_t t_start = get_cycles();
    /* Print a timeout at the warning interval */
    union psmi_envvar_val warn_intval;
    uint64_t to_warning_interval;
    uint64_t to_warning_next;

    /* Setup warning interval */
    psmi_getenv("PSM_CONNECT_WARN_INTERVAL",
		"Period in seconds to warn if connections are not completed."
		"Default is 300 seconds, 0 to disable",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 300,
		&warn_intval);
    
    to_warning_interval = nanosecs_to_cycles(warn_intval.e_uint * SEC_ULL);
    to_warning_next = t_start + to_warning_interval;

    /* Some sanity checks */
    psmi_assert_always(sizeof(struct connect_msghdr) == IPS_CONNECT_MSGHDR_SIZE);
    psmi_assert_always(array_of_epid_mask != NULL);
    psmi_assert_always(sizeof(struct ips_connect_reqrep) >= 
		       IPS_CONNECT_REQREP_MINIMUM_SIZE);
    psmi_assert_always(sizeof(struct ips_disconnect_reqrep) >= 
		       IPS_DISCONNECT_REQREP_MINIMUM_SIZE);

    /* First pass: make sure array of errors is at least fully defined */
    for (i = 0; i < numep; i++) {
	uint64_t lid, context, subcontext;

	lid = PSMI_EPID_GET_LID(array_of_epid[i]);
	context = PSMI_EPID_GET_CONTEXT(array_of_epid[i]);
	subcontext = PSMI_EPID_GET_SUBCONTEXT(array_of_epid[i]);
	_IPATH_VDBG("epid-connect=%s connect to %ld:%ld:%ld\n", 
			array_of_epid_mask[i] ? "YES" : " NO",
			(long) lid, (long) context, (long) subcontext);
	if (array_of_epid_mask[i]) {
	    array_of_errors[i] = PSM_EPID_UNKNOWN;
	    array_of_epaddr[i] = NULL;
	}
    }

    /* Second pass: see what to connect and what is connectable. */
    for (i = 0, numep_toconnect = 0; i < numep; i++) {
	if (!array_of_epid_mask[i])
	    continue;
	/* Can't send to epid on same lid */
	if (psm_epid_nid(proto->ep->epid) == psm_epid_nid(array_of_epid[i])) {
	    array_of_errors[i] = PSM_EPID_UNREACHABLE;
	    continue;
	}

	err = ips_get_addr_from_epid(proto, array_of_epid[i], 30000, &epaddr);
	if (err)
	  goto fail;
	if (epaddr == NULL) {
	    ips_epstate_idx idx;
	    /* We're sending a connect request message before some other node
	     * has sent its connect message */
	    epaddr = ips_alloc_epaddr(proto, array_of_epid[i], 
				      NULL, (timeout_in / 1000000UL));
	    if (epaddr == NULL) {
		err = PSM_NO_MEMORY;
		goto fail;
	    }
	    ipsaddr = epaddr->ptladdr;
	    err = ips_epstate_add(proto->epstate, ipsaddr, &idx);
	    if (err)
		goto fail;
	    ipsaddr->epr.epr_commidx_from = idx;
	    ipsaddr->cstate_from = CSTATE_NONE;
	} else if (epaddr->ptladdr->cstate_to != CSTATE_NONE) { /* already connected */
	    psmi_assert_always(epaddr->ptladdr->cstate_to == CSTATE_ESTABLISHED);
	    array_of_errors[i] = PSM_EPID_ALREADY_CONNECTED;
	    array_of_epaddr[i] = epaddr;
	    continue;
	} else {
	    /* We've already received a connect request message from a remote
	     * peer, it's time to send our own. */
	    ipsaddr = epaddr->ptladdr;
	    /* No re-entrancy sanity check and makes sure we are not connected
	     * twice (caller's precondition) */
	    psmi_assert_always(ipsaddr->cstate_to == CSTATE_NONE);
	    psmi_assert_always(ipsaddr->cstate_from != CSTATE_NONE);
#if 0
	    psmi_assert_always(ipsaddr->cerror_from != PSM_OK || 
			       !COMMIDX_IS_UNKNOWN(ptl, ipsaddr->commidx_from));
	    psmi_assert_always(!COMMIDX_IS_UNKNOWN(ptl, ipsaddr->commidx_to));
#endif
	}

	ipsaddr->cstate_to = CSTATE_TO_WAITING;
	ipsaddr->cerror_to = PSM_OK;
	array_of_epaddr[i] = epaddr;
	ipsaddr->s_timeout = get_cycles();
	ipsaddr->delay_in_ms = 1;
	ipsaddr->credit = 0;
	numep_toconnect++;
    }

    /* Second pass: do the actual connect.
     * PSM_EPID_UNKNOWN: Not connected yet.
     * PSM_EPID_UNREACHABLE: Not to be connected.
     * PSM_OK: Successfully connected.
     * Start sending connect messages at a random index between 0 and numep-1
     */
    numep_left = numep_toconnect;
    n_first = ((uint32_t) get_cycles()) % numep;
    while (numep_left > 0) {
	for (n = 0; n < numep; n++) {
	    int keep_polling = 1;
	    i = (n_first + n) % numep;
	    if (!array_of_epid_mask[i]) 
		continue;
	    switch (array_of_errors[i]) {
		case PSM_EPID_UNREACHABLE:
		case PSM_EPID_ALREADY_CONNECTED:
		case PSM_OK:
		    continue;
		default:
		    break;
	    }
	    psmi_assert_always(array_of_epaddr[i] != NULL);
	    ipsaddr = array_of_epaddr[i]->ptladdr;
	    if (ipsaddr->cstate_to == CSTATE_ESTABLISHED) {
		/* This is not the real error code, we only set OK here
		 * so we know to stop polling for the reply. The actual
		 * error is in ipsaddr->cerror_to */
		array_of_errors[i] = PSM_OK;
		numep_left--;
		connect_credits++;
		ipsaddr->credit = 0;
		continue;
	    }
	    while (keep_polling) {
		if (!psmi_cycles_left(t_start, timeout_in)) {
		    err = PSM_TIMEOUT;
		    goto err_timeout;
		}
		if (to_warning_interval && get_cycles() >= to_warning_next) {
		    uint64_t waiting_time = 
			cycles_to_nanosecs(get_cycles() - t_start) / SEC_ULL;
		    const char *first_name = NULL;
		    int num_waiting = 0;

		    for (i = 0; i < numep; i++) {
			if (!array_of_epid_mask[i] || 
			     array_of_errors[i] != PSM_EPID_UNKNOWN)
			    continue;
			if (!first_name)
			    first_name = psmi_epaddr_get_name(array_of_epid[i]);
			num_waiting++;
		    }
		    if (first_name) {
			_IPATH_INFO("Couldn't connect to %s (and %d others). "
			    "Time elapsed %02i:%02i:%02i. Still trying...\n",
			    first_name, num_waiting,
			    (int) (waiting_time / 3600),
                            (int) ((waiting_time / 60) -
				   ((waiting_time / 3600) * 60)),
                            (int) (waiting_time - ((waiting_time / 60) * 60)));
		    }
		    to_warning_next = get_cycles() + to_warning_interval;
		}

		if (get_cycles() > ipsaddr->s_timeout) {
		    if (!ipsaddr->credit && connect_credits) {
		        ipsaddr->credit = 1;
			connect_credits--;
		    }
		    if (ipsaddr->credit) {
		        _IPATH_VDBG("Connect req to %u:%u:%u\n",
				    __be16_to_cpu(ipsaddr->epr.epr_base_lid), 
				    ipsaddr->epr.epr_context, 
				    ipsaddr->epr.epr_subcontext);
		        if (ips_proto_send_ctrl_message(&ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO],
							OPCODE_CONNECT_REQUEST,
							&ipsaddr->ctrl_msg_queued,
							buf) == PSM_OK) {
			    keep_polling = 0;
			    ipsaddr->delay_in_ms = 
			        min(100, ipsaddr->delay_in_ms << 1);
		            ipsaddr->s_timeout = get_cycles() + 
			        nanosecs_to_cycles(ipsaddr->delay_in_ms * MSEC_ULL);
			}
		        /* If not, send got "busy", keep trying */
		    }
		    else {
		        keep_polling = 0;
		    }
		}

		if ((err = psmi_err_only(psmi_poll_internal(proto->ep, 1))))
		    goto fail;

		if (ipsaddr->cstate_to == CSTATE_ESTABLISHED) {
		/* This is not the real error code, we only set OK here
		 * so we know to stop polling for the reply. The actual
		 * error is in ipsaddr->cerror_to */
		    array_of_errors[i] = PSM_OK;
		    numep_left--;
		    connect_credits++;
		    ipsaddr->credit = 0;
		    break;
		}
	    }
	}
    }

err_timeout:
    /* Find the worst error to report */
    for (i = 0; i < numep; i++) {
	if (!array_of_epid_mask[i])
		continue;
	switch (array_of_errors[i]) {
	    /* These are benign */
	    case PSM_EPID_UNREACHABLE: 
	    case PSM_EPID_ALREADY_CONNECTED:
		break;
	    case PSM_EPID_UNKNOWN:
		array_of_errors[i] = PSM_TIMEOUT;
		err = psmi_error_cmp(err, PSM_TIMEOUT);
		break;
	    case PSM_OK:
		/* Restore the real connect error */
		ipsaddr = array_of_epaddr[i]->ptladdr;
		array_of_errors[i] = ipsaddr->cerror_to;
		psmi_assert_always(
		    array_of_epaddr[i]->ptladdr->cstate_to == CSTATE_ESTABLISHED);
		if (ipsaddr->cerror_to != PSM_OK) {
		    err = psmi_error_cmp(err, ipsaddr->cerror_to);
		    ips_free_epaddr(array_of_epaddr[i]->ptladdr);
		    array_of_epaddr[i] = NULL;
		}
		else { 
		    proto->num_connected_to++;
		    psmi_assert_always(ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0]->epr_mtu > 0);
		}
		break;
	    default:
		break;
	}
    }

fail:
    return err;
}

/* Repercutions on MQ.
 *
 * If num_connected==0, everything that exists in the posted queue should
 * complete and the error must be marked epid_was_closed.
 *
 */

psm_error_t
ips_proto_disconnect(struct ips_proto *proto, int force, int numep, 
	     const psm_epaddr_t array_of_epaddr[], 
	     const int array_of_epaddr_mask[], 
	     psm_error_t array_of_errors[],
	     uint64_t timeout_in)
{
    ips_epaddr_t *ipsaddr;
    int numep_left, numep_todisc, i, n;
    int n_first;
    int cstate;
    int has_pending;
    uint64_t timeout;
    psm_error_t err = PSM_OK;
    char buf[IPS_MAX_CONNECT_PAYLEN] PSMI_CACHEALIGN;
    uint64_t reqs_sent = 0;
    union psmi_envvar_val credits_intval;
    int disconnect_credits;
    uint64_t t_warning, t_start;
    union psmi_envvar_val warn_intval;
    unsigned warning_secs;

    psmi_assert_always(numep > 0);

    psmi_getenv("PSM_DISCONNECT_CREDITS",
                "End-point disconnect request credits.",
                PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) 100,
                &credits_intval);

    disconnect_credits = credits_intval.e_uint;

    /* Setup warning interval */
    psmi_getenv("PSM_DISCONNECT_WARN_INTERVAL",
		"Period in seconds to warn if disconnections are not completed."
		"Default is 300 seconds, 0 to disable.",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 300,
		&warn_intval);

    warning_secs = warn_intval.e_uint;

    PSMI_PLOCK_ASSERT();

    /* First pass: see what to disconnect and what is disconnectable */
    for (i = 0, numep_todisc = 0; i < numep; i++) {
	if (!array_of_epaddr_mask[i])
	    continue;
	psmi_assert_always(array_of_epaddr[i]->ptl == proto->ptl);
	cstate = array_of_epaddr[i]->ptladdr->cstate_to;
	array_of_epaddr[i]->ptladdr->credit = 0;
	if (cstate == CSTATE_NONE) {
	    array_of_errors[i] = PSM_OK;
	    continue;
	}
	else {
	    psmi_assert_always(cstate == CSTATE_ESTABLISHED);
	}
	_IPATH_VDBG("disconnecting %p\n", array_of_epaddr[i]);
	array_of_errors[i] = PSM_EPID_UNKNOWN;
	numep_todisc++;
    }
    if (numep_todisc == 0)
	goto success;

    /* Wait for everyone to ack previous packets before putting */
    if (timeout_in == 0)
	timeout = ~0ULL;
    else
	timeout = get_cycles() + nanosecs_to_cycles(timeout_in);

    t_start = get_cycles();
    t_warning = t_start + nanosecs_to_cycles(warning_secs * SEC_ULL);

    n_first = ((uint32_t) get_cycles()) % numep;
    if (!force) {
	numep_left = numep_todisc;
	do {
	    for (n = 0; n < numep; n++) {
		i = (n_first + n) % numep;
		if (!array_of_epaddr_mask[i] || array_of_errors[i] == PSM_OK)
		    continue;
		ipsaddr = array_of_epaddr[i]->ptladdr;
		switch (ipsaddr->cstate_to) {
		    case CSTATE_TO_DISCONNECTED:
			array_of_errors[i] = PSM_OK;
			numep_left--;
			disconnect_credits++;
			ipsaddr->credit = 0;
			continue;
		    case CSTATE_TO_WAITING_DISC:
			if (ipsaddr->s_timeout > get_cycles())
			    continue;
			ipsaddr->delay_in_ms = 
			    min(100, ipsaddr->delay_in_ms << 1);
			ipsaddr->s_timeout = get_cycles() +
			    nanosecs_to_cycles(ipsaddr->delay_in_ms*MSEC_ULL);
			ips_proto_send_ctrl_message_request(proto, &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO],
						            OPCODE_DISCONNECT_REQUEST,
						            &ipsaddr->ctrl_msg_queued, 
						            buf, timeout);
			reqs_sent++;
			break;
		    case CSTATE_ESTABLISHED:
			/* Still pending acks, hold off for now */
			ips_ptladdr_lock(ipsaddr);
			has_pending = 
			  !STAILQ_EMPTY(&ipsaddr->
				        flows[EP_FLOW_GO_BACK_N_PIO].scb_unacked) ||
			  !STAILQ_EMPTY(&ipsaddr->
				        flows[EP_FLOW_GO_BACK_N_DMA].scb_unacked) ||
			  !STAILQ_EMPTY(&ipsaddr->
				        flows[EP_FLOW_GO_BACK_N_AM_REQ].scb_unacked) ||
			  !STAILQ_EMPTY(&ipsaddr->
				        flows[EP_FLOW_GO_BACK_N_AM_RSP].scb_unacked);
			ips_ptladdr_unlock(ipsaddr);
			if (has_pending)
			    continue;
		        if (!ipsaddr->credit && disconnect_credits) {
		            ipsaddr->credit = 1;
			    disconnect_credits--;
		        }
		        if (!ipsaddr->credit)
			    continue;
			ipsaddr->delay_in_ms = 1;
			ipsaddr->cstate_to = CSTATE_TO_WAITING_DISC;
			ipsaddr->s_timeout = get_cycles() + 
			  nanosecs_to_cycles(MSEC_ULL);			
			ips_proto_send_ctrl_message_request(proto, &ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO],
						            OPCODE_DISCONNECT_REQUEST,
						            &ipsaddr->ctrl_msg_queued, 
						            buf, timeout);
			reqs_sent++;
			break;
		    default:
			psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			    "Unhandled/unknown close state %d", 
			    ipsaddr->cstate_to);
			break;
		}
	    }
	    if (numep_left == 0)
		break;

	    if ((err = psmi_err_only(psmi_poll_internal(proto->ep, 1))))
		goto fail;

	    if (warning_secs && get_cycles() > t_warning) {
                _IPATH_INFO("graceful close in progress for %d/%d peers "
		    "(elapsed=%d millisecs,timeout=%d millisecs,reqs=%lld)\n", numep_left, numep_todisc,
		    (int) (cycles_to_nanosecs(get_cycles() - t_start) / MSEC_ULL),
                    (int) (timeout_in / MSEC_ULL),
		    (unsigned long long) reqs_sent);
                t_warning = get_cycles() + nanosecs_to_cycles(warning_secs * SEC_ULL);
	    }
	} 
	while (timeout > get_cycles());

	if (numep_left > 0) {
	    err = PSM_TIMEOUT;
	    for (i = 0; i < numep; i++) {
		if (!array_of_epaddr_mask[i])
		    continue;
		if (array_of_errors[i] == PSM_EPID_UNKNOWN) {
		    array_of_errors[i] = PSM_TIMEOUT;
		    _IPATH_VDBG("disc timeout on index %d, epaddr %s\n",
			        i, psmi_epaddr_get_name(array_of_epaddr[i]->epid));
		}
	    }
            _IPATH_PRDBG("graceful close incomplete for %d/%d peers "
		    "(elapsed=%d millisecs,timeout=%d millisecs,reqs=%lld)\n", numep_left, numep_todisc,
		    (int) (cycles_to_nanosecs(get_cycles() - t_start) / MSEC_ULL),
                    (int) (timeout_in / MSEC_ULL),
		    (unsigned long long) reqs_sent);
	} 
	else
            _IPATH_PRDBG("graceful close complete from %d peers in %d millisecs, reqs_sent=%lld\n",
		     numep_todisc,
		    (int) (cycles_to_nanosecs(get_cycles() - t_start) / MSEC_ULL),
                    (unsigned long long) reqs_sent);
    } else {
	for (n = 0; n < numep; n++) {
	    i = (n_first + n) % numep;
	    if (!array_of_epaddr_mask[i])
		continue;
	    ipsaddr = array_of_epaddr[i]->ptladdr;
	    psmi_assert_always(ipsaddr->cstate_to == CSTATE_ESTABLISHED);
	    ips_proto_send_ctrl_message(&ipsaddr->flows[EP_FLOW_GO_BACK_N_PIO], 
					OPCODE_DISCONNECT_REQUEST,
					&ipsaddr->ctrl_msg_queued, 
					buf);
	    /* Force state to DISCONNECTED */
	    ipsaddr->cstate_to = CSTATE_TO_DISCONNECTED;
	    array_of_errors[i] = PSM_OK;
	}
        _IPATH_VDBG("non-graceful close complete from %d peers\n", numep);
    }

    for (i = 0; i < numep; i++) {
	if (!array_of_epaddr_mask[i] || array_of_errors[i] != PSM_OK)
	    continue;
	ipsaddr = array_of_epaddr[i]->ptladdr;
	if (ipsaddr->cstate_to == CSTATE_NONE)
	    continue;
	psmi_assert_always(ipsaddr->cstate_to == CSTATE_TO_DISCONNECTED);
	proto->num_connected_to--;
	/* Remote disconnect req arrived already, remove this epid.  If it
	 * hasn't arrived yet, that's okay, we'll pick it up later and just
	 * mark our connect-to status as being "none". */
	if (ipsaddr->cstate_from == CSTATE_NONE) {
	    ips_free_epaddr(ipsaddr);
	}
	else
	    ipsaddr->cstate_to = CSTATE_NONE;
    }

fail:
success:
    return err;
}

int
ips_proto_isconnected(ips_epaddr_t *ipsaddr)
{
    if (ipsaddr->cstate_to == CSTATE_ESTABLISHED || 
	ipsaddr->cstate_from == CSTATE_ESTABLISHED)
	return 1;
    else
	return 0;
}

