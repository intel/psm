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

#ifndef MQ_INT_H
#define MQ_INT_H

#include "psm_user.h"

#define MM_FLAG_NONE  0
#define MM_FLAG_TRANSIENT  0x1
#define MM_NUM_OF_POOLS 7

typedef struct _mem_block_ctrl mem_block_ctrl;
typedef struct _mem_ctrl mem_ctrl;
    
struct _mem_ctrl {
    mem_block_ctrl *free_list;
    uint32_t total_alloc;
    uint32_t current_available;
    uint32_t block_size;
    uint32_t flags;
    uint32_t replenishing_rate;
};

struct _mem_block_ctrl {
    union {
        mem_ctrl *mem_handler;
        mem_block_ctrl *next;
    };
    char _redzone[PSM_VALGRIND_REDZONE_SZ];
};

typedef psm_error_t (*psm_mq_unexpected_callback_fn_t)
		    (psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr,
		     uint64_t tag, uint32_t send_msglen, 
		     const void *payload, uint32_t paylen);
		    
struct psm_mq {
    psm_ep_t	  ep;		/**> ep back pointer */
    mpool_t	  sreq_pool;
    mpool_t	  rreq_pool;

    psm_mq_unexpected_callback_fn_t unexpected_callback;
    struct mqsq   expected_q;	/**> Preposted (expected) queue */
    struct mqsq   unexpected_q;	/**> Unexpected queue */
    struct mqq    completed_q;	/**> Completed queue */

    uint64_t	  cur_sysbuf_bytes;
    uint64_t	  max_sysbuf_bytes;
    uint32_t	  ipath_thresh_rv;
    uint32_t	  shm_thresh_rv;
    uint32_t	  ipath_window_rv;
    int		  memmode;

    psm_mq_stats_t	stats;	/**> MQ stats, accumulated by each PTL */

    mem_ctrl handler_index[MM_NUM_OF_POOLS];
    int      mem_ctrl_is_init;
    uint64_t mem_ctrl_total_bytes;
};

#define MQ_IPATH_THRESH_TINY	8
#define MQ_IPATH_THRESH_EGR_SDMA    34000
#define MQ_IPATH_THRESH_EGR_SDMA_SQ 8192

#define MQE_TYPE_IS_SEND(type)	((type) & MQE_TYPE_SEND)
#define MQE_TYPE_IS_RECV(type)	((type) & MQE_TYPE_RECV)

#define MQE_TYPE_SEND		0x1000
#define MQE_TYPE_RECV		0x2000
#define MQE_TYPE_FLAGMASK	0x0fff
#define MQE_TYPE_WAITING	0x0001
#define MQE_TYPE_WAITING_PEER	0x0004
#define MQE_TYPE_EGRLONG	0x0008

#define MQ_STATE_COMPLETE	0
#define MQ_STATE_POSTED		1
#define MQ_STATE_MATCHED	2
#define MQ_STATE_UNEXP		3
#define MQ_STATE_UNEXP_RV	4
#define MQ_STATE_FREE		5

#define MQ_MSG_TINY		1
#define MQ_MSG_SHORT		2
#define MQ_MSG_LONG		3
#define MQ_MSG_RTS		4
#define MQ_MSG_RTS_EGR		5
#define MQ_MSG_RTS_WAIT		6
#define MQ_MSG_DATA		9
#define MQ_MSG_DATA_BLK		10
#define MQ_MSG_DATA_REQ		11
#define MQ_MSG_DATA_REQ_BLK	12
#define MQ_MSG_CTS_EGR		13

#define MQ_MSG_USER_FIRST 64

/*
 * Descriptor allocation limits.
 * The 'LIMITS' predefines fill in a psmi_rlimits_mpool structure
 */
#define MQ_SENDREQ_LIMITS {					\
	    .env = "PSM_MQ_SENDREQS_MAX",			\
	    .descr = "Max num of isend requests in flight",	\
	    .env_level = PSMI_ENVVAR_LEVEL_USER,		\
	    .minval = 1,					\
	    .maxval = ~0,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 1024, 1048576 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = { 1024, 65536 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 8192, 16777216 }	\
	}

#define MQ_RECVREQ_LIMITS {					\
	    .env = "PSM_MQ_RECVREQS_MAX",			\
	    .descr = "Max num of irecv requests in flight",	\
	    .env_level = PSMI_ENVVAR_LEVEL_USER,		\
	    .minval = 1,					\
	    .maxval = ~0,					\
	    .mode[PSMI_MEMMODE_NORMAL]  = { 1024, 1048576 },	\
	    .mode[PSMI_MEMMODE_MINIMAL] = { 1024, 65536 },	\
	    .mode[PSMI_MEMMODE_LARGE]   = { 8192, 16777216 }	\
	}

typedef psm_error_t (*mq_rts_callback_fn_t)(psm_mq_req_t req, int was_posted);
typedef psm_error_t (*mq_testwait_callback_fn_t)(psm_mq_req_t *req, int istest,
						 psm_mq_status_t *status);

/* receive mq_req, the default */
struct psm_mq_req {
    struct {
	psm_mq_req_t    next;
	psm_mq_req_t    *pprev; /* used in completion queue */
    };
    uint32_t	    state;
    uint32_t	    type;
    psm_mq_t	    mq;

    /* Tag matching vars */
    uint64_t	tag;
    uint64_t    tagsel;	    /* used for receives */

    /* Some PTLs want to get notified when there's a test/wait event */
    mq_testwait_callback_fn_t	testwait_callback;

    /* Buffer attached to request.  May be a system buffer for unexpected
     * messages or a user buffer when an expected message */
    uint8_t *buf;
    uint32_t buf_len;
    uint32_t error_code;

    /* Used only for eager LONGs */
    STAILQ_ENTRY(psm_mq_req)    nextq; /* used for egr-long only */
    psmi_egrid_t egrid;
    psm_epaddr_t epaddr;
    uint16_t msg_seqnum;	/* msg seq num for mctxt */
    uint8_t tid_grant[128];	/* don't change the size unless... */

    uint32_t recv_msglen; /* Message length we are ready to receive */
    uint32_t send_msglen; /* Message length from sender */
    uint32_t recv_msgoff; /* Message offset into buf */
    union {
	uint32_t send_msgoff; /* Bytes received so far.. can be larger than buf_len */ 
	uint32_t recv_msgposted;
    };

    /* Used for request to send messages */
    void	*context;  /* user context associated to sends or receives */

    /* Used to keep track of unexpected rendezvous */
    mq_rts_callback_fn_t    rts_callback;
    psm_epaddr_t	    rts_peer;
    uint32_t		    rts_reqidx_peer;
    uintptr_t		    rts_sbuf;

    /* PTLs get to store their own per-request data.  MQ manages the allocation
     * by allocating psm_mq_req so that ptl_req_data has enough space for all 
     * possible PTLs.
     */
    union {
	void    *ptl_req_ptr;	  /* when used by ptl as pointer */
	uint8_t  ptl_req_data[0]; /* when used by ptl for "inline" data */
    };
};

void psmi_mq_mtucpy(void *vdest, const void *vsrc, uint32_t nchars);

#if defined(__x86_64__)
void psmi_mq_mtucpy_safe(void *vdest, const void *vsrc, uint32_t nchars);
#else
#define psmi_mq_mtucpy_safe psmi_mq_mtucpy
#endif

/*
 * Optimize for 0-8 byte case, but also handle others.
 */
PSMI_ALWAYS_INLINE(
void mq_copy_tiny(uint32_t* dest, uint32_t* src, uint8_t len)
)
{
    switch (len) {
        case 8: *dest++ = *src++;
        case 4: *dest++ = *src++;
	case 0: return;
        case 7:
        case 6:
        case 5: *dest++ = *src++; len -= 4;
	case 3: 
	case 2: 
	case 1: break;
	default: /* greater than 8 */
	    psmi_mq_mtucpy(dest,src,len);
	    return;
    }
    uint8_t* dest1 = (uint8_t*) dest;
    uint8_t* src1 = (uint8_t*) src;
    switch(len) {
        case 3: *dest1++ = *src1++;
        case 2: *dest1++ = *src1++;
        case 1: *dest1++ = *src1++;
    }
}

/*
 * Given an req with buffer ubuf of length ubuf_len,
 * fill in the req's status and return the amount of bytes the request
 * can receive.
 *
 * The function sets status truncation errors. Basically what MPI_Status.
 */
PSMI_ALWAYS_INLINE(
void mq_status_copy(psm_mq_req_t req, psm_mq_status_t *status))
{
    status->msg_tag    = req->tag;
    status->msg_length = req->send_msglen;
    status->nbytes     = req->recv_msglen;
    status->error_code = req->error_code;
    status->context    = req->context;
}

PSMI_ALWAYS_INLINE(
uint32_t mq_set_msglen(psm_mq_req_t req, uint32_t recvlen, uint32_t sendlen))
{
    req->send_msglen = sendlen;
    if (recvlen < sendlen) {
	req->recv_msglen = recvlen;
	req->error_code = PSM_MQ_TRUNCATION;
	return recvlen;
    }
    else {
	req->recv_msglen = sendlen;
	req->error_code = PSM_OK;
	return sendlen;
    }
}

#ifndef PSM_DEBUG

PSMI_ALWAYS_INLINE(
void
mq_qq_append(struct mqq *q, psm_mq_req_t req))
{
    req->next = NULL;
    req->pprev = q->lastp;
    *(q->lastp) = req;
    q->lastp = &req->next;
}
#else
#define mq_qq_append(q,req) do { \
    (req)->next = NULL;\
    (req)->pprev = (q)->lastp;\
    *((q)->lastp) = (req); \
    (q)->lastp = &(req)->next; \
    if (q == &(req)->mq->completed_q) \
	_IPATH_VDBG("Moving (req)=%p to completed queue on %s, %d\n", (req), __FILE__, __LINE__); \
} while (0)
#endif

PSMI_ALWAYS_INLINE(
void
mq_sq_append(struct mqsq *q, psm_mq_req_t req))
{
    req->next = NULL;
    *(q->lastp) = req;
    q->lastp = &req->next;
}

PSMI_ALWAYS_INLINE(
void
mq_qq_remove(struct mqq *q, psm_mq_req_t req))
{
    if (req->next != NULL)
	req->next->pprev = req->pprev;
    else
	q->lastp = req->pprev;
    *(req->pprev) = req->next;
}

psm_error_t  psmi_mq_req_init(psm_mq_t mq);
psm_error_t  psmi_mq_req_fini(psm_mq_t mq);
psm_mq_req_t psmi_mq_req_alloc(psm_mq_t mq, uint32_t type);
#define      psmi_mq_req_free(req)  psmi_mpool_put(req)

/*
 * MQ unexpected buffer management
 */
void	  psmi_mq_sysbuf_init(psm_mq_t mq);
void	  psmi_mq_sysbuf_fini(psm_mq_t mq);
void *	  psmi_mq_sysbuf_alloc(psm_mq_t mq, uint32_t nbytes);
void	  psmi_mq_sysbuf_free(psm_mq_t mq, void *);
void	  psmi_mq_sysbuf_getinfo(psm_mq_t mq, char *buf, size_t len);

/*
 * Main receive progress engine, for shmops and ipath, in mq.c
 */
psm_error_t psmi_mq_malloc(psm_mq_t *mqo);
psm_error_t psmi_mq_initialize_defaults(psm_mq_t mq);
psm_error_t psmi_mq_free(psm_mq_t mq);

/* Three functions that handle all MQ stuff */
#define MQ_RET_MATCH_OK	0
#define MQ_RET_UNEXP_OK 1
#define MQ_RET_UNEXP_NO_RESOURCES 2
#define MQ_RET_DATA_OK 3
#define MQ_RET_DATA_OUT_OF_ORDER 4

int psmi_mq_handle_outoforder_queue(psm_epaddr_t epaddr);
int psmi_mq_handle_envelope_outoforder(psm_mq_t mq, uint16_t mode,
		   psm_epaddr_t epaddr, uint16_t msg_seqnum,
		   uint64_t tag, psmi_egrid_t egrid, uint32_t msglen,
		   const void *payload, uint32_t paylen);
int psmi_mq_handle_envelope(psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr, 
		   uint64_t tag, psmi_egrid_t egrid, uint32_t msglen,
		   const void *payload, uint32_t paylen);
int psmi_mq_handle_data(psm_mq_req_t req, psm_epaddr_t epaddr, 
		   uint32_t egrid, uint32_t offset,
		   const void *payload, uint32_t paylen);

/* If rtsreq is non-NULL, it contains enough information to pull the data from
 * the initiator and signal completion at a later time */
int psmi_mq_handle_rts_outoforder(psm_mq_t mq, uint64_t tag,
		   uintptr_t send_buf, uint32_t send_msglen,
		   psm_epaddr_t peer, uint16_t msg_seqnum,
		   mq_rts_callback_fn_t cb, psm_mq_req_t *req_o);
int psmi_mq_handle_rts(psm_mq_t mq, uint64_t tag, uintptr_t send_buf,
		   uint32_t send_msglen, psm_epaddr_t peer, 
		   mq_rts_callback_fn_t cb, psm_mq_req_t *req_o);
void psmi_mq_handle_rts_complete(psm_mq_req_t req);

void psmi_mq_stats_register(psm_mq_t mq, mpspawn_stats_add_fn add_fn);

PSMI_ALWAYS_INLINE(
psm_mq_req_t 
mq_req_match(struct mqsq *q, uint64_t tag, int remove)
)
{
    psm_mq_req_t *curp;
    psm_mq_req_t cur;

    for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
	if (!((tag ^ cur->tag) & cur->tagsel)) { /* match! */
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

PSMI_ALWAYS_INLINE(
psm_mq_req_t 
mq_ooo_match(struct mqsq *q, uint16_t msg_seqnum)
)
{
    psm_mq_req_t *curp;
    psm_mq_req_t cur;

    for (curp = &q->first; (cur = *curp) != NULL; curp = &cur->next) {
	if (cur->msg_seqnum == msg_seqnum) { /* match! */
	    if ((*curp = cur->next) == NULL) /* fix tail */
		q->lastp = curp;
	    cur->next = NULL;
	    return cur;
	}
    }
    return NULL; /* no match */
}

/* Default handler */
int __fastpath
psmi_mq_handle_envelope_unexpected(
	psm_mq_t mq, uint16_t mode, psm_epaddr_t epaddr,
	uint64_t tag, psmi_egrid_t egrid, uint32_t send_msglen, 
	const void *payload, uint32_t paylen);

/* Not exposed in public psm, but may extend parts of PSM 2.1 to support
 * this feature before 2.3 */
psm_mq_unexpected_callback_fn_t
psmi_mq_register_unexpected_callback(psm_mq_t mq, 
				     psm_mq_unexpected_callback_fn_t fn);


PSMI_ALWAYS_INLINE(
int 
psmi_mq_handle_tiny_envelope(psm_mq_t mq, psm_epaddr_t epaddr,
			     uint64_t tag, const void *payload, uint32_t tinylen))
{
    psm_mq_req_t req;
    uint32_t msglen;
    int rc;
    psmi_assert(epaddr != NULL);

    req = mq_req_match(&(mq->expected_q), tag, 1);
    if (req) { /* we have a match */
	req->tag = tag;
	msglen = mq_set_msglen(req, req->buf_len, tinylen);
	PSM_VALGRIND_DEFINE_MQ_RECV(req->buf, req->buf_len, msglen);
	mq_copy_tiny((uint32_t *)req->buf, (uint32_t *)payload, msglen);
	req->state = MQ_STATE_COMPLETE;
	mq_qq_append(&mq->completed_q, req);
	mq->stats.rx_user_bytes += msglen;
	mq->stats.rx_user_num++;
	_IPATH_VDBG("tiny from=%s match=YES (req=%p) mode=1 mqtag=%llu "
		"msglen=%d paylen=%d\n", psmi_epaddr_get_name(epaddr->epid), req, 
		(unsigned long long) tag, msglen, tinylen);
	rc =  MQ_RET_MATCH_OK;
    }
    else {
	rc = psmi_mq_handle_envelope_unexpected(mq, MQ_MSG_TINY, epaddr, tag, 
		(union psmi_egrid) 0U, tinylen, payload, tinylen);
    }
    return rc;
}

PSMI_ALWAYS_INLINE(
void
psmi_mq_stats_rts_account(psm_mq_req_t req))
{
    psm_mq_t mq = req->mq;
    if (MQE_TYPE_IS_SEND(req->type)) {
	mq->stats.tx_num++;
	mq->stats.tx_rndv_num++;
	mq->stats.tx_rndv_bytes += req->send_msglen;
    }
    else {
	mq->stats.rx_user_num++;
	mq->stats.rx_user_bytes += req->recv_msglen;
    }
    return;
}

#endif
