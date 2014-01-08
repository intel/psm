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

#ifndef _IPS_SCB_H
#define _IPS_SCB_H

#include "psm_user.h"
#include "ips_proto_header.h"

/* ips_alloc_scb flags */
#define IPS_SCB_FLAG_NONE	0x0
#define IPS_SCB_FLAG_ADD_BUFFER 0x1

/* macros to update scb */
#define ips_scb_mqhdr(scb)     scb->ips_lrh.mqhdr
#define ips_scb_mqtag(scb)     scb->ips_lrh.data[0].u64w0
#define ips_scb_mqparam(scb)   scb->ips_lrh.data[1]
#define ips_scb_uwords(scb)    scb->ips_lrh.data
#define ips_scb_subopcode(scb) scb->ips_lrh.sub_opcode
#define ips_scb_buffer(scb)    scb->payload
#define ips_scb_length(scb)    scb->payload_size
#define ips_scb_flags(scb)     scb->flags
#define ips_scb_dma_ctr(scb)   scb->dma_ctr
#define ips_scb_epaddr(scb)    scb->epaddr
#define ips_scb_cb(scb)        scb->callback
#define ips_scb_cb_param(scb)  scb->cb_param
#define ips_scb_hdr_dlen(scb)  scb->ips_lrh.hdr_dlen

struct ips_scbbuf;
struct ips_scb;
struct ips_scbctrl;
struct ips_tid_send_desc;

typedef void (*ips_scbctrl_avail_callback_fn_t)(struct ips_scbctrl *, 
					        void *context);

STAILQ_HEAD(ips_scb_stailq, ips_scb);
SLIST_HEAD(ips_scb_slist, ips_scb);

struct ips_scbctrl {
    //const psmi_context_t *context;

    /* Send control blocks for each send */
    uint32_t			     scb_num;
    uint32_t                         scb_num_cur;
    SLIST_HEAD(scb_free, ips_scb)    scb_free;
    void			    *scb_base;
    ips_scbctrl_avail_callback_fn_t  scb_avail_callback;
    void			    *scb_avail_context;

    /* Immediate data for send buffers */		    
    uint32_t                         scb_imm_size;
    void                            *scb_imm_buf;

    /*
     * Send buffers (or bounce buffers) to keep user data if we need to
     * retransmit.
     */
    uint32_t				sbuf_num;
    uint32_t                            sbuf_num_cur;
    SLIST_HEAD(sbuf_free, ips_scbbuf)	sbuf_free;
    void			       *sbuf_buf_alloc;
    uint32_t				sbuf_buf_size;
    void			       *sbuf_buf_base;
    void			       *sbuf_buf_last;
};

struct ips_scbbuf {
	SLIST_ENTRY(ips_scbbuf)	next;
};

typedef struct ips_scb ips_scb_t;

struct ips_scb {
	union {
	    SLIST_ENTRY(ips_scb)    next;
	    STAILQ_ENTRY(ips_scb)   nextq;
	};
	union {
	    void		*payload;
	    struct ips_scbbuf	*sbuf;
	};
	uint64_t ack_timeout;	/* in cycles  */
	uint64_t abs_timeout;	/* in cycles  */

	/* Used when composing packet */
	psmi_seqnum_t seq_num;
	uint32_t payload_size;
	uint32_t extra_bytes;
        uint32_t cksum;
	uint32_t flags;
	uint32_t dma_ctr;
	uint32_t payload_bytes;
	uint16_t pkt_flags;
        uint16_t tid;
	uint16_t offset;
	uint16_t nfrag;
	uint16_t frag_size;
  
	struct ips_flow *flow;
	struct ptl_epaddr *epaddr;
	struct ips_tid_send_desc *tidsendc;
	void	*tsess;
	uint16_t tsess_length;
	

	struct ips_scbctrl *scbc;
        void               *imm_payload;

        union {
	  int (*callback) (void *, uint32_t);
	  psm_am_completion_fn_t completion_am;
	};
	void *cb_param;

	struct {
	    union ipath_pbc	      pbc;
	    struct ips_message_header ips_lrh;
	} PSMI_CACHEALIGN;
};

void	    ips_scbctrl_free(ips_scb_t *scb);
int	    ips_scbctrl_bufalloc(ips_scb_t *scb);
int	    ips_scbctrl_avail(struct ips_scbctrl *scbc);
ips_scb_t * ips_scbctrl_alloc(struct ips_scbctrl *scbc, 
			      int scbnum, int len, uint32_t flags);
ips_scb_t * ips_scbctrl_alloc_tiny(struct ips_scbctrl *scbc);

psm_error_t ips_scbctrl_init(const psmi_context_t *context, 
		 uint32_t numscb, uint32_t numbufs, 
		 uint32_t imm_size, uint32_t bufsize, 
		 ips_scbctrl_avail_callback_fn_t, void *avail_context,
		 struct ips_scbctrl *);
psm_error_t ips_scbctrl_fini(struct ips_scbctrl *);

psm_error_t ips_scbctrl_writev(struct ips_scb_slist *slist, int fd);

#endif /* _IPS_SCB_H */
