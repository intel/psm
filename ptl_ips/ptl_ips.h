/*
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

#ifndef _IPS_PTL_H
#define _IPS_PTL_H

#include "psm_user.h"
#include "psm_mq_internal.h"

#include "ips_proto_params.h"
#include "ips_proto.h"
#include "ips_spio.h"
#include "ips_recvhdrq.h"
#include "ips_writehdrq.h"
#include "ips_epstate.h"
#include "ips_stats.h"
#include "ips_subcontext.h"

struct ptl_shared;

/*
 * PTL at the ips level (for InfiniPath)
 *
 * This PTL structure glues all the ips components together.
 *
 * * ips timer, shared by various components, allows each component to
 *   schedule time-based expiration callbacks on the timerq.
 * * HW receive queue
 * * send control block to handle eager messages
 * * instantiation of the ips protocol
 * * endpoint state, to map endpoint indexes into structures
 *
 *   Receive-side                                  
 *
 *          ----[   proto    ] 
 *         /       ^      ^   
 *        |        |      |
 *        |     packet  packet
 *        |	known   unknown
 *   add_endpt      \ /
 *        |          |
 *        `----> [epstate] 
 *                   ^
 *                   |
 *               lookup_endpt
 *                   |
 *                [recvq]
 *                   |
 *                 poll
 *
 */
/* Updates to this struct must be reflected in PTL_IPS_SIZE in ptl_fwd.h */
/* IPS knows it functions as a PTL whenever ptl->ep is non-NULL */
struct ptl {
    psm_ep_t	      ep;       /* back ptr */	
    psm_epid_t	      epid;     /* cached from ep */
    psm_epaddr_t      epaddr;   /* cached from ep */
    ips_epaddr_t      *ipsaddr; /* cached from epaddr */
    ptl_ctl_t	      *ctl;     /* cached from init */
    const psmi_context_t *context;    /* cached from init */

    struct ips_spio	spioc;   /* PIO send control */
    struct ips_proto	proto;	 /* protocol instance: timerq, epstate, spio */

    /* Receive header queue and receive queue processing */
    uint32_t		  runtime_flags;
    struct psmi_timer_ctrl timerq;
    struct ips_epstate    epstate; /* map incoming packets */
    struct ips_recvhdrq_state recvq_state;
    struct ips_recvhdrq   recvq;   /* HW recvq: epstate, proto */

    /* timer to check the context's status */
    struct psmi_timer	    status_timer;

    /* context's status check timeout in cycles -- cached */
    uint64_t		    status_cyc_timeout;

    /* Shared contexts context */
    struct ptl_shared	    *recvshc;

    /* Rcv thread context */
    struct ptl_rcvthread    *rcvthread;
};

/*
 * Sample implementation of shared contexts context.
 *
 * In shared mode, the hardware queue is serviced by more than one process.
 * Each process also mirrors the hardware queue in software (represented by an
 * ips_recvhdrq).  For packets we service in the hardware queue that are not
 * destined for us, we write them in other processes's receive queues
 * (represented by an ips_writehdrq).
 *
 */
struct ptl_shared {
    ptl_t  *ptl;		            /* backptr to main ptl */
    uint32_t subcontext;
    uint32_t subcontext_cnt;

    pthread_spinlock_t *context_lock;
    struct ips_subcontext_ureg *subcontext_ureg[INFINIPATH_MAX_SUBCONTEXT];
    struct ips_recvhdrq	recvq;	            /* subcontext receive queue */
    struct ips_recvhdrq_state recvq_state;  /* subcontext receive queue state */
    struct ips_writehdrq writeq[INFINIPATH_MAX_SUBCONTEXT]; /* peer subcontexts */
};

/*
 * Connect/disconnect are wrappers around psm proto's connect/disconnect,
 * mostly to abstract away PSM-specific stuff from ips internal structures
 */
psm_error_t ips_ptl_connect(ptl_t *ptl, int numep, 
			    const psm_epid_t *array_of_epid, 
			    const int *array_of_epid_mask, 
			    psm_error_t *array_of_errors, 
			    psm_epaddr_t *array_of_epaddr, 
			    uint64_t timeout_in);

psm_error_t ips_ptl_disconnect(ptl_t *ptl, int force, int numep, 
			       const psm_epaddr_t array_of_epaddr[],
			       const int array_of_epaddr_mask[], 
			       psm_error_t array_of_errors[], 
			       uint64_t timeout_in);

/*
 * Generic Poll function for ips-level ptl
 */
psm_error_t ips_ptl_poll(ptl_t *ptl, int _ignored);
psm_error_t ips_ptl_shared_poll(ptl_t *ptl, int _ignored);

/*
 * Support for receive thread
 */
psm_error_t ips_ptl_rcvthread_init(ptl_t *ptl, struct ips_recvhdrq *recvq);
psm_error_t ips_ptl_rcvthread_fini(ptl_t *ptl);

#endif /* _IPS_PTL_H */
