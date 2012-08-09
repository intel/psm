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

#ifndef _PSMI_IN_USER_H
#error psm_timer.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef _PSMI_TIMER_H
#define _PSMI_TIMER_H

#include "psm_user.h"

/* Keep timer stats */
#define PSMI_TIMER_STATS 0

typedef struct psmi_timer    psmi_timer;
typedef psm_error_t (*psmi_timer_expire_callback_t)(struct psmi_timer *, uint64_t);

struct psmi_timer {
    TAILQ_ENTRY(psmi_timer)  timer;	/* opaque */
    uint64_t		    t_timeout;  /* opaque */
    uint8_t		    flags;	/* opaque */

    psmi_timer_expire_callback_t	    expire_callback; /* user -- callback fn */
    void			    *context;	     /* user -- callback param */
};

struct psmi_timer_ctrl {
    uint64_t			    t_cyc_next_expire;
    TAILQ_HEAD(timerq, psmi_timer)   timerq;

#if PSMI_TIMER_STATS
    uint64_t	num_insertions;
    uint64_t	num_traversals;
#endif
};

/*
 * Some events need to be unconditionally enqueued at the beginning of the
 * timerq -- they are not timers meant to expire but merely operations that
 * need to be delayed.  For delayed operations, there are 5 levels of
 * priority.
 */
#define PSMI_TIMER_PRIO_0	 0ULL
#define PSMI_TIMER_PRIO_1	 1ULL
#define PSMI_TIMER_PRIO_2	 2ULL
#define PSMI_TIMER_PRIO_3	 3ULL
#define PSMI_TIMER_PRIO_4	 4ULL
#define PSMI_TIMER_PRIO_LAST	 PSMI_TIMER_PRIO_4

#define PSMI_TIMER_INFINITE	 0xFFFFFFFFFFFFFFFFULL
#define PSMI_TIMER_FLAG_PENDING  0x01

/*
 * Timer control initialization and finalization
 */
psm_error_t psmi_timer_init(struct psmi_timer_ctrl *ctrl);
psm_error_t psmi_timer_fini(struct psmi_timer_ctrl *ctrl);

/*
 * Timer entry initialization (a timer must be initialized before it can be
 * added to the timer request queue).
 */

void psmi_timer_entry_init(struct psmi_timer *t_init,
		     psmi_timer_expire_callback_t expire_fn,
		     void *context);

/*
 * Timer requests, conditional (macro) or unconditional
 */
#define psmi_timer_request(ctrl, t_insert, t_cyc)			\
	    if (!((t_insert)->flags & PSMI_TIMER_FLAG_PENDING))		\
		psmi_timer_request_always((ctrl), (t_insert), (t_cyc))

void	psmi_timer_request_always(struct psmi_timer_ctrl *ctrl,
		       struct psmi_timer *t_insert,
		       uint64_t t_cyc_expire);

/*
 * Timer cancelations, conditional (macro) only (cancel_inner is internal)
 */
#define psmi_timer_cancel(ctrl, t_remove)		    \
	    if ((t_remove)->flags & PSMI_TIMER_FLAG_PENDING) \
		psmi_timer_cancel_inner(ctrl, t_remove)	
void	    psmi_timer_cancel_inner(struct psmi_timer_ctrl *ctrl,
				   struct psmi_timer *t_remove);

/*
 * Timer processing, conditional or unconditional.
 */
#define psmi_timer_process_if_expired(ctrl, t_cyc_expire)		\
	    (((ctrl)->t_cyc_next_expire <= (t_cyc_expire)) ?		\
		psmi_timer_process_expired(ctrl, t_cyc_expire) :	\
		PSM_OK_NO_PROGRESS)

#define psmi_timer_is_expired(ctrl, t_cyc_expire)			\
	    ((ctrl)->t_cyc_next_expire <= (t_cyc_expire))

psm_error_t psmi_timer_process_expired(struct psmi_timer_ctrl *ctrl, 
				      uint64_t t_cyc_expire);

#endif /* _PSMI_TIMER_H */
