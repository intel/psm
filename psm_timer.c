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

#include "psm_user.h"

#define __timerpath __recvpath

#if PSMI_TIMER_STATS
#  define PSMI_TIMER_STATS_ADD_INSERTION(ctrl)	((ctrl)->num_insertions++)
#  define PSMI_TIMER_STATS_ADD_TRAVERSAL(ctrl)	((ctrl)->num_traversals++)
#else
#  define PSMI_TIMER_STATS_ADD_INSERTION(ctrl)	
#  define PSMI_TIMER_STATS_ADD_TRAVERSAL(ctrl)	
#endif

psm_error_t
psmi_timer_init(struct psmi_timer_ctrl *ctrl)
{
    ctrl->t_cyc_next_expire = PSMI_TIMER_INFINITE;

#if PSMI_TIMER_STATS
    ctrl->num_insertions = 0;
    ctrl->num_traversals = 0;
#endif

    TAILQ_INIT(&ctrl->timerq);
    return PSM_OK;
}

void
psmi_timer_entry_init(struct psmi_timer *t_init,
		     psmi_timer_expire_callback_t expire_fn,
		     void *context)
{
    TAILQ_NEXT(t_init, timer) = NULL;
    t_init->t_timeout = 0ULL;
    t_init->flags = 0;
    t_init->expire_callback = expire_fn;
    t_init->context = context;
    return;
}

psm_error_t
psmi_timer_fini(struct psmi_timer_ctrl *ctrl)
{
#if PSMI_TIMER_STATS
    if (ctrl->num_insertions > 0) {
	_IPATH_INFO("avg elem traversals/insertion = %3.2f %%\n",
		100.0 * (double) ctrl->num_traversals / ctrl->num_insertions);
    }
#endif
    return PSM_OK;
}

void __timerpath
psmi_timer_request_always(struct psmi_timer_ctrl *ctrl,
		         struct psmi_timer *t_insert,
		         uint64_t t_cyc_expire)
{
    struct psmi_timer *t_cursor;

    psmi_assert(!(t_insert->flags & PSMI_TIMER_FLAG_PENDING));

    t_insert->t_timeout  = t_cyc_expire;
    t_insert->flags     |= PSMI_TIMER_FLAG_PENDING;

    /*
     * We keep the list from oldest (head) to newest (tail), with the
     * assumption that insert and remove occur much more often than search
     * (when the timer expires).  Newly added timers are more likely to expire
     * later rather than sooner, which is why the head is older.
     */
    PSMI_TIMER_STATS_ADD_INSERTION(ctrl);

    if (TAILQ_EMPTY(&ctrl->timerq)) { /* Common case */
	TAILQ_INSERT_TAIL(&ctrl->timerq, t_insert, timer);
	ctrl->t_cyc_next_expire = t_cyc_expire;
	PSMI_TIMER_STATS_ADD_TRAVERSAL(ctrl);
	return;
    }
    else if (t_cyc_expire > PSMI_TIMER_PRIO_LAST) {
	TAILQ_FOREACH(t_cursor, &ctrl->timerq, timer) {
	    if (t_cursor->t_timeout <= t_cyc_expire) {
		TAILQ_INSERT_BEFORE(t_cursor, t_insert, timer);
		return;
	    }
	    PSMI_TIMER_STATS_ADD_TRAVERSAL(ctrl);
	}
	/* Got to the end of the list -- We're the next to expire */
	ctrl->t_cyc_next_expire = t_cyc_expire;
	TAILQ_INSERT_TAIL(&ctrl->timerq, t_insert, timer);
	return;
    }
    else {
	TAILQ_FOREACH_REVERSE(t_cursor, &ctrl->timerq, timerq, timer) {
	    if (t_cursor->t_timeout >= t_cyc_expire) {
		TAILQ_INSERT_AFTER(&ctrl->timerq, t_cursor, t_insert, timer);
		ctrl->t_cyc_next_expire = min(t_cyc_expire,
					      ctrl->t_cyc_next_expire);
		return;
	    }
	    PSMI_TIMER_STATS_ADD_TRAVERSAL(ctrl);
	}
	TAILQ_INSERT_HEAD(&ctrl->timerq, t_insert, timer);
	/* No need to check if we inserted last, given first branch case */
	// if (TAILQ_LAST(&ctrl->timerq, timerq) == t_insert)
	//    ctrl->t_cyc_next_expire = t_cyc_expire;
	return;
    }

    return;
}

psm_error_t __timerpath
psmi_timer_process_expired(struct psmi_timer_ctrl *ctrl, uint64_t t_cyc_expire)
{
    psm_error_t err = PSM_OK_NO_PROGRESS;
    struct psmi_timer *t_cursor = TAILQ_LAST(&ctrl->timerq, timerq);

    while (t_cursor) {
	if (t_cursor->t_timeout > t_cyc_expire) 
	    break;

	err = PSM_OK;
	psmi_assert(t_cursor->flags & PSMI_TIMER_FLAG_PENDING);
	t_cursor->flags &= ~PSMI_TIMER_FLAG_PENDING;
	TAILQ_REMOVE(&ctrl->timerq, t_cursor, timer);
	t_cursor->expire_callback(t_cursor, t_cyc_expire);
	t_cursor = TAILQ_PREV(t_cursor, timerq, timer);
    }

    if (TAILQ_EMPTY(&ctrl->timerq))
	ctrl->t_cyc_next_expire = PSMI_TIMER_INFINITE;
    else 
	ctrl->t_cyc_next_expire = 
		TAILQ_LAST(&ctrl->timerq, timerq)->t_timeout;

    return err;
}

void __timerpath
psmi_timer_cancel_inner(struct psmi_timer_ctrl *ctrl,
		       struct psmi_timer *t_remove)
{

    psmi_assert(t_remove->flags & PSMI_TIMER_FLAG_PENDING);

    t_remove->flags &= ~PSMI_TIMER_FLAG_PENDING;
    TAILQ_REMOVE(&ctrl->timerq, t_remove, timer);

    /* 
     * If we're removing the last entry, we need to reset the 
     * expiration cycle time.
     */
    if (TAILQ_EMPTY(&ctrl->timerq))
	ctrl->t_cyc_next_expire = PSMI_TIMER_INFINITE;
    else 
	ctrl->t_cyc_next_expire = 
		TAILQ_LAST(&ctrl->timerq, timerq)->t_timeout;
    return;
}


