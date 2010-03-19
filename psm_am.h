/*
 * Copyright (c) 2006-2010. QLogic Corporation. All rights reserved.
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

#ifndef PSM_AM_H
#define PSM_AM_H

/* Active Messages.
 *
 * PSM implements an internal active message component that currently lives
 * alongside the Matched Queues (mq) component.  It's internal-only, meaning
 * that it is not exposed in public header files (it may be made public if
 * there is demand and a good reason to support it).  
 *
 *
 * Only portions of the interface are currently implemented.
 */

typedef uint32_t psm_handler_t;
typedef void    *psm_am_token_t;

#define PSM_AM_MAX_ARGS	      8
#define PSM_AM_NUM_HANDLERS 256 /* must be power of 2 */

#define PSM_AM_FLAG_NONE    0
#define PSM_AM_FLAG_ASYNC   1 /* No need to copy source data */
#define PSM_AM_FLAG_NOREPLY 2 /* AM request with no reply */

typedef
struct psm_amarg { 
    union {
	struct {
	    uint16_t	u16w3;
	    uint16_t	u16w2;
	    uint16_t	u16w1;
	    uint16_t	u16w0;
	};
	struct {
	    uint32_t	u32w1;
	    uint32_t	u32w0;
	};
	uint64_t	u64w0;
	uint64_t	u64;
    };
}
psm_amarg_t;

typedef
int (*psm_am_handler_fn_t)(psm_am_token_t token, psm_epaddr_t epaddr,
			   psm_amarg_t *args, int nargs, 
			   void *src, uint32_t len);

typedef
void (*psm_am_completion_fn_t)(void *context);

/* Activate the endpoint for active message handling */
psm_error_t psm_am_activate(psm_ep_t ep);

psm_error_t psm_am_register_handlers(psm_ep_t ep, 
				     const psm_am_handler_fn_t *handlers, 
				     int num_handlers, int *handlers_idx);

/* Active message request/reply, short only for now */
psm_error_t
psm_am_request_short(psm_epaddr_t epaddr, psm_handler_t handler, 
		     psm_amarg_t *args, int nargs, void *src, size_t len,
		     int flags, psm_am_completion_fn_t completion_fn,
		     void *completion_ctxt);

psm_error_t
psm_am_reply_short(psm_am_token_t token, psm_handler_t handler, 
		   psm_amarg_t *args, int nargs, void *src, size_t len, 
		   int flags, psm_am_completion_fn_t completion_fn,
		   void *completion_ctxt);

struct psm_am_max_sizes {
    uint32_t	nargs;
    uint32_t	request_short;
    uint32_t	reply_short;
    uint32_t	request_long;
    uint32_t	reply_long;
};

psm_error_t psm_am_get_max_sizes(psm_ep_t ep, struct psm_am_max_sizes *);

#endif

