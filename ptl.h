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

/* Interface implemented by Packet Transport layers such as
 * ips and active messages.
 *
 * This interface can be volatile, it is never seen by PSM clients, and it will
 * probably change as the AM ptl is developed.
 */

#ifndef PSM_PTL_H
#define PSM_PTL_H
#include <inttypes.h>
#include <psm.h>
#include <psm_mq.h>
#include <psm_am.h>

/* We currently have 3 PTLs, 0 is reserved. */
#define PTL_DEVID_IPS  1
#define PTL_DEVID_AMSH 2
#define PTL_DEVID_SELF 3

/* We can currently initialize up to 3 PTLs */
#define PTL_MAX_INIT	3

struct ptl;
typedef struct ptl ptl_t;

struct ptl_epaddr;
typedef struct ptl_epaddr ptl_epaddr_t;

struct ptl_ctl;
typedef struct ptl_ctl ptl_ctl_t;

struct ptl_mq_req;
typedef struct ptl_mq_req ptl_mq_req_t;

/* To be filled in statically by all PTLs */
struct ptl_ctl_init
{
    size_t
    (*sizeof_ptl)(void);

    psm_error_t
    (*init)(const psm_ep_t ep, ptl_t *ptl, ptl_ctl_t *ctl);

    psm_error_t
    (*fini)(ptl_t *ptl, int force, uint64_t timeout_ns);

    psm_error_t
    (*setopt)(const void *component_obj, int optname, 
	      const void *optval, uint64_t optlen);
    
    psm_error_t
    (*getopt)(const void *component_obj, int optname,
	      void *optval, uint64_t *optlen);
};

typedef
struct ptl_arg { 
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
	void		*uptr;
    };
}
ptl_arg_t;

#include "ptl_self/ptl_fwd.h"
#include "ptl_ips/ptl_fwd.h"
#include "ptl_am/ptl_fwd.h"

/* To be filled in as part of ptl_init */
struct ptl_ctl
{
    ptl_t    *ptl;	   /* pointer to ptl */

    /* EP-specific stuff */
    psm_error_t (*ep_poll)(ptl_t *ptl, int replyonly);

    /* PTL-level connect
     *
     * This PTL-level is slightly different from the top-level PSM connect.
     *
     * pre 1: Caller has masked off epids in epid array that are already
     *        connected at the PSM level.
     *
     * post 0: PTL has allocate all epaddrs and whatever internal ptladdr that
     *         ptl needs.
     * post 1: PTL marks error[i] as UNREACHABLE if PTL can't get to epid[i]
     * post 2: PTL marks error[i] as UNKNOWN for all epid[i] that couldn't be
     *         connected before a timeout occurred.
     * post 3: PTL returns OK iff all epids are either OK or UNREACHABLE
     * post 4: PTL defines content or epaddr[i] only if epaddr[i] is OK.
     */
    psm_error_t (*ep_connect)(ptl_t *ptl,
			      int num_ep,
			      const psm_epid_t input_array_of_epid[], 
			      const int	 array_of_epid_mask[],
			      psm_error_t  output_array_of_errors[],
			      psm_epaddr_t output_array_of_epddr[],
			      uint64_t timeout_ns);

    psm_error_t (*ep_disconnect)(ptl_t *ptl, int force,
				 int num_ep,
				 const psm_epaddr_t input_array_of_epaddr[],
				 const int array_of_epaddr_mask[],
				 psm_error_t output_array_of_errors[],
				 uint64_t timeout_ns);

    /* MQ stuff */
    psm_error_t (*mq_send)(psm_mq_t mq, psm_epaddr_t dest, 
		           uint32_t flags, uint64_t stag, const void *buf, uint32_t len);
    psm_error_t (*mq_isend)(psm_mq_t mq, psm_epaddr_t dest, 
			    uint32_t flags, uint64_t stag, const void *buf, uint32_t len, 
			    void *ctxt, psm_mq_req_t *req);

    int (*epaddr_stats_num)(void);
    int	(*epaddr_stats_init)(char *desc[], uint16_t *flags);
    int	(*epaddr_stats_get)(psm_epaddr_t epaddr, uint64_t *stats);

    /* AM stuff, only for Active messages PTL.  Eventually we will expose
     * this to PSM clients. */
    psm_error_t (*am_short_request)(psm_epaddr_t epaddr, 
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
			void *src, size_t len, int flags, 
			psm_am_completion_fn_t completion_fn, 
			void *completion_ctxt);
    psm_error_t (*am_short_reply)(psm_am_token_t token, psm_handler_t handler, 
				  psm_amarg_t *args, int nargs,
				  void *src, size_t len, int flags,
				  psm_am_completion_fn_t completion_fn,
				  void *completion_ctxt);
    psm_error_t (*am_long_request)(psm_epaddr_t epaddr,
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
		        void *src, size_t len, void *dest, int flags);
    psm_error_t (*am_long_reply)(psm_am_token_t token, psm_handler_t handler, 
		          psm_amarg_t *args, int nargs, void *src, 
			  size_t len, void *dest, int flags);
};
#endif
