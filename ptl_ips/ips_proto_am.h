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

#ifndef _IPS_PROTO_AM_H
#define _IPS_PROTO_AM_H

#include "psm_user.h"
#include "ips_scb.h"

#define PSM_AM_HDR_QWORDS   2	/* Needs to be at least 2 */

struct ips_proto_am {
    struct ips_proto *proto;	/* back pointer */
    struct ips_scbctrl	*scbc_request;
    struct ips_scbctrl	scbc_reply;

    uint64_t	amreply_nobufs;
};

psm_error_t
ips_am_short_reply(psm_am_token_t tok,
                   psm_handler_t handler, psm_amarg_t *args, int nargs,
		   void *src, size_t len, int flags,
		   psm_am_completion_fn_t completion_fn, 
		   void *completion_ctxt);

psm_error_t
ips_am_short_request(psm_epaddr_t epaddr, 
                     psm_handler_t handler, psm_amarg_t *args, int nargs,
		     void *src, size_t len, int flags,
		     psm_am_completion_fn_t completion_fn, 
		     void *completion_ctxt);

psm_error_t ips_proto_am_init(struct ips_proto *proto, int num_of_send_bufs, 
			      int num_of_send_desc, uint32_t imm_size,
			      struct ips_proto_am *proto_am);

psm_error_t ips_proto_am_fini(struct ips_proto_am *proto_am);

#endif /* _IPS_PROTO_AM_H */
