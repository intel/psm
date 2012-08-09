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

#ifndef _PSM_AM_INTERNAL_H
#define _PSM_AM_INTERNAL_H

#define PSMI_AM_MAX_ARGS     8
#define PSMI_AM_NUM_HANDLERS 256	/* must be power of 2 */

#define PSMI_AM_ARGS_DEFAULT psm_am_token_t token, psm_epaddr_t epaddr, \
                             psm_amarg_t *args,	int nargs, 		\
			     void *src, uint32_t len

struct psmi_am_token {
  psm_epaddr_t epaddr_from;
  uint32_t	 flags;
  /* Can handler reply? i.e. Not OPCODE_AM_REQUEST_NOREPLY request */
  uint32_t     can_reply;
  
  /* PTLs may add other stuff here */
};

PSMI_ALWAYS_INLINE(
psm_am_handler_fn_t
psm_am_get_handler_function(psm_ep_t ep, psm_handler_t handler_idx))
{
    int hidx = handler_idx & (PSMI_AM_NUM_HANDLERS-1);
    psm_am_handler_fn_t fn = (psm_am_handler_fn_t) ep->am_htable[hidx];
    psmi_assert_always(fn != NULL);
    return fn;
}

/* PSM internal initialization */
psm_error_t psmi_am_init_internal(psm_ep_t ep);

#endif
