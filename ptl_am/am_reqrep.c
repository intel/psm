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
#include "psm_am.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"

psm_error_t
psmi_amsh_am_short_request(psm_epaddr_t epaddr,
			   psm_handler_t handler, psm_amarg_t *args, int nargs,
			   void *src, size_t len, int flags,
			   psm_am_completion_fn_t completion_fn,
			   void *completion_ctxt)
{
  psm_amarg_t req_args[NSHORT_ARGS] = {};

  /* All sends are synchronous. Ignore PSM_AM_FLAG_ASYNC. 
   * TODO: Treat PSM_AM_FLAG_NOREPLY as "advisory". This was mainly
   * used to optimize the IPS path though we could put a stricter interpretation
   * on it to disallow any replies.
   */
  
  /* For now less than NSHORT_ARGS-1. We use the first arg to carry the handler
   * index.
   */
  psmi_assert(nargs < (NSHORT_ARGS - 1));
  req_args[0].u32w0 = (uint32_t) handler;
  psmi_mq_mtucpy((void*) &req_args[1], (const void*) args, 
		 (nargs * sizeof(psm_amarg_t)));
  psmi_amsh_short_request(epaddr->ptl, epaddr, am_handler_hidx,
			req_args, nargs + 1, 
			  src, len, 0);
  
  if (completion_fn)
    completion_fn(completion_ctxt);
  
  return PSM_OK;
}

psm_error_t
psmi_amsh_am_short_reply(psm_am_token_t tok,
			 psm_handler_t handler, psm_amarg_t *args, int nargs,
			 void *src, size_t len, int flags,
			 psm_am_completion_fn_t completion_fn,
			 void *completion_ctxt)
{
  psm_amarg_t rep_args[NSHORT_ARGS] = {};

  /* For now less than NSHORT_ARGS-1. We use the first arg to carry the handler
   * index.
   */
  psmi_assert(nargs < (NSHORT_ARGS - 1));
  rep_args[0].u32w0 = (uint32_t) handler;
  psmi_mq_mtucpy((void*) &rep_args[1], (const void*) args, 
		 (nargs * sizeof(psm_amarg_t)));

  psmi_amsh_short_reply((amsh_am_token_t*) tok, am_handler_hidx, rep_args, nargs+1, src, len, 0);
  
  if (completion_fn)
    completion_fn(completion_ctxt);
  
  return PSM_OK;
}

