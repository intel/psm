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

#include "psm_user.h"
#include "psm_am.h"
#include "psm_am_internal.h"

static int psmi_am_isinit = 0;

static int _ignore_handler(PSMI_AM_ARGS_DEFAULT)
{
    return 0;
}

int psmi_abort_handler(PSMI_AM_ARGS_DEFAULT)
{
    abort();
    return 0;
}

psm_error_t
psmi_am_init_internal(psm_ep_t ep)
{
    int i;
    psm_am_handler_fn_t *am_htable;

    ep->am_htable = 
	psmi_malloc(ep, UNDEFINED, sizeof(psm_am_handler_fn_t) * PSM_AM_NUM_HANDLERS);
    if (ep->am_htable == NULL)
	return PSM_NO_MEMORY;

    am_htable = (psm_am_handler_fn_t *) ep->am_htable;
    for (i = 0; i < PSM_AM_NUM_HANDLERS; i++) 
	am_htable[i] = _ignore_handler;

    return PSM_OK;
}

psm_error_t
__psm_am_activate(psm_ep_t ep)
{
    psmi_am_isinit = 1;
    return PSM_OK;
}
PSMI_API_DECL(psm_am_activate)

psm_error_t
__psm_am_register_handlers(psm_ep_t ep, 
			 const psm_am_handler_fn_t *handlers, 
			 int num_handlers, int *handlers_idx)
{
    int i, j;

    //psmi_assert_always(psmi_am_isinit == 1);

    /* For now just assign any free one */
    for (i = 0, j = 0; i < PSM_AM_NUM_HANDLERS; i++) {
	if (ep->am_htable[i] == _ignore_handler) {
	    ep->am_htable[i] = handlers[j];
	    handlers_idx[j] = i;
	    if (++j == num_handlers) /* all registered */
		break;
	}
    }

    if (j < num_handlers) {
	/* Not enough free handlers, restore unused handlers */
	for (i = 0; i < j; i++) 
	    ep->am_htable[handlers_idx[i]] = _ignore_handler;

	return psmi_handle_error(ep, PSM_EP_NO_RESOURCES, "Insufficient "
		"available AM handlers: registered %d of %d requested handlers",
		j, num_handlers);
    }
    else
	return PSM_OK;
}
PSMI_API_DECL(psm_am_register_handlers)

psm_error_t
__psm_am_request_short(psm_epaddr_t epaddr, psm_handler_t handler, 
		       psm_amarg_t *args, int nargs, void *src, size_t len,
		       int flags, psm_am_completion_fn_t completion_fn,
		       void *completion_ctxt)
{
    psm_error_t err;
    ptl_ctl_t *ptlc = epaddr->ptlctl;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();
    
    err =  ptlc->am_short_request(epaddr->ptl, epaddr, handler, args, 
				  nargs, src, len, flags, completion_fn,
				  completion_ctxt);
    PSMI_PUNLOCK();
    return err;
}
PSMI_API_DECL(psm_am_request_short)
 
psm_error_t
__psm_am_reply_short(psm_am_token_t token, psm_handler_t handler, 
		     psm_amarg_t *args, int nargs, void *src, size_t len, 
		     int flags, psm_am_completion_fn_t completion_fn,
		     void *completion_ctxt)
{
    psm_error_t err;
    struct psmi_am_token *tok = (struct psmi_am_token *)token;
    psm_epaddr_t epaddr = tok->epaddr_from;
    ptl_ctl_t *ptlc = epaddr->ptlctl;

    psmi_assert_always(token != NULL);

    /* No locking here since we are already within handler context and already
     * locked */

    PSMI_ASSERT_INITIALIZED();

    err =  ptlc->am_short_reply(token, handler, args, 
				nargs, src, len, flags, completion_fn,
				completion_ctxt);
    return err;
}
PSMI_API_DECL(psm_am_reply_short)
 
