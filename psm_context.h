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
#error psm_context.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef _PSM_CONTEXT_H
#define _PSM_CONTEXT_H

typedef
struct psmi_context {
    int			    fd;	    /* driver fd */
    struct _ipath_ctrl	    *ctrl;  /* driver opaque ipath_proto */
    psm_ep_t		    ep;	    /* psm ep handle */
    psm_epid_t		    epid;   /* psm integral ep id */
    struct ipath_user_info  user_info;
    struct ipath_base_info  base_info;
    uint32_t		    runtime_flags;
    uint32_t		    rcvthread_flags;
    volatile uint64_t	    *spi_status;
    psm_error_t		    spi_status_lasterr;
}
psmi_context_t;

psm_error_t
psmi_context_open(const psm_ep_t ep, long unit_id, long port,
		  psm_uuid_t const job_key, 
		  int64_t timeout_ns, psmi_context_t *context);

psm_error_t
psmi_context_close(psmi_context_t *context);

/* Check status of context */
psm_error_t psmi_context_check_status(const psmi_context_t *context);

psm_error_t psmi_context_interrupt_set(psmi_context_t *context, int enable);
int	    psmi_context_interrupt_isenabled(psmi_context_t *context);

int psmi_sharedcontext_params(int *nranks, int *rankid);
/* Runtime flags describe what features are enabled in hw/sw and which
 * corresponding PSM features are being used.
 *
 * Hi 16 bits are PSM options
 * Lo 16 bits are IPATH_RUNTIME options copied from (ipath_common.h)
 */
#define PSMI_RUNTIME_RCVTHREAD	    0x80000000
#define PSMI_RUNTIME_INTR_ENABLED   0x40000000
#define PSMI_RUNTIME_LOCKHDRQ	    PSMI_RUNTIME_RCVTHREAD /* alias */
/* Update _PSMI_RUNTIME_LAST to be the lowest runtime flag */
#define _PSMI_RUNTIME_LAST	    PSMI_RUNTIME_INTR_ENABLED

/*
 * The receive thread can be initialized with optional behaviour.
 *
 * Note: Currently there is no optional behaviour.
 */
#define PSMI_RCVTHREAD_FLAG_ENABLED 0x1


#endif /* PSM_CONTEXT_H */
