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

#ifndef _PTL_FWD_AMSH_H
#define _PTL_FWD_AMSH_H

#define PTL_AMSH_MAX_LOCAL_PROCS   256

/* SCIF manual says it is optimized for up to 8 nodes, so choose 16 for
   future expansion. */
#ifdef PSM_HAVE_SCIF
#define PTL_AMSH_MAX_LOCAL_NODES   8
#else
/* Compiling without SCIF: assume one node */
#define PTL_AMSH_MAX_LOCAL_NODES   1
#endif

/* Symbol in am ptl */
extern struct ptl_ctl_init psmi_ptl_amsh;

/* Special non-ptl function exposed to pre-attach to shm segment */
psm_error_t psmi_shm_attach(psm_ep_t ep, int *shmidx_o);
psm_error_t psmi_shm_detach(psm_ep_t ep);

extern int psmi_shm_mq_rv_thresh;

#endif
