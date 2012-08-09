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

/* included header files  */

#ifndef _IPS_TID_H
#define _IPS_TID_H

#include "psm_user.h"

#define IPS_TID_MAX_TIDS    512
#define IPS_TID_ALIGNMENT   4

typedef uint64_t ips_tidmap_t[IPS_TID_MAX_TIDS/64];

struct ips_tid {
    const psmi_context_t *context;

    uint32_t	tid_num_max;
    uint32_t	tid_num_avail;
    uint32_t	tid_pagesz;

    uint64_t	tid_num_total;
};

psm_error_t ips_tid_init(struct ips_tid *tidc, const psmi_context_t *context);
psm_error_t ips_tid_fini(struct ips_tid *tidc);

/* Acquiring tids.
 * Buffer base has to be aligned on ips_tid_page_size() boundary
 * Buffer base+length has to be aligned on IPS_TID_ALIGNMENT boundary
 */
psm_error_t
ips_tid_acquire(struct ips_tid *tidc, 
		const void *buf,	/* input buffer, aligned to page_size  */
		int ntids,		/* input number of tids */
		ips_tidmap_t tidmap,	/* output tidmap */
		uint16_t *tid_array);	/* output tidarray, */

psm_error_t
ips_tid_release(struct ips_tid *tidc,
		ips_tidmap_t tidmap,	/* input tidmap */
		int ntids);		/* intput number of tids to release */
PSMI_INLINE(
psm_error_t
ips_tid_num_available(struct ips_tid *tidc))
{
    return tidc->tid_num_avail;
}

PSMI_INLINE(
int
ips_tid_num_required(struct ips_tid *tidc, void *bufi, uint32_t length))
{
    uintptr_t buf = (uintptr_t) bufi;
    const uint32_t page_size = tidc->tid_pagesz;

    return (PSMI_ALIGNUP(buf + length, page_size) -
	    PSMI_ALIGNDOWN(buf, page_size)) / page_size;
}

PSMI_INLINE(
uint32_t
ips_tid_page_size(struct ips_tid *tidc))
{
    return tidc->tid_pagesz;
}

#endif /* _IPS_TID_H */
