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

#include "ips_tid.h"

psm_error_t ips_ptl_handle_check_unit_status(psm_ep_t ep, int ips_rc);

psm_error_t
ips_tid_init(struct ips_tid *tidc, const psmi_context_t *context)
{
    const struct ipath_base_info *base_info = &context->base_info;
    struct psmi_stats_entry entries[] = { 
	PSMI_STATS_DECL("tid update count", MPSPAWN_STATS_REDUCTION_ALL,
			NULL, &tidc->tid_num_total),
    };

    tidc->context	= context;
    tidc->tid_num_max   = base_info->spi_tidcnt;
    tidc->tid_num_avail = base_info->spi_tidcnt;
    tidc->tid_pagesz    = base_info->spi_tid_maxsize;

    tidc->tid_num_total = 0;

    return psmi_stats_register_type(PSMI_STATS_NO_HEADING,
				    PSMI_STATSTYPE_TIDS,
				    entries,
				    PSMI_STATS_HOWMANY(entries),
				    tidc);
}

psm_error_t
ips_tid_fini(struct ips_tid *tidc)
{
    return PSM_OK;
}

psm_error_t
ips_tid_acquire(struct ips_tid *tidc, const void *buf,
		int ntids, ips_tidmap_t tid_map,	
		uint16_t *tid_array)
{
    psm_error_t err = PSM_OK;
    int rc;

    psmi_assert((uintptr_t)buf % tidc->tid_pagesz == 0);
    psmi_assert(ntids <= tidc->tid_num_avail);

    rc = ipath_update_tid(tidc->context->ctrl, ntids,
			  (uint64_t)(uintptr_t) tid_array,
			  (uint64_t)(uintptr_t) buf,
			  (uint64_t)(uintptr_t) tid_map);

    if (rc != 0) {
	/* We're still going to fail but check unit status */
	err = psmi_err_only(psmi_context_check_status(tidc->context));
	if (err == PSM_OK) /* okay, but something else is still wrong */
	    err = psmi_handle_error(tidc->context->ep, PSM_EP_DEVICE_FAILURE,
				    "Failed to update %d tids",
				    ntids);
	goto fail;
    }

    tidc->tid_num_total += ntids;
    tidc->tid_num_avail -= ntids;

fail:
    return err;
}

psm_error_t
ips_tid_release(struct ips_tid *tidc, ips_tidmap_t tidmap, int ntids)
{
    psm_error_t err = PSM_OK;

    if (ipath_free_tid(tidc->context->ctrl, ntids, 
		       (uint64_t) (uintptr_t) tidmap)) {
	err = PSM_EP_DEVICE_FAILURE;
	goto fail;
    }

    tidc->tid_num_avail += ntids;

fail:
    return err;
}

