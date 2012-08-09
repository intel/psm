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

#include "ips_subcontext.h"
#include "ptl_ips.h"

psm_error_t
ips_subcontext_ureg_get(ptl_t *ptl, const psmi_context_t *context,
			struct ips_subcontext_ureg **uregp,
			uint32_t subcontext_cnt)
{
    psm_error_t err = PSM_OK;
    const struct ipath_base_info *base_info = &context->base_info;
    uint64_t *all_subcontext_uregbase = (uint64_t *) (uintptr_t)
                                     base_info->spi_subctxt_uregbase;
    unsigned pagesize = getpagesize();
    int i;
    psmi_assert_always(all_subcontext_uregbase != NULL);
    for (i = 0; i < INFINIPATH_MAX_SUBCONTEXT; i++) {
        struct ips_subcontext_ureg *subcontext_ureg = 
          (struct ips_subcontext_ureg *) &all_subcontext_uregbase[_IPATH_UregMax*8];
        *uregp++ = (i < subcontext_cnt) ? subcontext_ureg : NULL;
        all_subcontext_uregbase += pagesize / sizeof(uint64_t);
    }
    return err;
}

psm_error_t
ips_subcontext_ureg_initialize(ptl_t *ptl, uint32_t subcontext,
                            struct ips_subcontext_ureg *uregp)
{
    psm_error_t err = PSM_OK;
    memset(uregp, 0, sizeof(*uregp));
    if (subcontext == 0) {
        if (pthread_spin_init(&uregp->context_lock, 
                              PTHREAD_PROCESS_SHARED) != 0) {
            err = psmi_handle_error(ptl->ep, PSM_EP_DEVICE_FAILURE,
	        "Couldn't initialize process-shared spin lock");
	}
    }
    return err;
}
