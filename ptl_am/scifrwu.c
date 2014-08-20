/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * Copyright (c) 2010. QLogic Corporation. All rights reserved.
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

#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>

#include "psm_user.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"
#include "scifrw.h"

#if defined(PSM_HAVE_SCIF)
int scif_register_region(scif_epd_t epd, void* addr, size_t len, off_t* offset)
{
    /* SCIF requires registrations on page granularity.  The address must be
       rounded down to a page boundary, and the length must be rounded up. */
    off_t addr_offset = (off_t)addr & 0xFFF;
    uintptr_t reg_addr = (uintptr_t)addr & ~0xFFF;
    size_t reg_len = len + addr_offset;

    if(reg_len & 0xFFF) {
        reg_len += 0x1000 - (reg_len & 0xFFF);
    }

    off_t reg = scif_register(epd, (void*)reg_addr, reg_len, 0,
            SCIF_PROT_READ|SCIF_PROT_WRITE, 0);

    if(reg == SCIF_REGISTER_FAILED) {
        _IPATH_INFO("SCIF: Registering memory %p (%p) length %ld (%ld) epd %d failed: (%d) %s\n",
                addr, (void*)reg_addr, len, reg_len, epd,
                errno, strerror(errno));

        *offset = SCIF_REGISTER_FAILED;
        return PSM_INTERNAL_ERR;
    }

    /* Although the registration is rounded out to whole pages, return the
       exact SCIF-space registration offset for the specified address. */
    *offset = reg + addr_offset;
    return PSM_OK;
}

int scif_unregister_region(scif_epd_t epd, off_t reg, size_t len)
{
    /* SCIF requires registrations on page granularity.  The address must be
       rounded down to a page boundary, and the length must be rounded up. */
    off_t reg_addr = reg & ~0xFFF;
    size_t reg_len = len + ((size_t)reg & 0xFFF);

    if(reg_len & 0xFFF) {
        reg_len += 0x1000 - (reg_len & 0xFFF);
    }

    if(scif_unregister(epd, reg_addr, reg_len)) {
        _IPATH_INFO("SCIF: Unregistering offset %lx (%lx) length %ld (%ld) epd %d failed: (%d) %s\n",
                reg, reg_addr, len, reg_len, epd,
                errno, strerror(errno));
        return PSM_INTERNAL_ERR;
    }

    return PSM_OK;
}

#endif /* defined(PSM_USE_SCIF) */

