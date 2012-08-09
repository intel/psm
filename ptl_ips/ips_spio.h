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

#ifndef IPS_SPIO_H
#define IPS_SPIO_H

#include "psm_user.h"

struct ips_spio;
struct ptl;

psm_error_t ips_spio_init(const psmi_context_t *context, 
			  const struct ptl *ptl,
			  struct ips_spio *ctrl);
psm_error_t ips_spio_transfer_frame(struct ips_spio *ctrl,struct ips_flow *flow,
				    void *header, void *payload, int length,
				    uint32_t isCtrlMsg, 
				    uint32_t cksum_valid, uint32_t cksum);
psm_error_t ips_spio_fini(struct ips_spio *ctrl);

struct ips_spio
{
    const struct ptl       *ptl;
    const psmi_context_t   *context;
    uint32_t	            runtime_flags;
    int			    unit_id;
    uint16_t		    portnum;
    pthread_spinlock_t      spio_lock;

    /* pio copy routine */
    void  (*spio_copy_fn)(volatile uint32_t *,
	const struct ipath_pio_params *pioparm, void *, void *);

    volatile __le64   *spio_avail_addr __attribute__((aligned(64)));
    volatile uint32_t *spio_buffer_base;
    volatile unsigned long *spio_sendbuf_status;

    uint32_t spio_buffer_spacing;
    uint32_t spio_first_buffer;
    uint32_t spio_last_buffer;
    uint32_t spio_current_buffer;
    uint32_t spio_num_of_buffer;

    uint64_t spio_avail_shadow[8] __attribute__((aligned(64)));

    uint32_t spio_consecutive_failures;
    uint64_t spio_num_stall;
    uint64_t spio_num_stall_total;
    uint64_t spio_next_stall_warning;
    uint64_t spio_last_stall_cyc;
    uint64_t spio_init_cyc;
  
};

#endif /* IPS_SPIO_H */
