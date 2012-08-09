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

#ifndef _IPS_STATS_H
#define _IPS_STATS_H

struct psm_epaddr;  /* for non-PSM clients */

/* Old stats */
typedef 
struct {
	uint64_t err_chk_send;
	uint64_t err_chk_recv;
	uint64_t send_failed;
	uint64_t recv_dropped;
	union {
	    uint64_t recv_copied; /* obsolete */
	    uint64_t nak_sent;
	};
	uint64_t nak_recv;
	uint64_t total_send_eager;
	uint64_t total_send_exp;
	uint64_t acks_sent;
	uint64_t retransmits;
	uint64_t recv_matched;
	uint64_t recv_unmatched;
	uint64_t scb_alloc_yields;
} ips_sess_stat;

int ips_get_stat(struct psm_epaddr *epaddr, ips_sess_stat *stats);

#endif /* _IPS_STATS_H */
