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

#include "ips_proto.h"
#include "ips_proto_internal.h"
#include "ips_epstate.h"

/* The indexes are used to map a particular endpoint to a strcture at the
 * receiver.  Although we take extra care to validate the identity of endpoints
 * when packets are received, the communication index is at an offset selected
 * by the endpoint that allocates the index.  This narrows the window of two
 * jobs communicated with the same set of indexes from getting crosstalk.
 */
/* Allocate new epaddrs in chunks of 128 */
#define PTL_EPADDR_ALLOC_CHUNK  128

psm_error_t
ips_epstate_init(struct ips_epstate *eps, const psmi_context_t *context)
{
    memset(eps, 0, sizeof(*eps));
    eps->context = context;
    eps->eps_base_idx = ((ips_epstate_idx)get_cycles()) &
      (IPS_EPSTATE_COMMIDX_MAX-1);
    return PSM_OK;
}

psm_error_t
ips_epstate_fini(struct ips_epstate *eps)
{
    if (eps->eps_tab)
	psmi_free(eps->eps_tab);
    memset(eps, 0, sizeof(*eps));
    return PSM_OK;
}

/*
 * Add ipsaddr with epid to the epstate table, return new index to caller in
 * 'commidx'.
 */
psm_error_t
ips_epstate_add(struct ips_epstate *eps, struct ptl_epaddr *ipsaddr,
		ips_epstate_idx *commidx_o)
{
    int i, j;
    ips_epstate_idx commidx;
    uint16_t lmc_mask = ~((1 << ipsaddr->proto->epinfo.ep_lmc) - 1);
    
    if (++eps->eps_tabsizeused > eps->eps_tabsize) { /* realloc */
	struct ips_epstate_entry *newtab;
	eps->eps_tabsize += PTL_EPADDR_ALLOC_CHUNK;
	newtab = (struct ips_epstate_entry *) 
	    psmi_calloc(eps->context->ep, PER_PEER_ENDPOINT, eps->eps_tabsize, 
			sizeof(struct ips_epstate_entry));
	if (newtab == NULL) 
	    return PSM_NO_MEMORY;
	else if (eps->eps_tab) { /* NOT first alloc */
	    for (i = 0; i < eps->eps_tabsize-PTL_EPADDR_ALLOC_CHUNK; i++)
		newtab[i] = eps->eps_tab[i]; /* deep copy */
	    psmi_free(eps->eps_tab);
	}
	eps->eps_tab = newtab;
    }
    /* Find the next free hole.  We can afford to do this since connect is not
     * in the critical path */
    for (i = 0, j = eps->eps_tab_nextidx; i < eps->eps_tabsize; i++, j++) {
	if (j == eps->eps_tabsize)
	    j = 0;
	if (eps->eps_tab[j].epid == 0) {
	    eps->eps_tab_nextidx = j + 1;
	    if (eps->eps_tab_nextidx == eps->eps_tabsize)
		eps->eps_tab_nextidx = 0;
	    break;
	}
    }
    psmi_assert_always(i != eps->eps_tabsize);
    commidx = (j - eps->eps_base_idx) & (IPS_EPSTATE_COMMIDX_MAX-1);
    _IPATH_VDBG("node %s gets commidx=%d (table idx %d)\n", 
	    psmi_epaddr_get_name(ipsaddr->epaddr->epid), commidx, j);
    eps->eps_tab[j].epid = 
      PSMI_EPID_PACK(ipsaddr->epr.epr_base_lid & lmc_mask,
		     ipsaddr->epr.epr_context,
		     ipsaddr->epr.epr_subcontext);
    eps->eps_tab[j].ipsaddr = ipsaddr;
    if (j >= IPS_EPSTATE_COMMIDX_MAX) {
	return psmi_handle_error(eps->context->ep, PSM_TOO_MANY_ENDPOINTS, 
	    "Can't connect to more than %d non-local endpoints", 
	    IPS_EPSTATE_COMMIDX_MAX);
    }
    *commidx_o = commidx;
    return PSM_OK;
}

psm_error_t
ips_epstate_del(struct ips_epstate *eps, ips_epstate_idx commidx)
{
    ips_epstate_idx idx;
    /* actual table index */
    idx = (commidx + eps->eps_base_idx) & (IPS_EPSTATE_COMMIDX_MAX-1);
    psmi_assert_always(idx < eps->eps_tabsize);
    _IPATH_VDBG("commidx=%d, table_idx=%d\n", commidx, idx);
    eps->eps_tab[idx].epid = 0;
    eps->eps_tab[idx].ipsaddr = NULL;
    /* We may eventually want to release memory, but probably not */
    eps->eps_tabsizeused--;
    return PSM_OK;
}

