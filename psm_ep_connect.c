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

#include "psm_user.h"

int psmi_ep_device_is_enabled(const psm_ep_t ep, int devid);

psm_error_t
__psm_ep_connect(psm_ep_t ep, int num_of_epid,
	        psm_epid_t const *array_of_epid,
	        int const *array_of_epid_mask, /* can be NULL */
	        psm_error_t  *array_of_errors,
	        psm_epaddr_t *array_of_epaddr,
	        int64_t timeout)
{
    psm_error_t err = PSM_OK;
    ptl_ctl_t *ptlctl;
    ptl_t     *ptl;
    int i, j, dup_idx;
    int num_toconnect = 0;
    int *epid_mask = NULL;
    int *epid_mask_isdupof = NULL;
    char *device;
    uint64_t t_start = get_cycles();
    uint64_t t_left;
    union psmi_envvar_val timeout_intval;

    PSMI_ERR_UNLESS_INITIALIZED(ep);

    PSMI_PLOCK();

    /*
     * Normally we would lock here, but instead each implemented ptl component
     * does its own locking.  This is mostly because the ptl components are
     * ahead of the PSM interface in that they can disconnect their peers.
     */
    if (ep == NULL || array_of_epaddr == NULL || array_of_epid == NULL ||
	num_of_epid < 1) {
	err = psmi_handle_error(ep, PSM_PARAM_ERR, 
				 "Invalid psm_ep_connect parameters");
	goto fail;
    } 
    
    /* We need two of these masks to detect duplicates */
    err = PSM_NO_MEMORY;
    epid_mask = (int *) psmi_malloc(ep, UNDEFINED, sizeof(int) * num_of_epid);
    if (epid_mask == NULL) 
	goto fail;
    epid_mask_isdupof = (int *) psmi_malloc(ep, UNDEFINED, sizeof(int) * num_of_epid);
    if (epid_mask_isdupof == NULL) 
	goto fail;
    err = PSM_OK;

    /* Eventually handle timeouts across all connects. */
    for (j = 0; j < num_of_epid; j++) {
	if (array_of_epid_mask != NULL && !array_of_epid_mask[j])
	    epid_mask[j] = 0;
	else {
	    epid_mask[j] = 1;
	    array_of_errors[j] = PSM_EPID_UNKNOWN;
	    array_of_epaddr[j] = NULL;
	    num_toconnect++;
	}
	epid_mask_isdupof[j] = -1;
    }

    psmi_getenv("PSM_CONNECT_TIMEOUT",
                "End-point connection timeout over-ride. 0 for no time-out.",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) 0,
                &timeout_intval);

    if (getenv("PSM_CONNECT_TIMEOUT")) {
        timeout = timeout_intval.e_uint * SEC_ULL;
    }
    else if (timeout > 0) {
        /* The timeout parameter provides the minimum timeout. A heuristic
	 * is used to scale up the timeout linearly with the number of 
	 * endpoints, and we allow one second per 100 endpoints. */
        timeout = max(timeout, (num_toconnect * SEC_ULL) / 100);
    }

    if (timeout > 0 && timeout < PSMI_MIN_EP_CONNECT_TIMEOUT)
        timeout = PSMI_MIN_EP_CONNECT_TIMEOUT;
    _IPATH_PRDBG("Connect to %d endpoints with time-out of %.2f secs\n",
                 num_toconnect, (double) timeout/ 1e9);

    /* Look for duplicates in input array */
    for (i = 0; i < num_of_epid; i++) {
	for (j = i + 1; j < num_of_epid; j++) {
	    if (array_of_epid[i] == array_of_epid[j] &&
		epid_mask[i] && epid_mask[j]) {
		epid_mask[j] = 0; /* don't connect more than once */
		epid_mask_isdupof[j] = i;
	    }
	}
    }

    for (i = 0; i < PTL_MAX_INIT; i++) {
	if (ep->devid_enabled[i] == -1)
	    continue;
	/* Set up the right connect ptrs */
	switch (ep->devid_enabled[i]) {
	    case PTL_DEVID_IPS:
		ptlctl = &ep->ptl_ips;
		ptl = ep->ptl_ips.ptl;
		device = "ips";
		break;
	    case PTL_DEVID_AMSH:
		ptlctl = &ep->ptl_amsh;
		ptl = ep->ptl_amsh.ptl;
		device = "amsh";
		break;
	    case PTL_DEVID_SELF:
		ptlctl = &ep->ptl_self;
		ptl = ep->ptl_self.ptl;
		device = "self";
		break;
	    default:
		device = "unknown";
		ptlctl = &ep->ptl_ips; /*no-unused*/
		ptl = ep->ptl_ips.ptl; /*no-unused*/
		device = "ips"; /*no-unused*/
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
			"Unknown/unhandled PTL id %d\n", ep->devid_enabled[i]);
		break;
	}
	t_left = psmi_cycles_left(t_start, timeout);

	_IPATH_VDBG("Trying to connect with device %s\n", device);
	if ((err = ptlctl->ep_connect(ptl, num_of_epid, array_of_epid, 
		    epid_mask, array_of_errors, array_of_epaddr, 
		    cycles_to_nanosecs(t_left)))) 
	{
		_IPATH_PRDBG("Connect failure in device %s err=%d\n", 
			    device, err);
		goto connect_fail;
	}

	/* Now process what's been connected */
	for (j = 0; j < num_of_epid; j++) {
	    dup_idx = epid_mask_isdupof[j];
	    if (!epid_mask[j] && dup_idx == -1)
		continue;

	    if (dup_idx != -1) { /* dup */
		array_of_epaddr[j] = array_of_epaddr[dup_idx];
		array_of_errors[j] = array_of_errors[dup_idx];
		epid_mask_isdupof[j] = -1;
	    }

	    if (array_of_errors[j] == PSM_OK) {
		epid_mask[j] = 0; /* don't try on next ptl */
		ep->connections++;
	    }
	}
    }

    for (i = 0; i < num_of_epid; i++) {
	ptl_ctl_t *c = NULL;
	if (array_of_epid_mask != NULL && !array_of_epid_mask[i])
	    continue;
	/* If we see unreachable here, that means some PTLs were not enabled */
	if (array_of_errors[i] == PSM_EPID_UNREACHABLE) {
	    err = PSM_EPID_UNREACHABLE;
	    break;
	}
	
	psmi_assert_always(array_of_epaddr[i] != NULL);
	c = array_of_epaddr[i]->ptlctl;
	psmi_assert_always(c != NULL);
	_IPATH_VDBG("%-20s DEVICE %s (%p)\n", 
		psmi_epaddr_get_name(array_of_epid[i]),
		c == &ep->ptl_ips ? "ipath" :
		    (c == &ep->ptl_amsh ? "amsh" : "self" ),
		(void *) array_of_epaddr[i]->ptl);
    }

connect_fail:
    /* If the error is a timeout (at worse) and the client is InfiniPath MPI,
     * just return timeout to let InfiniPath MPI handle the hostnames that
     * timed out */
    if (err != PSM_OK) {
	char errbuf[PSM_ERRSTRING_MAXLEN];
	size_t len;
	int j = 0;

	if (err == PSM_EPID_UNREACHABLE) {
	    char *deverr = "of an incorrect setting";
	    char *eperr = " ";
	    char *devname = NULL;
	    if (!psmi_ep_device_is_enabled(ep, PTL_DEVID_AMSH)) {
		deverr = "there is no shared memory PSM device (shm)";
		eperr = " shared memory ";
	    }
	    else if (!psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) {
		deverr = "there is no InfiniPath PSM device (ipath)";
		eperr = " InfiniPath ";
	    }

	    len = snprintf(errbuf, sizeof errbuf - 1,
		"Some%sendpoints could not be connected because %s "
		"in the currently enabled PSM_DEVICES (",
		eperr, deverr);
	    for (i = 0; i < PTL_MAX_INIT && len < sizeof errbuf - 1; i++) {
		switch (ep->devid_enabled[i]) {
		    case PTL_DEVID_IPS:
			devname = "ipath";
			break;
		    case PTL_DEVID_AMSH:
			devname = "shm";
			break;
		    case PTL_DEVID_SELF:
		    default:
			devname = "self";
			break;
		}
		len += snprintf(errbuf+len, sizeof errbuf - len - 1,
				"%s,", devname);
	    }
	    if (len < sizeof errbuf - 1 && devname != NULL)
		/* parsed something, remove trailing comma */
		errbuf[len-1] = ')';
	}
	else 
	    len = snprintf(errbuf, sizeof errbuf - 1,
		       "%s", err == PSM_TIMEOUT ? 
		       "Dectected connection timeout" : 
		       psm_error_get_string(err));

	/* first pass, look for all nodes with the error */
	for (i = 0; i < num_of_epid && len < sizeof errbuf - 1; i++) {
	    if (array_of_epid_mask != NULL && !array_of_epid_mask[i])
		continue;
	    if (array_of_errors[i] == PSM_OK)
		continue;
	    if (array_of_errors[i] == PSM_EPID_UNREACHABLE &&
		err != PSM_EPID_UNREACHABLE)
		continue;
	    if (err == array_of_errors[i]) {
		len += snprintf(errbuf+len, sizeof errbuf - len - 1,
			    "%c %s", j==0 ? ':' : ',',
			    psmi_epaddr_get_hostname(array_of_epid[i]));
		j++;
	    }
	}
	errbuf[sizeof errbuf - 1] = '\0';
	err = psmi_handle_error(ep, err, errbuf, "%s");
    }

fail:
    PSMI_PUNLOCK();

    if (epid_mask != NULL)
	psmi_free(epid_mask);
    if (epid_mask_isdupof != NULL)
	psmi_free(epid_mask_isdupof);

    return err;
}
PSMI_API_DECL(psm_ep_connect)

