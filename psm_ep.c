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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h> // cpu_set
#include <ctype.h> // isalpha

#include "psm_user.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"

/*
 * Endpoint management
 */
psm_ep_t psmi_opened_endpoint = NULL; 
int psmi_opened_endpoint_count = 0;

static psm_error_t psmi_ep_open_device(const psm_ep_t ep, 
			    const struct psm_ep_open_opts *opts,
			    const psm_uuid_t unique_job_key,
			    struct psmi_context *context,
			    psm_epid_t *epid);

/*
 * Device managment
 *
 * PSM uses "devices" as components to manage communication to self, to peers
 * reachable via shared memory and finally to peers reachable only through
 * ipath.
 *
 * By default, PSMI_DEVICES_DEFAULT establishes the bind order a component is
 * tested for reachability to each peer.  First self, then shm and finally
 * ipath.  The order should really only affect endpoints that happen to be on
 * the same node.  PSM will correctly detect that two endpoints are on the same
 * node even though they may be using different host interfaces.
 */

#define PSMI_DEVICES_DEFAULT "self,shm,ipath"
static psm_error_t psmi_parse_devices(int devices[PTL_MAX_INIT], 
				      const char *devstr);
static int	   psmi_device_is_enabled(const int devices[PTL_MAX_INIT],
					  int devid);
int		   psmi_ep_device_is_enabled(const psm_ep_t ep, int devid);

psm_error_t
__psm_ep_num_devunits(uint32_t *num_units_o)
{
    static int num_units = -1;

    PSMI_ERR_UNLESS_INITIALIZED(NULL);

    if (num_units == -1) {
	num_units = ipath_get_num_units();
	if (num_units == -1)
	    num_units = 0;
    }

    *num_units_o = (uint32_t) num_units;
    return PSM_OK;
}
PSMI_API_DECL(psm_ep_num_devunits)

static int
cmpfunc(const void *p1, const void *p2)
{
    uint64_t a = ((uint64_t *)p1)[0];
    uint64_t b = ((uint64_t *)p2)[0];
    if (a < b) return -1;
    if (a == b) return 0;
    return 1;
}
static psm_error_t
psmi_ep_multirail(int *num_rails, uint32_t *unit, uint16_t *port)
{
    uint32_t num_units;
    uint64_t gid_hi, gid_lo;
    int i, j, ret, count=0;
    char *env;
    psm_error_t err = PSM_OK;
    uint64_t gidh[IPATH_MAX_UNIT][3];

    env = getenv("PSM_MULTIRAIL");
    if (!env || atoi(env) == 0) {
	*num_rails = 0;
	return err;
    }
#ifdef __MIC__
    env = getenv("MPI_LOCALRANKID");
    if (!env || atoi(env) == 0) {
	_IPATH_INFO("PSM_MULTIRAIL is not supported and "
			"ignored for this PSM mic version.\n");
    }
    *num_rails = 0;
    return err;
#endif

/*
 * map is in format: unit:port,unit:port,...
 */
    if ((env = getenv("PSM_MULTIRAIL_MAP"))) {
	if (sscanf(env, "%d:%d", &i, &j) == 2) {
	    char *comma = strchr(env, ',');
	    unit[count] = i;
	    port[count] = j;
	    count++;
	    while (comma) {
		if (sscanf(comma, ",%d:%d", &i, &j) != 2) {
		    break;
		}
		unit[count] = i;
		port[count] = j;
		count++;
		if (count == IPATH_MAX_UNIT) break;
		comma = strchr(comma+1, ',');
	    }
	}
	*num_rails = count;

/*
 * Check if any of the port is not usable.
 */
	for (i = 0; i < count; i++) {
	    ret = ipath_get_port_lid(unit[i], port[i]);
	    if (ret == -1) {
		err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
			    "Couldn't get lid for unit %d:%d",
			    unit[i], port[i]);
		return err;
	    }
	    ret = ipath_get_port_gid(unit[i], port[i], &gid_hi, &gid_lo);
	    if (ret == -1) {
		err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
			    "Couldn't get gid for unit %d:%d",
			    unit[i], port[i]);
		return err;
	    }
	}

	return err;
    }

    if ((err = psm_ep_num_devunits(&num_units))) {
	return err;
    }
    if (num_units > IPATH_MAX_UNIT) {
	_IPATH_INFO("Found %d units, max %d units are supported, use %d\n",
		num_units, IPATH_MAX_UNIT, IPATH_MAX_UNIT);
	num_units = IPATH_MAX_UNIT;
    }

/*
 * Get all the ports with a valid lid and gid, one per unit.
 * we don't know which number is a valid unit, we just loop
 * over all supported numbers.
 */
    for (i = 0; i < IPATH_MAX_UNIT; i++) {
	for (j = 1; j <= IPATH_MAX_PORT; j++) {
	    ret = ipath_get_port_lid(i, j);
	    if (ret == -1) continue;
	    ret = ipath_get_port_gid(i, j, &gid_hi, &gid_lo);
	    if (ret == -1) continue;

	    gidh[count][0] = gid_hi;
	    gidh[count][1] = i;
	    gidh[count][2] = j;
	    count++;
	    break;
	}
	if (count == num_units) break;
    }

/*
 * Sort all the ports with gidh from small to big.
 * This is for multiple fabrics, and we use fabric with the
 * smallest gid to make the master connection.
 */
    qsort(gidh, count, sizeof(uint64_t)*3, cmpfunc);

    for (i = 0; i < count; i++) {
	unit[i] = (uint32_t)gidh[i][1];
	port[i] = (uint16_t)(uint32_t)gidh[i][2];
    }
    *num_rails = count;
    return err;
}

static psm_error_t
psmi_ep_devlids(uint16_t **lids, uint32_t *num_lids_o,
		uint64_t my_gid_hi, uint64_t my_gid_lo)
{
    static uint16_t *ipath_lids = NULL;
    static uint32_t nlids;
    uint32_t num_units;
    int i;
    psm_error_t err = PSM_OK;

    PSMI_ERR_UNLESS_INITIALIZED(NULL);

    if (ipath_lids == NULL) {
	if ((err = psm_ep_num_devunits(&num_units)))
	    goto fail;
	ipath_lids = (uint16_t *) 
	    psmi_calloc(PSMI_EP_NONE, UNDEFINED, num_units*IPATH_MAX_PORT,
		sizeof(uint16_t));
	if (ipath_lids == NULL) {
	    err = psmi_handle_error(NULL, PSM_NO_MEMORY, 
		    "Couldn't allocate memory for dev_lids structure");
	    goto fail;
	}

	for (i = 0; i < IPATH_MAX_UNIT; i++) {
	    int j;
	    for (j = 1; j <= IPATH_MAX_PORT; j++) {
		    int lid = ipath_get_port_lid(i, j);
		    int ret;
		    uint64_t gid_hi = 0, gid_lo = 0;

		    if (lid == -1) continue;
		    ret = ipath_get_port_gid(i, j, &gid_hi, &gid_lo);
		    if (ret == -1)
			continue;
		    else if (my_gid_hi != gid_hi) {
		        _IPATH_VDBG("LID %d, unit %d, port %d, "
                                    "mismatched GID %llx:%llx and "
				    "%llx:%llx\n",
				    lid, i, j,
				    (unsigned long long) gid_hi,
				    (unsigned long long) gid_lo,
				    (unsigned long long) my_gid_hi,
				    (unsigned long long) my_gid_lo);
		        continue;
		    }
		    _IPATH_VDBG("LID %d, unit %d, port %d, "
                                "matching GID %llx:%llx and "
				"%llx:%llx\n", lid, i, j,
				(unsigned long long) gid_hi,
				(unsigned long long) gid_lo,
				(unsigned long long) my_gid_hi,
				(unsigned long long) my_gid_lo);

		    ipath_lids[nlids++] = (uint16_t) lid;
	    }
	}
	if (nlids == 0) {
		err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
			    "Couldn't get lid&gid from any unit/port");
		goto fail;
	}
    }
    *lids = ipath_lids;
    *num_lids_o = nlids;

fail:
    return err;
}

uint64_t
__psm_epid_nid(psm_epid_t epid)
{
    return PSMI_EPID_GET_LID(epid);
}
PSMI_API_DECL(psm_epid_nid)

/* Currently not exposed to users, we don't acknowledge the existence of
 * subcontexts */
uint64_t
psmi_epid_subcontext(psm_epid_t epid)
{
    return PSMI_EPID_GET_SUBCONTEXT(epid);
}

/* Currently not exposed to users, we don't acknowledge the existence of
 * service levels and HCA types encoding within epids. This may require
 * changing to expose SLs
 */
uint64_t
psmi_epid_hca_type(psm_epid_t epid)
{
  return PSMI_EPID_GET_HCATYPE(epid);
}

uint64_t
psmi_epid_sl(psm_epid_t epid)
{
  return PSMI_EPID_GET_SL(epid);
}

uint64_t
__psm_epid_context(psm_epid_t epid)
{
    return PSMI_EPID_GET_CONTEXT(epid);
}
PSMI_API_DECL(psm_epid_context)

uint64_t
__psm_epid_port(psm_epid_t epid)
{
    return __psm_epid_context(epid);
}
PSMI_API_DECL(psm_epid_port)

psm_error_t 
__psm_ep_query (int *num_of_epinfo, psm_epinfo_t *array_of_epinfo)
{
  psm_error_t err = PSM_OK;
  int i;
  psm_ep_t ep;
  
  PSMI_ERR_UNLESS_INITIALIZED(NULL);
  
  if (*num_of_epinfo <= 0) {
    err = psmi_handle_error(NULL, PSM_PARAM_ERR, 
			    "Invalid psm_ep_query parameters");
    return err;
  }

  if (psmi_opened_endpoint == NULL) {
    err =  psmi_handle_error(NULL, PSM_EP_WAS_CLOSED,
			     "PSM Endpoint is closed or does not exist");
    return err;
  }
  
  ep = psmi_opened_endpoint;
  for (i = 0; i < *num_of_epinfo; i++) {
	if (ep == NULL) break;
	array_of_epinfo[i].ep = ep;
	array_of_epinfo[i].epid = ep->epid;
	memcpy(array_of_epinfo[i].uuid, 
	 (void *) ep->key, sizeof(psm_uuid_t));
	psmi_uuid_unparse(ep->key, array_of_epinfo[i].uuid_str);
	ep = ep->user_ep_next;
  }
  *num_of_epinfo = i;

  return err;
}
PSMI_API_DECL(psm_ep_query)

psm_error_t 
__psm_ep_epid_lookup (psm_epid_t epid, psm_epconn_t *epconn)
{
  psm_error_t err = PSM_OK;
  psm_epaddr_t epaddr;
  psm_ep_t ep;
  
  PSMI_ERR_UNLESS_INITIALIZED(NULL);

  /* Need to have an opened endpoint before we can resolve epids */
  if (psmi_opened_endpoint == NULL) {
    err =  psmi_handle_error(NULL, PSM_EP_WAS_CLOSED,
			     "PSM Endpoint is closed or does not exist");
    return err;
  }
  
  ep = psmi_opened_endpoint;
  while (ep) {
	epaddr = psmi_epid_lookup(ep, epid);
	if (!epaddr) {
	    /* Search over SL values for bug 122239. Note that function
	     * ips_get_addr_from_epid() converts a base epid to an epaddr,
	     * which can then be used to get the correct epid for this flow.
	     * However, that function is at the IPS level and not accessible 
	     * from here without breaking the layering. */
	    uint64_t lid, context, subcontext, hca_type, sl, try_sl;
	    psm_epid_t try_epid;
	    lid = PSMI_EPID_GET_LID(epid);
	    context = PSMI_EPID_GET_CONTEXT(epid);
	    subcontext = PSMI_EPID_GET_SUBCONTEXT(epid);
	    hca_type = PSMI_EPID_GET_HCATYPE(epid);
	    sl = PSMI_EPID_GET_SL(epid);
	    for (try_sl = 0; !epaddr && try_sl < 16; try_sl++) {
	      if (try_sl != sl) {
	        try_epid = PSMI_EPID_PACK_EXT(lid, context, subcontext,
					      hca_type, try_sl);
	        epaddr = psmi_epid_lookup(psmi_opened_endpoint, try_epid);
	      }
	    }

	    if (!epaddr) {
		ep = ep->user_ep_next;
		continue;
	    }
	}
  
	/* Found connection for epid. Return info about endpoint to caller. */
	psmi_assert_always(epaddr->ep == ep);
	epconn->addr = epaddr;
	epconn->ep   = epaddr->ep;
	epconn->mq   = epaddr->ep->mq;
	return err;
  }
  
  err =  psmi_handle_error(NULL, PSM_EPID_UNKNOWN,
	     "Endpoint connection status unknown");
  return err;
}
PSMI_API_DECL(psm_ep_epid_lookup);

psm_error_t
__psm_ep_epid_share_memory(psm_ep_t ep, psm_epid_t epid, int *result_o)
{
    uint32_t num_lids = 0;
    uint16_t *lids = NULL;
    int i;
    uint16_t epid_lid;
    int result = 0;
    psm_error_t err;

    psmi_assert_always(ep != NULL);
    PSMI_ERR_UNLESS_INITIALIZED(ep);

    epid_lid = (uint16_t) psm_epid_nid(epid);
    /* If we're in non-ipath mode, done bother listing lids */
    if (!psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) {
	uint64_t mylid = (uint16_t) psm_epid_nid(ep->epid);
	if (mylid == epid_lid)
	    result = 1;
    }
    else {
        err = psmi_ep_devlids(&lids, &num_lids, ep->gid_hi, ep->gid_lo);
	if (err)
	    return err;
	for (i = 0; i < num_lids; i++) {
	    if (epid_lid == lids[i]) {
		result = 1;
		break;
	    }
	}
    }
    *result_o = result;
    return PSM_OK;
}
PSMI_API_DECL(psm_ep_epid_share_memory)

#define PSMI_EP_OPEN_SHM_MBYTES_MIN     2
#define PSMI_EP_OPEN_PKEY_MASK	        0x7fffULL

psm_error_t
__psm_ep_open_opts_get_defaults(struct psm_ep_open_opts *opts)
{
    union psmi_envvar_val nSendBuf;
    union psmi_envvar_val netPKey;
#if (PSM_VERNO >= 0x010d)
    union psmi_envvar_val env_path_service_id;
    union psmi_envvar_val env_path_res_type;
#endif
#if (PSM_VERNO >= 0x010e)
    union psmi_envvar_val nSendDesc;
    union psmi_envvar_val immSize;
#endif

    PSMI_ERR_UNLESS_INITIALIZED(NULL);
    
    /* Get number of default send buffers from environment */
    psmi_getenv("PSM_NUM_SEND_BUFFERS",
		"Number of send buffers to allocate [1024]",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 1024,
		&nSendBuf);
    
    /* Get network key from environment. MVAPICH and other vendor MPIs do not
     * specify it on ep open and we may require it for vFabrics.
     */
    psmi_getenv("PSM_PKEY",
		"Infiniband PKey to use for endpoint",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_ULONG,
		(union psmi_envvar_val) IPATH_DEFAULT_P_KEY,
		&netPKey);

#if (PSM_VERNO >= 0x010d)    
    /* Get Service ID from environment */
    psmi_getenv("PSM_IB_SERVICE_ID",
		"IB Service ID for path resolution",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_ULONG_ULONG,
		(union psmi_envvar_val) IPATH_DEFAULT_SERVICE_ID, 
		&env_path_service_id);
    
    /* Get Path resolution type from environment Possible choices are:
     *
     * NONE : Default same as previous instances. Utilizes static data.
     * OPP  : Use OFED Plus Plus library to do path record queries.
     * UMAD : Use raw libibumad interface to form and process path records.
     * ANY  : Try all available path record mechanisms.
     */
    psmi_getenv("PSM_PATH_REC",
                "Mechanism to query IB path record (default is no path query)",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
                (union psmi_envvar_val) "none", &env_path_res_type);
#endif

#if (PSM_VERNO >= 0x010e)
    /* Get numner of send descriptors - by default this is 4 times the number
     * of send buffers - mainly used for short/inlined messages.
     */
    psmi_getenv("PSM_NUM_SEND_DESCRIPTORS",
		"Number of send descriptors to allocate [4096]",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) (nSendBuf.e_uint << 2),
		&nSendDesc);

    /* Get immediate data size - transfers less than immediate data size do
     * not consume a send buffer and require just a send descriptor.
     */
    psmi_getenv("PSM_SEND_IMMEDIATE_SIZE",
		"Immediate data send size not requiring a buffer [128]",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) 128,
		&immSize);
#endif
    
    opts->timeout = 30000000000LL; /* 30 sec */
    opts->unit    = IPATH_UNIT_ID_ANY;
    opts->port    = 0;
    opts->outsl    = PSMI_SL_DEFAULT;
#if (PSM_VERNO >= 0x0107) && (PSM_VERNO <= 0x010a)
    opts->outvl    = 0;
#endif
    opts->affinity = PSM_EP_OPEN_AFFINITY_SET;
    opts->shm_mbytes = 10;
    opts->sendbufs_num = nSendBuf.e_uint;
    opts->network_pkey = (uint64_t) netPKey.e_ulong;
#if (PSM_VERNO >= 0x010d)
    opts->service_id = (uint64_t) env_path_service_id.e_ulonglong;
    
    if (!strcasecmp(env_path_res_type.e_str, "none"))
      opts->path_res_type = PSM_PATH_RES_NONE;
    else if (!strcasecmp(env_path_res_type.e_str, "opp"))
      opts->path_res_type = PSM_PATH_RES_OPP;
    else if (!strcasecmp(env_path_res_type.e_str, "umad"))
      opts->path_res_type = PSM_PATH_RES_UMAD;
    else {
      _IPATH_ERROR("Unknown path resolution type %s. Disabling use of path record query.\n", env_path_res_type.e_str);
      opts->path_res_type = PSM_PATH_RES_NONE;
    }
#endif
#if (PSM_VERNO >= 0x010e)
    opts->senddesc_num = nSendDesc.e_uint;
    opts->imm_size     = immSize.e_uint;
#endif

    return PSM_OK;
}
PSMI_API_DECL(psm_ep_open_opts_get_defaults)

psm_error_t psmi_poll_noop(ptl_t *ptl, int replyonly);

psm_error_t
__psm_ep_open_internal(psm_uuid_t const unique_job_key, int *devid_enabled,
	    struct psm_ep_open_opts const *opts_i, psm_mq_t mq,
	    psm_ep_t *epo, psm_epid_t *epido)
{
    psm_ep_t ep = NULL;
    uint32_t num_units;
    size_t len;
    psm_error_t err;
    psm_epaddr_t epaddr = NULL;
    char buf[128], *p, *e;
    char *old_cpuaff = NULL, *old_unit = NULL;
    union psmi_envvar_val yield_cnt, no_cpuaff, env_unit_id,
	  env_port_id, env_sl;
    size_t ptl_sizes;
    int default_cpuaff;
    struct psm_ep_open_opts opts;
    ptl_t *amsh_ptl, *ips_ptl, *self_ptl;
    int i;

    /* First get the set of default options, we overwrite with the user's
     * desired values afterwards */
    if ((err = psm_ep_open_opts_get_defaults(&opts))) 
	goto fail;

    if (opts_i != NULL) {
	if (opts_i->timeout != -1)
	    opts.timeout = opts_i->timeout;
	if (opts_i->unit != -1)
	    opts.unit = opts_i->unit;
	if (opts_i->affinity != -1)
	    opts.affinity = opts_i->affinity;
	if (opts_i->shm_mbytes != -1)
	    opts.shm_mbytes = opts_i->shm_mbytes;
	if (opts_i->sendbufs_num != -1)
	    opts.sendbufs_num = opts_i->sendbufs_num;
	if (psmi_verno_client() >= PSMI_VERNO_MAKE(1,1)) {
	  if ((opts_i->network_pkey & PSMI_EP_OPEN_PKEY_MASK) != 
	      PSMI_EP_OPEN_PKEY_MASK) 
	    opts.network_pkey = opts_i->network_pkey;
	}
	if (psmi_verno_client() >= PSMI_VERNO_MAKE(1,7)) {
    	    /* these values are sanity checked below */
	    opts.port = opts_i->port;
	    opts.outsl = opts_i->outsl;
#if (PSM_VERNO >= 0x0107) && (PSM_VERNO <= 0x010a)
	    opts.outvl = opts_i->outvl;
#endif
	}
#if (PSM_VERNO >= 0x010d)
	/* Note: Environment variable specification for service ID and 
	 * path resolition type takes precedence over ep_open defaults.
	 */
	if (psmi_verno_client() >= 0x010d) {
	  if (opts_i->service_id)
	    opts.service_id = (uint64_t) opts_i->service_id;
	  if (opts.path_res_type == PSM_PATH_RES_NONE)
	    opts.path_res_type = opts_i->path_res_type;
	}
#endif

#if (PSM_VERNO >= 0x010e)
	if (psmi_verno_client() >= 0x010e) {
	  if (opts_i->senddesc_num)
	    opts.senddesc_num = opts_i->senddesc_num;
	  if (opts_i->imm_size) 
	    opts.imm_size = opts_i->imm_size;
	}
#endif
    }

    if (psmi_device_is_enabled(devid_enabled, PTL_DEVID_IPS)) {
	if ((err = psm_ep_num_devunits(&num_units)) != PSM_OK) 
	    goto fail;
    } else num_units = 0;

    /* do some error checking */
    if (opts.timeout < -1) {
	err = psmi_handle_error(NULL, PSM_PARAM_ERR, 
				"Invalid timeout value %lld", 
				(long long) opts.timeout);
	goto fail;
    } else if (num_units && (opts.unit < -1 || opts.unit >= IPATH_MAX_UNIT)) {
	err = psmi_handle_error(NULL, PSM_PARAM_ERR, 
				"Invalid Device Unit ID %d (%d units found)",
				opts.unit, num_units);
	goto fail;
    } else if (opts.affinity < 0 || opts.affinity > PSM_EP_OPEN_AFFINITY_FORCE) {
	err = psmi_handle_error(NULL, PSM_PARAM_ERR, 
				    "Invalid Affinity option: %d", opts.affinity);
	goto fail;
    } else if (opts.shm_mbytes < PSMI_EP_OPEN_SHM_MBYTES_MIN) {
	err = psmi_handle_error(NULL, PSM_PARAM_ERR, 
		"Invalid shm_mbytes option at %d mbytes (minimum is %d)",
		opts.shm_mbytes, PSMI_EP_OPEN_SHM_MBYTES_MIN);
	goto fail;
    } 

    /* Advertise in verbose env the fact that we parse the no-affinity
     * variable. */ 
    default_cpuaff = psmi_getenv("IPATH_NO_CPUAFFINITY",
				"Prevent PSM from setting affinity",
				PSMI_ENVVAR_LEVEL_USER,
				PSMI_ENVVAR_TYPE_YESNO,
				PSMI_ENVVAR_VAL_NO,
				&no_cpuaff);

    if (no_cpuaff.e_uint || 
	(default_cpuaff && opts.affinity == PSM_EP_OPEN_AFFINITY_SKIP)) 
    {
	old_cpuaff = getenv("IPATH_NO_CPUAFFINITY");
	setenv("IPATH_NO_CPUAFFINITY", "1", 1);
    }

#ifdef __MIC__
    /*
     * On MIC, we always pick unit from /sys/class/qib/ipath/unit,
     * but only do this if there is a HCA unit.
     */
    if (num_units > 0) {
	char pathname[128];
	struct stat st;
	FILE *fp;
	
	snprintf(pathname, sizeof(pathname),
		"/sys/class/qib/ipath/unit");
	fp = NULL;
	if (stat(pathname, &st) || S_ISDIR(st.st_mode) ||
	!(fp = fopen(pathname, "r")) || (fscanf(fp, "%d", &opts.unit) != 1)) {
	    err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
				"Couldn't read from %s", pathname);
	    if (fp) fclose(fp);
	    goto fail;
	}
	fclose(fp);
	psmi_assert(opts.unit != IPATH_UNIT_ID_ANY);
	psmi_assert(opts.unit < IPATH_MAX_UNIT);
    }
#else
    /* If a specific unit is set in the environment, use that one. */
    if (!psmi_getenv("IPATH_UNIT", "Device Unit number (-1 autodetects)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_LONG,
		    (union psmi_envvar_val) IPATH_UNIT_ID_ANY,
		    &env_unit_id)) {
	opts.unit = env_unit_id.e_long;
	/* set mock UNIT *just* for setaffinity */
	if (opts.unit != IPATH_UNIT_ID_ANY) {
	    char buf[32];
	    snprintf(buf, sizeof buf - 1, "%d", (int) opts.unit);
	    buf[sizeof buf - 1] = '\0';
	    old_unit = getenv("IPATH_UNIT");
	    setenv("IPATH_UNIT", buf, 1);
	}
	else
	    unsetenv("IPATH_UNIT");
    }
#endif

    if (!psmi_getenv("IPATH_PORT", "IB Port number (<= 0 autodetects)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_LONG,
		    (union psmi_envvar_val)0,
		    &env_port_id)) {
	opts.port = env_port_id.e_long;
    }

    if (!psmi_getenv("IPATH_SL", "IB outging ServiceLevel number (default 0)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_LONG,
		    (union psmi_envvar_val) PSMI_SL_DEFAULT,
		    &env_sl)) {
	opts.outsl = env_sl.e_long;
    }

#if (PSM_VERNO >= 0x0107) && (PSM_VERNO <= 0x010a)
    {
      union psmi_envvar_val env_vl;
      if (!psmi_getenv("IPATH_VL", "IB outging VirtualLane (default 0)",
		       PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_LONG,
		       (union psmi_envvar_val)0,
		       &env_vl)) {
	opts.outvl = env_vl.e_long;
      }
    }
#endif

    /* sanity check new capabilities, after both opts and env */
    if (opts.port < 0 || opts.port > IPATH_MAX_PORT)
	err = psmi_handle_error(NULL, PSM_PARAM_ERR,
	    "Invalid Port number: %lld",
	    (unsigned long long) opts.port);
    if (opts.outsl < 0 || opts.outsl > 15)
	err = psmi_handle_error(NULL, PSM_PARAM_ERR,
	    "Invalid SL number: %lld",
	    (unsigned long long) opts.outsl);

#if (PSM_VERNO >= 0x0107) && (PSM_VERNO <= 0x010a)
    if (opts.outvl < 0 || opts.outvl > 7)
	err = psmi_handle_error(NULL, PSM_PARAM_ERR,
	    "Invalid VL number: %lld",
	    (unsigned long long) opts.outvl);
#endif

    ptl_sizes =
	(psmi_device_is_enabled(devid_enabled, PTL_DEVID_SELF) ?
	    psmi_ptl_self.sizeof_ptl() : 0) +
	(psmi_device_is_enabled(devid_enabled, PTL_DEVID_IPS) ?
	    psmi_ptl_ips.sizeof_ptl() : 0) +
	(psmi_device_is_enabled(devid_enabled, PTL_DEVID_AMSH) ?
	    psmi_ptl_amsh.sizeof_ptl() : 0);
    if (ptl_sizes == 0) return PSM_EP_NO_DEVICE;

    ep = (psm_ep_t) psmi_calloc(PSMI_EP_NONE, UNDEFINED, 1, 
				sizeof(struct psm_ep) + ptl_sizes);
    epaddr = (psm_epaddr_t) psmi_calloc(PSMI_EP_NONE, PER_PEER_ENDPOINT, 
					1, sizeof(struct psm_epaddr));
    if (ep == NULL || epaddr == NULL) {
	err = psmi_handle_error(NULL, PSM_NO_MEMORY, 
				"Couldn't allocate memory for %s structure",
				ep == NULL ? "psm_ep" : "psm_epaddr");
	goto fail;
    }

    /* Copy PTL enabled status */
    for (i = 0; i < PTL_MAX_INIT; i++)
	ep->devid_enabled[i] = devid_enabled[i];

    /* Matched Queue initialization.  We do this early because we have to
     * make sure ep->mq exists and is valid before calling ips_do_work.
     */
    ep->mq = mq;

    /* Get ready for PTL initialization */
    memcpy(&ep->key, (void *) unique_job_key, sizeof(psm_uuid_t));
    ep->epaddr = epaddr;
    ep->shm_mbytes = opts.shm_mbytes;
    ep->memmode = mq->memmode;
    ep->ipath_num_sendbufs = opts.sendbufs_num;
    ep->network_pkey = (uint16_t) opts.network_pkey & PSMI_EP_OPEN_PKEY_MASK;
#if (PSM_VERNO >= 0x010d)
    ep->service_id = opts.service_id;
    ep->path_res_type = opts.path_res_type;
#else
    /* Select sane defaults with older PSM header */
    ep->service_id = 0x1000117500000000ULL; /* Default service ID */
    ep->path_res_type = 0;  /* No path resolution */
#endif
#if (PSM_VERNO >= 0x010e)
    ep->ipath_num_descriptors = opts.senddesc_num;
    ep->ipath_imm_size = opts.imm_size;
#else
    /* Default is 4 times more descriptors than buffers */
    ep->ipath_num_descriptors = ep->ipath_num_sendbufs << 2;
    ep->ipath_imm_size = 128;
#endif
    ep->errh = psmi_errhandler_global; /* by default use the global one */
    ep->ptl_amsh.ep_poll = psmi_poll_noop;
    ep->ptl_ips.ep_poll  = psmi_poll_noop;
    ep->connections = 0;

    /* Active message fields, used by psmi_shm_attach() */
    ep->psmi_kassist_fd = -1;
    ep->psmi_kassist_mode = 0;
    ep->amsh_shmbase = 0;
    ep->amsh_blockbase = 0;
    ep->amsh_dirpage = NULL;
    ep->amsh_keyname = NULL;
    ep->amsh_shmfd = -1;
    ep->amsh_shmidx = -1;
    ep->amsh_max_idx = -1;

    /* See how many iterations we want to spin before yielding */
    psmi_getenv("PSM_YIELD_SPIN_COUNT",
		"Spin poll iterations before yield",
		PSMI_ENVVAR_LEVEL_HIDDEN,
		PSMI_ENVVAR_TYPE_UINT,
		(union psmi_envvar_val) PSMI_BLOCKUNTIL_POLLS_BEFORE_YIELD,
		&yield_cnt);
    ep->yield_spin_cnt = yield_cnt.e_uint;

    ptl_sizes = 0;
    amsh_ptl = ips_ptl = self_ptl = NULL;
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_AMSH)) {
	amsh_ptl = (ptl_t *) (ep->ptl_base_data + ptl_sizes);
	ptl_sizes += psmi_ptl_amsh.sizeof_ptl();
    }
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) {
	ips_ptl = (ptl_t *) (ep->ptl_base_data + ptl_sizes);
	ptl_sizes += psmi_ptl_ips.sizeof_ptl();
    }
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_SELF)) {
	self_ptl = (ptl_t *) (ep->ptl_base_data + ptl_sizes);
	ptl_sizes += psmi_ptl_self.sizeof_ptl();
    }

    if ((err = psmi_ep_open_device(ep, &opts, unique_job_key, 
			   &(ep->context), &ep->epid)))
	goto fail;

    /* Restore old cpuaffinity and unit settings.
     * TODO: PSM should really just implement its own affinity
     *       setting function */
    if (old_cpuaff != NULL) 
	setenv("IPATH_NO_CPUAFFINITY", old_cpuaff, 1);
    if (old_unit != NULL)
	setenv("IPATH_UNIT", old_unit, 1);

    psmi_assert_always(ep->epid != 0);
    ep->epaddr->epid = ep->epid;

    /* Set our new label as soon as we know what it is */
    strncpy(buf, psmi_gethostname(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    p = buf + strlen(buf);

    /* If our rank is set, use it. If not, use context.subcontext notation */
    if (((e = getenv("MPI_RANKID")) != NULL && *e) ||
	    ((e = getenv("PSC_MPI_RANK")) != NULL && *e))
	len = snprintf(p, sizeof buf - strlen(buf), ":%d.", atoi(e));
    else
	len = snprintf(p, sizeof buf - strlen(buf), ":%d.%d.", 
		(uint32_t) psm_epid_context(ep->epid),
		(uint32_t) psmi_epid_subcontext(ep->epid));
    *(p + len) = '\0';
    ep->context_mylabel = psmi_strdup(ep, buf);
    if (ep->context_mylabel == NULL) {
	err = PSM_NO_MEMORY;
	goto fail;
    }
    //ipath_set_mylabel(ep->context_mylabel);

    if ((err = psmi_epid_set_hostname(psm_epid_nid(ep->epid), buf, 0)))
	goto fail;

    /* 
     * Active Message initialization
     */
    if ((err = psmi_am_init_internal(ep)))
	goto fail;

    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_SELF)) {
	if ((err = psmi_ptl_self.init(ep, self_ptl, &ep->ptl_self)))
	    goto fail;
    }
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) {
	if ((err = psmi_ptl_ips.init(ep, ips_ptl, &ep->ptl_ips)))
	    goto fail;
    }
    /* If we're shm-only, this device is enabled above */
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_AMSH)) {
	if ((err = psmi_ptl_amsh.init(ep, amsh_ptl, &ep->ptl_amsh)))
	    goto fail;
    }
    else {
	/* We may have pre-attached as part of getting our rank for enabling
	 * shared contexts.  */ 
	psmi_shm_detach(ep);
    }

    /*
     * Keep only IPS since only IPS support multi-rail, other devices
     * are only setup once. IPS device can come to this function again.
     */
    for (i = 0; i < PTL_MAX_INIT; i++) {
	if (devid_enabled[i] != PTL_DEVID_IPS) {
	    devid_enabled[i] = -1;
	}
    }

    *epido    = ep->epid;
    *epo     = ep;

    return PSM_OK;

fail:
    if (ep != NULL) {
	if (ep->context.fd != -1) close(ep->context.fd);
	psmi_free(ep);
    }
    if (epaddr != NULL)
	psmi_free(epaddr);
    return err;
}

psm_error_t
__psm_ep_open(psm_uuid_t const unique_job_key, struct psm_ep_open_opts const *opts_i,
	    psm_ep_t *epo, psm_epid_t *epido)
{
    psm_error_t err;
    psm_mq_t mq;
    psm_epid_t epid;
    psm_ep_t ep, tmp;
    uint32_t units[IPATH_MAX_UNIT];
    uint16_t ports[IPATH_MAX_UNIT];
    int i, num_rails = 0;
    char *uname = "IPATH_UNIT";
    char *pname = "IPATH_PORT";
    char uvalue[4], pvalue[4];
    int devid_enabled[PTL_MAX_INIT];
    union psmi_envvar_val devs;

    PSMI_ERR_UNLESS_INITIALIZED(NULL);

    PSMI_PLOCK();

    /* Matched Queue initialization.  We do this early because we have to
     * make sure ep->mq exists and is valid before calling ips_do_work.
     */
    err = psmi_mq_malloc(&mq);
    if (err != PSM_OK) goto fail;

    /* See which ptl devices we want to use for this ep to be opened */
    psmi_getenv("PSM_DEVICES",
		"Ordered list of PSM-level devices",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_STR,
		(union psmi_envvar_val) PSMI_DEVICES_DEFAULT,
		&devs);

    if ((err = psmi_parse_devices(devid_enabled, devs.e_str)))
	goto fail;

    if (psmi_device_is_enabled(devid_enabled, PTL_DEVID_IPS)) {
	err = psmi_ep_multirail(&num_rails, units, ports);
	if (err != PSM_OK) goto fail;

	/* If multi-rail is used, set the first ep unit/port */
	if (num_rails > 0) {
	    snprintf(uvalue, 4, "%d", units[0]);
	    snprintf(pvalue, 4, "%d", ports[0]);
	    setenv(uname, uvalue, 1);
	    setenv(pname, pvalue, 1);
	}
    }

    err = __psm_ep_open_internal(unique_job_key,
		devid_enabled, opts_i, mq, &ep, &epid);
    if (err != PSM_OK) goto fail;

    if (psmi_opened_endpoint == NULL) {
	psmi_opened_endpoint = ep;
    } else {
	tmp = psmi_opened_endpoint;
	while (tmp->user_ep_next) tmp = tmp->user_ep_next;
	tmp->user_ep_next = ep;
    }
    psmi_opened_endpoint_count++;
    ep->mctxt_prev = ep->mctxt_next = ep;
    ep->mctxt_master = ep;
    mq->ep = ep;

    *epo = ep;
    *epido = epid;

    if (psmi_device_is_enabled(devid_enabled, PTL_DEVID_IPS)) {
	for (i = 1; i < num_rails; i++) {
	    snprintf(uvalue, 4, "%d", units[i]);
	    snprintf(pvalue, 4, "%d", ports[i]);
	    setenv(uname, uvalue, 1);
	    setenv(pname, pvalue, 1);

	    /* Create slave EP */
	    err = __psm_ep_open_internal(unique_job_key,
			devid_enabled, opts_i, mq, &tmp, &epid);
	    if (err) goto fail;

	    /* Link slave EP after master EP. */
	    PSM_MCTXT_APPEND(ep, tmp);
	}
    }
	
    /* Once we've initialized all devices, we can update the MQ with its
     * default values */
    if (err == PSM_OK) err = psmi_mq_initialize_defaults(mq);

fail:
    PSMI_PUNLOCK();
    return err;
}
PSMI_API_DECL(psm_ep_open)

psm_error_t
__psm_ep_close(psm_ep_t ep, int mode, int64_t timeout_in)
{
    psm_error_t err = PSM_OK;
    uint64_t t_start = get_cycles();
    union psmi_envvar_val timeout_intval;
    psm_ep_t tmp, mep;

    PSMI_ERR_UNLESS_INITIALIZED(ep);
    psmi_assert_always(ep->mctxt_master == ep);

    PSMI_PLOCK();

    if (psmi_opened_endpoint == NULL) {
        err =  psmi_handle_error(NULL, PSM_EP_WAS_CLOSED,
		         "PSM Endpoint is closed or does not exist");
        return err;
    }

    tmp = psmi_opened_endpoint;
    while (tmp && tmp != ep) {
	tmp = tmp->user_ep_next;
    }
    if (!tmp) {
	err =  psmi_handle_error(NULL, PSM_EP_WAS_CLOSED,
		         "PSM Endpoint is closed or does not exist");
        return err;
    }

    psmi_getenv("PSM_CLOSE_TIMEOUT",
                "End-point close timeout over-ride.",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) 0,
                &timeout_intval);

    if (getenv("PSM_CLOSE_TIMEOUT")) {
        timeout_in = timeout_intval.e_uint * SEC_ULL;
    }
    else if (timeout_in > 0) {
        /* The timeout parameter provides the minimum timeout. A heuristic
	 * is used to scale up the timeout linearly with the number of 
	 * endpoints, and we allow one second per 100 endpoints. */
        timeout_in = max(timeout_in, (ep->connections * SEC_ULL) / 100);
    }

    if (timeout_in > 0 && timeout_in < PSMI_MIN_EP_CLOSE_TIMEOUT)
	timeout_in = PSMI_MIN_EP_CLOSE_TIMEOUT;

    /* Infinite and excessive close time-out are limited here to a max.
     * The "rationale" is that there is no point waiting around forever for
     * graceful termination. Normal (or forced) process termination should clean 
     * up the context state correctly even if termination is not graceful. */
    if (timeout_in <= 0 || timeout_in < PSMI_MAX_EP_CLOSE_TIMEOUT)
	timeout_in = PSMI_MAX_EP_CLOSE_TIMEOUT;
    _IPATH_PRDBG("Closing endpoint %p with force=%s and to=%.2f seconds and "
                 "%d connections\n",
		 ep, mode == PSM_EP_CLOSE_FORCE ? "YES" : "NO", 
		 (double) timeout_in / 1e9, (int) ep->connections);

    /* XXX We currently cheat in the sense that we leave each PTL the allowed
     * timeout.  There's no good way to do this until we change the PTL
     * interface to allow asynchronous finalization
     */
    mep = ep;
    tmp = ep->mctxt_prev;
    do {
	ep = tmp;
	tmp = ep->mctxt_prev;
	PSM_MCTXT_REMOVE(ep);
	if (psmi_ep_device_is_enabled(ep, PTL_DEVID_AMSH)) 
	    err = psmi_ptl_amsh.fini(ep->ptl_amsh.ptl, mode, timeout_in);

	if ((err == PSM_OK || err == PSM_TIMEOUT) && 
	    psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) 
	    err = psmi_ptl_ips.fini(ep->ptl_ips.ptl, mode, timeout_in);

	/* If there's timeouts in the disconnect requests,
	 * still make sure that we still get to close the
	 *endpoint and mark it closed */
	if (psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS))
	    psmi_context_close(&ep->context);

	psmi_free(ep->epaddr);
	psmi_free(ep->context_mylabel);
	/*
	 * Before freeing the master ep itself,
	 * remove it from the global linklist.
	 * We do it here to let atexit handler in ptl_am directory
	 * to search the global linklist and free the shared memory file.
	 */
	if (ep == mep) {
	    if (psmi_opened_endpoint == ep) {
		psmi_opened_endpoint = ep->user_ep_next;
	    } else {
		tmp = psmi_opened_endpoint;
		while (tmp->user_ep_next != ep) {
		    tmp = tmp->user_ep_next;
		}
	        tmp->user_ep_next = ep->user_ep_next;
	    }
	    psmi_opened_endpoint_count--;
	}
	psmi_free(ep);

    } while ((err == PSM_OK || err == PSM_TIMEOUT) && tmp != ep);

    PSMI_PUNLOCK();

    _IPATH_PRDBG("Closed endpoint in %.3f secs\n",
	    (double) cycles_to_nanosecs(get_cycles() - t_start) / SEC_ULL);
    return err;
}
PSMI_API_DECL(psm_ep_close)

static
psm_error_t 
psmi_ep_open_device(const psm_ep_t ep, 
		    const struct psm_ep_open_opts *opts,
		    const psm_uuid_t unique_job_key,
		    struct psmi_context *context,
		    psm_epid_t *epid)
{
    psm_error_t err = PSM_OK;

    /* Skip affinity.  No affinity if:
     * 1. User explicitly sets no-affinity=YES in environment.
     * 2. User doesn't set affinity in environment and PSM is opened with
     *    option affinity skip.
     */
    if (psmi_ep_device_is_enabled(ep, PTL_DEVID_IPS)) {
	uint32_t lid;
	
	ep->out_sl = opts->outsl;
	
	if ((err = psmi_context_open(ep, opts->unit, opts->port, unique_job_key,
				     opts->timeout, context)) != PSM_OK)
	    goto fail;

	_IPATH_DBG("[%d]use unit %d port %d\n", getpid(), 
	    context->base_info.spi_unit, context->base_info.spi_port);

	if ((lid = ipath_get_port_lid(context->base_info.spi_unit,
	    context->base_info.spi_port)) == -1) {
	    err = psmi_handle_error(NULL, 
		PSM_EP_DEVICE_FAILURE, 
		"Can't get InfiniBand LID in psm_ep_open: is SMA running?");
	    goto fail;
	}

	if (context->base_info.spi_sw_version >= (1 << 16 | 5)) {
	    uint32_t rcvthread_flags;
	    union psmi_envvar_val env_rcvthread;
	    static int norcvthread = 0; /* only for first rail */

	    /* See if we want to activate support for receive thread */
	    psmi_getenv("PSM_RCVTHREAD", "Recv thread flags (0 disables thread)",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		    (union psmi_envvar_val)(norcvthread++?0:PSMI_RCVTHREAD_FLAGS),
		    &env_rcvthread); 
	    rcvthread_flags = env_rcvthread.e_uint;

	    /* If enabled, use the pollurg capability to implement a receive
	     * interrupt thread that can handle urg packets */
	    if (rcvthread_flags) {
		context->runtime_flags |= PSMI_RUNTIME_RCVTHREAD;
#ifdef PSMI_PLOCK_IS_NOLOCK
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		    "#define PSMI_PLOCK_IS_NOLOCK not functional yet "
		    "with RCVTHREAD on");
#endif
	    }
	    context->rcvthread_flags = rcvthread_flags;

	}
	
	*epid = context->epid;
    }
    else {
	int rank, nranks;
	char *e;
	long nproc = sysconf(_SC_NPROCESSORS_ONLN);

	if (psmi_ep_device_is_enabled(ep, PTL_DEVID_AMSH)) {
	    /* In shm-only mode, we need to derive a valid epid based on our
	     * rank.  We try to get it from the environment if its available,
	     * or resort to preattaching to the shared memory segment and use
	     * our shared memory rank (shmidx) as the rank.
	     */
	    union psmi_envvar_val env_rankid;

	    if (psmi_getenv("MPI_LOCALRANKID", "Shared context rankid",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val) -1,
		    &env_rankid)) {
		if (psmi_getenv("PSC_MPI_NODE_RANK", "Shared context rankid",
			PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
			(union psmi_envvar_val) -1,
			&env_rankid)) {
		    if ((err = psmi_shm_attach(ep, &rank)))
			goto fail;
		}
		else
		    rank = env_rankid.e_int;
	    }
	    else
		rank = env_rankid.e_int;
	    nranks = (int) nproc;
	}
	else {
	    /* Self-only, meaning only 1 proc max */
	    rank = 0;
	    nranks = 1;
	}

	e = getenv("IPATH_NO_CPUAFFINITY");

	/* Now that we have a rank, set our affinity based on this rank */
	if (e == NULL || *e == '\0') 
	{
	    cpu_set_t cpuset;
	    CPU_ZERO(&cpuset);
	    /* First see if affinity is already set */
	    if (sched_getaffinity(0, sizeof cpuset, &cpuset)) {
		_IPATH_PRDBG("Couldn't get processory affinity, assuming "
			     "not set: %s\n", strerror(errno));
	    }
	    else {
		int i, num_set = 0;
		for (i = 0; i < CPU_SETSIZE; i++) {
		    if (CPU_ISSET(i, &cpuset))
			num_set++;
		}

		if (num_set > 0 && num_set < nproc)
		    _IPATH_PRDBG("CPU affinity already set, leaving as is\n");
		else if (rank >= nranks || rank < 0) 
		    _IPATH_PRDBG("Skipping affinity, rank is %d and there are "
				"only %d processors.\n", rank, nranks);
		else {
		    CPU_ZERO(&cpuset);
		    CPU_SET(rank, &cpuset);
		    if (sched_setaffinity(0,sizeof cpuset, &cpuset)) 
			_IPATH_PRDBG("Couldn't set affinity to processor %d: %s\n",
			    rank, strerror(errno));
		    else
			_IPATH_PRDBG("Set CPU affinity to %d out of %d processors\n",
			    rank, nranks);
		}
	    }
	}

	/* 
	 * We use a random lid 0xffff which doesn't really matter since we're
	 * closing ourselves to the outside world by explicitly disabling the
	 * ipath device).
	 */
	*epid = PSMI_EPID_PACK(0xffff, (rank>>2), rank);
    } 

fail:
    return err;
}

/* Get a list of PTLs we want to use.  The order is important, it affects
 * whether node-local processes use shm or ips */
static
psm_error_t
psmi_parse_devices(int devices[PTL_MAX_INIT], const char *devstring)
{
    char *devstr = NULL; 
    char *b_new, *e, *ee, *b;
    psm_error_t err = PSM_OK;
    int len;
    int i = 0;

    psmi_assert_always(devstring != NULL);
    len = strlen(devstring)+1;

    for (i = 0; i < PTL_MAX_INIT; i++)
	devices[i] = -1;

    devstr = (char *) psmi_calloc(PSMI_EP_NONE, UNDEFINED, 2, len);
    if (devstr == NULL)
	goto fail;

    b_new = (char *) devstr;
    e = b_new + len;
    strncpy(e, devstring, len-1);
    e[len-1] = '\0';
    ee = e + len;
    i = 0;
    while (e < ee && *e && i < PTL_MAX_INIT) {
	while (*e && !isalpha(*e))
	    e++;
	b = e;
	while (*e && isalpha(*e))
	    e++;
	*e = '\0';
	if (*b) {
	    if (!strcasecmp(b, "self")) {
		devices[i++] = PTL_DEVID_SELF;
		b_new = strcpy(b_new, "self,");
		b_new += 5;
	    } else if (!strcasecmp(b, "amsh")) {
		devices[i++] = PTL_DEVID_AMSH;
		strcpy(b_new, "amsh,");
		b_new += 5;
	    } else if (!strcasecmp(b, "ips")) {
		devices[i++] = PTL_DEVID_IPS;
		strcpy(b_new, "ips,");
		b_new += 4;
	    /* If shm or shmem is set, bind to amsh */
	    } else if (!strcasecmp(b, "shm") || !strcasecmp(b, "shmem")) {
		devices[i++] = PTL_DEVID_AMSH;
		strcpy(b_new, "amsh,");
		b_new += 5;
	    /* If shm or shmem is set, bind to ipath */
	    } else if (!strcasecmp(b, "ipath") || !(strcasecmp(b, "infinipath"))) {
		devices[i++] = PTL_DEVID_IPS;
		strcpy(b_new, "ips,");
		b_new += 4;
	    } else {
		err = psmi_handle_error(NULL, PSM_PARAM_ERR,
		    "%s set in environment variable PSM_PTL_DEVICES=\"%s\" "
		    "is not one of the recognized PTL devices (%s)", 
		    b, devstring, PSMI_DEVICES_DEFAULT);
		goto fail;
	    }
	    e++;
	}
    }
    if (b_new != devstr)  /* we parsed something, remove trailing comma */
	b_new[strlen(b_new) - 1] = '\0';

    _IPATH_PRDBG("PSM Device allocation order: %s\n", devstr);
fail:
    if (devstr != NULL)
	psmi_free(devstr);
    return err;

}

static
int
psmi_device_is_enabled(const int devid_enabled[PTL_MAX_INIT], int devid)
{
    int i;
    for (i = 0; i < PTL_MAX_INIT; i++) 
	if (devid_enabled[i] == devid)
	    return 1;
    return 0;
}

int
psmi_ep_device_is_enabled(const psm_ep_t ep, int devid)
{
    return psmi_device_is_enabled(ep->devid_enabled, devid);
}

