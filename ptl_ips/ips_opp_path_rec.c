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

#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"
#include <dlfcn.h>

#define DF_OPP_LIBRARY "libofedplus.so"
#define DATA_VFABRIC_OFFSET 8

/* SLID and DLID are in network byte order */
static psm_error_t
ips_opp_get_path_rec(ips_path_type_t type, struct ips_proto *proto,
		     uint16_t slid, uint16_t dlid, uint16_t desthca_type,
		     ips_path_rec_t **path_rec)
{
  psm_error_t err = PSM_OK;
  ibta_path_rec_t query;
  ips_opp_path_rec_t *opp_path_rec;
  int opp_err;
  ENTRY elid, *epath = NULL;
  char eplid[128];
  uint64_t timeout_ack_ms;

  /* Query path record query cache first */
  bzero(&query, sizeof(query));
  bzero(eplid, sizeof(eplid));
  
  /* Bulk service ID is control service id + 1 */
  switch(type) {
  case IPS_PATH_NORMAL_PRIORITY:
  case IPS_PATH_LOW_PRIORITY:
    query.service_id = 
	__cpu_to_be64(proto->ep->service_id + DATA_VFABRIC_OFFSET);
    break;
  case IPS_PATH_HIGH_PRIORITY:
  default:
    query.service_id = __cpu_to_be64(proto->ep->service_id);
  }

  query.slid = slid;
  query.dlid = dlid;

  snprintf(eplid, sizeof(eplid), "%s_%x_%x", (type == IPS_PATH_HIGH_PRIORITY) ? "HIGH" : "LOW", query.slid,query.dlid);
  elid.key = eplid;
  hsearch_r(elid, FIND, &epath, &proto->ips_path_rec_hash);

  if (!epath) { /* Unable to find path record in cache */
    elid.key = psmi_calloc(proto->ep, UNDEFINED, 1, strlen(eplid) + 1);
    opp_path_rec = (ips_opp_path_rec_t*) 
      psmi_calloc(proto->ep, UNDEFINED, 1, sizeof(ips_opp_path_rec_t));
    if (!elid.key || !opp_path_rec) {
	if (elid.key) psmi_free(elid.key);
	if (opp_path_rec) psmi_free(opp_path_rec);
	err = PSM_NO_MEMORY;
	goto fail;
    }
    
    /* Get path record between local LID and remote */
    opp_err = proto->opp_fn.op_path_get_path_by_rec(proto->opp_ctxt, &query,
					     &opp_path_rec->opp_response);
    if (opp_err) {
      psmi_free(opp_path_rec);
      psmi_free(elid.key);
      err = PSM_EPID_PATH_RESOLUTION;
      goto fail;
    }

    /* Create path record */
    opp_path_rec->ips.epr_slid = opp_path_rec->opp_response.slid;
    opp_path_rec->ips.epr_dlid = opp_path_rec->opp_response.dlid;
    opp_path_rec->ips.epr_mtu = 
      min(ibta_mtu_enum_to_int(opp_path_rec->opp_response.mtu & 0x3f), 
	  proto->epinfo.ep_mtu);
    opp_path_rec->ips.epr_pkey = ntohs(opp_path_rec->opp_response.pkey);
    opp_path_rec->ips.epr_sl = ntohs(opp_path_rec->opp_response.qos_class_sl);
    opp_path_rec->ips.epr_static_rate = opp_path_rec->opp_response.rate & 0x3f;
    opp_path_rec->ips.epr_static_ipd = 
      proto->ips_ipd_delay[opp_path_rec->ips.epr_static_rate];
    
    /* Setup CCA parameters for path */
    if (opp_path_rec->ips.epr_sl > 15) {
        psmi_free(opp_path_rec);
        psmi_free(elid.key);
	err = PSM_INTERNAL_ERR;
	goto fail;
    }
    if (!(proto->ccti_ctrlmap&(1<<opp_path_rec->ips.epr_sl))) {
	_IPATH_CCADBG("No CCA for sl %d, disable CCA\n",
		opp_path_rec->ips.epr_sl);
	proto->flags &= ~IPS_PROTO_FLAG_CCA;
    }
    opp_path_rec->ips.proto = proto;
    opp_path_rec->ips.epr_ccti_min = proto->cace[opp_path_rec->ips.epr_sl].ccti_min;
    opp_path_rec->ips.epr_ccti = opp_path_rec->ips.epr_ccti_min;
    psmi_timer_entry_init(&opp_path_rec->ips.epr_timer_cca,
			  ips_cca_timer_callback, &opp_path_rec->ips);
    
    /* Determine active IPD for path. Is max of static rate and CCT table */
    if ((opp_path_rec->ips.epr_static_ipd) && 
	((opp_path_rec->ips.epr_static_ipd + 1) > 
	 (proto->cct[opp_path_rec->ips.epr_ccti] & CCA_IPD_MASK))) {
      opp_path_rec->ips.epr_active_ipd = opp_path_rec->ips.epr_static_ipd + 1;
      opp_path_rec->ips.epr_cca_divisor = 0; /*Static rate has no CCA divisor */
    }
    else {
      /* Pick it from the CCT table */
      opp_path_rec->ips.epr_active_ipd = 
	proto->cct[opp_path_rec->ips.epr_ccti] & CCA_IPD_MASK;
      opp_path_rec->ips.epr_cca_divisor = 
	proto->cct[opp_path_rec->ips.epr_ccti] >> CCA_DIVISOR_SHIFT;
    }
        
    /* Compute max timeout based on pkt life time for path */
    timeout_ack_ms = ((4096UL * (1UL << (opp_path_rec->opp_response.pkt_life & 0x3f)))/ 1000000UL);
    opp_path_rec->ips.epr_timeout_ack = 
      ms_2_cycles(IPS_PROTO_ERRCHK_MS_MIN_DEFAULT);
    opp_path_rec->ips.epr_timeout_ack_max = 
      ms_2_cycles(IPS_PROTO_ERRCHK_MS_MIN_DEFAULT + timeout_ack_ms);
    opp_path_rec->ips.epr_timeout_ack_factor = IPS_PROTO_ERRCHK_FACTOR_DEFAULT;

    /* Add path record into cache */
    strcpy(elid.key, eplid);
    elid.data = (void*) opp_path_rec;
    hsearch_r(elid, ENTER, &epath, &proto->ips_path_rec_hash);
  }
  else /* Path record found in cache */
    opp_path_rec = (ips_opp_path_rec_t*) epath->data;
  
  /* Dump path record stats */
  _IPATH_PRDBG("Path Record ServiceID: %"PRIx64" %x -----> %x\n", (uint64_t) __be64_to_cpu(query.service_id), __be16_to_cpu(slid), __be16_to_cpu(dlid));
  _IPATH_PRDBG("MTU: %x, %x\n", (opp_path_rec->opp_response.mtu & 0x3f), opp_path_rec->ips.epr_mtu);
  _IPATH_PRDBG("PKEY: 0x%04x\n", ntohs(opp_path_rec->opp_response.pkey));
  _IPATH_PRDBG("SL: 0x%04x\n", ntohs(opp_path_rec->opp_response.qos_class_sl));
  _IPATH_PRDBG("Rate: %x, IPD: %x\n", (opp_path_rec->opp_response.rate & 0x3f), opp_path_rec->ips.epr_static_ipd);
  _IPATH_PRDBG("Timeout Init.: 0x%"PRIx64" Max: 0x%"PRIx64"\n", opp_path_rec->ips.epr_timeout_ack, opp_path_rec->ips.epr_timeout_ack_max);

  /* Return the IPS path record */
  *path_rec = &opp_path_rec->ips;
  
 fail:  
  return err;
}

static psm_error_t 
ips_opp_path_rec(struct ips_proto *proto,
		 uint16_t slid, uint16_t dlid, uint16_t desthca_type,
		 unsigned long timeout, 
		 ips_epaddr_t *ipsaddr)
{
  psm_error_t err = PSM_OK;
  uint16_t pidx, cpath, num_path = (1 << proto->epinfo.ep_lmc);
  ips_path_type_t path_type = IPS_PATH_NORMAL_PRIORITY;
  ips_path_rec_t *path;
  uint16_t path_slid, path_dlid;
  psmi_context_t *context = &proto->ep->context;
  
  /*
   * High Priority Path
   * ------------------
   * 
   * Uses the "base" Service ID. For now there exists only 1 high priority
   * path between nodes even for non zero LMC fabrics. 
   * TODO: Investigate if there are any benefits for using multiple high 
   * priority paths. Initial empirical data shows that this leads to worse
   * performance as the bulk data can induce HOL blocking.
   * Currently the normal and low priority paths are same but at some point
   * we can create separate vFabrics to further distinguish/isolate those 
   * traffic flows.
   *
   * Normal/Low Priority Paths
   * -------------------------
   * 
   * Currently these paths are the same i.e. they are queried for the same
   * Service ID/vFabric which is the Base Service ID for High Priority + 1.
   * 
   * Use case Scenarios
   * ------------------
   *
   * Since with vFabrics we have the capability to define different QoS 
   * parameters per vFabric it is envisioned that the IPS_PATH_HIGH_PRIORITY is
   * setup in a separate vFabric for high priority traffic. The NORMAL paths
   * are setup in a separate vFabric optimized for high bandwidth. This allows
   * us to potentially have control traffic (RTS, CTS etc.) not be bottlenecked
   * by bulk transfer data. All control messages (ACKs,NAKs, TID_GRANT etc.)
   * also use the high priority control vFabric.
   *
   * NOTE: In order to distinguish between the different vFabrics the user
   * specifies the service ID to use via mpirun (or environment variable). 
   * This is the service ID for the high priority control traffic. The bulk
   * data vFabric is identified by service ID + 1. So for each MPI application
   * one should specify two service IDs for the high priority and bulk data.
   * Both these service IDs can be placed in the same vFabric which can be
   * configured for high priority or bandwidth traffic giving us the default
   * behavior upto Infinipath 2.5 release.
   *
   * NOTE: All of the above would have really helped if the S20 silicon could
   * correctly support IBTA QoS features. Due to S20 design we can only have
   * high priority VLarb table (low priority VLarb table results in round
   * robin arbitration ignoring the weights!). But if this is fixed in a 
   * subsequent chip respin then this may potentially help our scalability
   * on large fabrics.
   *
   * Mesh/Torus and DOR routed networks
   * ----------------------------------
   * 
   * In a mesh/torus fabric we always have a non zero LMC (atleast 1 can be 
   * more). We would like to take advantage of dispersive routing on these
   * fabrics as well to obtain better "worst case/congested" bandwidth. For
   * these networks currently the base LIDs are used for UPDN routing which 
   * is suboptimal on these networks. Higher order LIDs (+1 .. +N) use DOR
   * routing (Dimension Ordered Routing) to avoid deadlocks and provide
   * higher performance. If a fabric is disrupted then only the base UPDN
   * routing is available. PSM should continue to operate in this environment
   * albeit with degraded performance. In disrupted fabric the OPP path
   * record queries may fail for some DOR routed LIDs i.e. no path exists
   * PSM should hence ignore path record failures as they indicate a disrupted
   * fabric and only use valid paths that are returned from the replica. This
   * will degenerate to only using the UPDN paths on disrupted fabrics and DOR
   * routes only for fully configured fabrics. Note: For a clean fabric the
   * base LIDs that are configured for UPDN route will not exist in the replica
   * as DOR routes are preferred. Hence we will only dispersively route across
   * the DOR routes only using the UPDN route for disrupted fabrics.
   *
   * AS LONG AS ONE PATH EXISTS (for each of the priorities) COMMUNICATION CAN
   * TAKE PLACE.
   */
  
  /* If base lids are only used then reset num_path to 1 */
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_BASE)
    num_path = 1;
  
  ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY] = 
  ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY] =
  ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY] = 0;

  /* For now there is always only one high priority path between nodes. */
  for (pidx = 0,cpath = 0; pidx < num_path && cpath == 0; pidx++) {
    path_slid = __cpu_to_be16(__be16_to_cpu(slid) + pidx);
    path_dlid = __cpu_to_be16(__be16_to_cpu(dlid) + pidx);

    err = ips_opp_get_path_rec(IPS_PATH_HIGH_PRIORITY, proto, 
			       path_slid, path_dlid, 
			       desthca_type, &path);
    
    if (err == PSM_OK) {  /* Valid high priority path found */      
      /* Resolved high priority path successfully */
      ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY]++;
      ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][cpath] = path;
      
      /* Increment current path index */
      cpath++;
    }
  }
  
  /* Make sure we have atleast 1 high priority path */
  if (ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY] == 0) {
    err = psmi_handle_error(NULL, PSM_EPID_PATH_RESOLUTION,
			    "OFEF Plus path lookup failed. Unable to resolve high priority network path for LID 0x%x <---> 0x%x. Is the SM running or service ID %"PRIx64" defined?", ntohs(slid), ntohs(dlid), (uint64_t) proto->ep->service_id);
    goto fail;
  }
  
  /* Next setup the bulk paths. If the subnet administrator has misconfigured
   * or rather not configured two separate service IDs we place the bulk
   * paths in the same vFabric as the control paths.
   */
  for (pidx = 0,cpath = 0; pidx < num_path; pidx++) {
    path_slid = __cpu_to_be16(__be16_to_cpu(slid) + pidx);
    path_dlid = __cpu_to_be16(__be16_to_cpu(dlid) + pidx);
    
  retry_path_res:
    err = ips_opp_get_path_rec(path_type, proto, 
			       path_slid, path_dlid, desthca_type,
			       &path);
    if (err != PSM_OK) {
      if (path_type == IPS_PATH_NORMAL_PRIORITY) {
	/* Subnet may only be configured for one service ID/vFabric. Default
	 * to using the control vFabric/service ID for bulk data as well.
	 */
	path_type = IPS_PATH_HIGH_PRIORITY;
	goto retry_path_res;
      }
      
      /* Unable to resolve path for <path_slid, path_dline>. This is possible
       * for disrupted fabrics using DOR routing so continue to acquire paths
       */
      err = PSM_OK;
      continue;
    }
        
    /* Valid path. For now both normal and low priority paths are the same */
    ipsaddr->epr.epr_path[IPS_PATH_NORMAL_PRIORITY][cpath] = path;
    ipsaddr->epr.epr_path[IPS_PATH_LOW_PRIORITY][cpath] = path;
    ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY]++;
    ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY]++;
    cpath++;
  }

  /* Make sure we have atleast have a single bulk data transfer path */
  if ((ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY] == 0) ||
      (ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY] == 0)) {
    err = psmi_handle_error(NULL, PSM_EPID_PATH_RESOLUTION,
			    "OFEF Plus path lookup failed. Unable to resolve normal/low priority network path for LID 0x%x <---> 0x%x. Is the SM running or service ID %"PRIx64" defined?", ntohs(slid), ntohs(dlid), (uint64_t) proto->ep->service_id);
    goto fail;
  }
  
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE) {
    ipsaddr->epr.epr_hpp_index = 0; 
    ipsaddr->epr.epr_next_path[IPS_PATH_NORMAL_PRIORITY] = 
      context->base_info.spi_context % ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY];
    ipsaddr->epr.epr_next_path[IPS_PATH_LOW_PRIORITY] = 
      context->base_info.spi_context % ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY];
  }
  else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_DST)
    ipsaddr->epr.epr_hpp_index = 
      ipsaddr->epr.epr_context  % ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY];
  else if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_SRC)
    ipsaddr->epr.epr_hpp_index = 
      context->base_info.spi_context % ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY];
  else  /* Base LID  */
    ipsaddr->epr.epr_hpp_index = 0;
  
 fail:
  if (err != PSM_OK) 
    _IPATH_PRDBG("Unable to get path record for LID 0x%x <---> DLID 0x%x.\n", slid, dlid);
  return err;
}

static psm_error_t ips_opp_fini(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;
  
  if (proto->opp_lib)
    dlclose(proto->opp_lib);
  
  return err;  
}

psm_error_t ips_opp_init(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;
  struct ipath_base_info *base_info = &proto->ep->context.base_info;
  char hcaName[32];

  proto->opp_lib = dlopen(DF_OPP_LIBRARY, RTLD_NOW);
  if (!proto->opp_lib) {
    char *err = dlerror();
    _IPATH_ERROR("Unable to open OFED Plus Plus library %s. Error: %s\n", DF_OPP_LIBRARY,
		err ? err : "no dlerror()");
    goto fail;
  }
  
  /* Resolve symbols that we require within opp library */
  proto->opp_fn.op_path_find_hca = dlsym(proto->opp_lib, "op_path_find_hca");
  proto->opp_fn.op_path_open = dlsym(proto->opp_lib, "op_path_open");
  proto->opp_fn.op_path_close = dlsym(proto->opp_lib, "op_path_close");
  proto->opp_fn. op_path_get_path_by_rec = dlsym(proto->opp_lib, "op_path_get_path_by_rec");
  
  /* If we can't resovle any symbol then fail to load opp module */  
  if (!proto->opp_fn.op_path_find_hca || !proto->opp_fn.op_path_open ||
  !proto->opp_fn.op_path_close || !proto->opp_fn.op_path_get_path_by_rec) {
    _IPATH_PRDBG("Unable to resolve symbols in OPP library. Unloading.\n");
    goto fail;
  }
  
    /* If PSM_IDENTIFY is set display the OPP library location being used. */
  if (getenv("PSM_IDENTIFY")) {
    Dl_info info_opp;
    _IPATH_INFO("PSM path record queries using OFED Plus Plus (%s) from %s\n", 
		DF_OPP_LIBRARY,
		dladdr(proto->opp_fn.op_path_open, &info_opp) ? info_opp.dli_fname : 
		"Unknown/unsupported version of OPP library found!");
  }

  /* Obtain handle to hca (requires verbs on node) */
  snprintf(hcaName, sizeof(hcaName), "qib%d", base_info->spi_unit);
  proto->hndl = proto->opp_fn.op_path_find_hca(hcaName, &proto->device);
  if (!proto->hndl) {
    _IPATH_ERROR("OPP: Unable to find HCA %s. Disabling OPP interface for path record queries.\n", hcaName);
    goto fail;
  }
  
  /* Get OPP context */
  proto->opp_ctxt = proto->opp_fn.op_path_open(proto->device, base_info->spi_port);
  if (!proto->opp_ctxt) {
    _IPATH_ERROR("OPP: Unable to optain OPP context. Disabling OPP interface for path record queries.\n");
    goto fail;
  }
  
  /* OPP initialized successfully */
  proto->ibta.get_path_rec = ips_opp_path_rec;
  proto->ibta.fini = ips_opp_fini;
  proto->flags |= IPS_PROTO_FLAG_QUERY_PATH_REC;

  return err;
  
 fail:
  _IPATH_ERROR("Make sure SM is running...\n");
  _IPATH_ERROR("Make sure service dist_sa is running...\n");
  _IPATH_ERROR("to start dist_sa: service dist_sa start\n");
  _IPATH_ERROR("or enable it at boot time: iba_config -E dist_sa\n\n");

  err = psmi_handle_error(NULL, PSM_EPID_PATH_RESOLUTION,
			  "Unable to initialize OFED Plus library successfully.\n");

  if (proto->opp_lib)
    dlclose(proto->opp_lib);
  
  return err;
}

