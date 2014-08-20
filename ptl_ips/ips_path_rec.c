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
#include "psm_user.h"
#include "ipserror.h"
#include "ips_proto.h"
#include "ips_proto_internal.h"

static void
ips_gen_ipd_table(struct ips_proto *proto)
{
  /* Based on our current link rate setup the IPD table */
  switch(proto->epinfo.ep_link_rate) {
  case IBTA_RATE_10_GBPS:
    proto->ips_ipd_delay[IBTA_RATE_10_GBPS] = 0;
    proto->ips_ipd_delay[IBTA_RATE_5_GBPS] = 1;
    proto->ips_ipd_delay[IBTA_RATE_2_5_GBPS] = 3;
    break;
  case IBTA_RATE_20_GBPS:
    proto->ips_ipd_delay[IBTA_RATE_20_GBPS] = 0;
    proto->ips_ipd_delay[IBTA_RATE_10_GBPS] = 1;
    proto->ips_ipd_delay[IBTA_RATE_5_GBPS] = 3;
    proto->ips_ipd_delay[IBTA_RATE_2_5_GBPS] = 7;
    break;
  case IBTA_RATE_40_GBPS:
  default:
    proto->ips_ipd_delay[IBTA_RATE_40_GBPS] = 0;
    proto->ips_ipd_delay[IBTA_RATE_30_GBPS] = 1;
    proto->ips_ipd_delay[IBTA_RATE_20_GBPS] = 1;
    proto->ips_ipd_delay[IBTA_RATE_10_GBPS] = 3;
    proto->ips_ipd_delay[IBTA_RATE_5_GBPS] = 7;
    proto->ips_ipd_delay[IBTA_RATE_2_5_GBPS] = 15;
    break;
  }
}

static psm_error_t
ips_gen_cct_table(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;
  uint32_t cca_divisor, ipdidx, ipdval = 1;
  uint16_t *cct_table;

  /* The CCT table is static currently. If it's already created then return */
  if (proto->cct)
    goto fail;

  /* Allocate the CCT table */
  cct_table = psmi_calloc(proto->ep, UNDEFINED,
		proto->ccti_size, sizeof(uint16_t));
  if (!cct_table) {
    err = PSM_NO_MEMORY;
    goto fail;
  }

  /* The first table entry is always 0 i.e. no IPD delay */
  cct_table[0] = 0;
  
  /* Generate the remaining CCT table entries */
  for (ipdidx = 1; ipdidx < proto->ccti_size; ipdidx += 4,ipdval++)
    for (cca_divisor = 0; cca_divisor < 4; cca_divisor++) {
      if ((ipdidx+cca_divisor) == proto->ccti_size) break;
      cct_table[ipdidx+cca_divisor] = 
	(((cca_divisor ^ 0x3) << CCA_DIVISOR_SHIFT) | (ipdval & 0x3FFF));
      _IPATH_VDBG("CCT[%d] = %x. Divisor: %x, IPD: %x\n", ipdidx+cca_divisor, cct_table[ipdidx+cca_divisor], (cct_table[ipdidx+cca_divisor] >> CCA_DIVISOR_SHIFT), cct_table[ipdidx+cca_divisor] & CCA_IPD_MASK);
    }

  /* On link up/down CCT is re-generated. If CCT table is previously created
   * free it 
   */
  if (proto->cct) {
    psmi_free(proto->cct);
    proto->cct = NULL;
  }
  
  /* Update to the new CCT table */
  proto->cct = cct_table;
  
 fail:
  return err;
}

static ibta_rate
ips_default_hca_rate(uint16_t hca_type)
{
  ibta_rate rate = IBTA_RATE_40_GBPS;
  
  switch(hca_type){
  case PSMI_HCA_TYPE_QLE73XX:
    rate = IBTA_RATE_40_GBPS;
    break;
  case PSMI_HCA_TYPE_QLE72XX:
    rate = IBTA_RATE_20_GBPS;
    break;
  case PSMI_HCA_TYPE_QLE71XX:
    rate = IBTA_RATE_10_GBPS;
    break;
  }
  
  return rate;
}

static ibta_rate
ips_rate_to_enum(int link_rate) 
{
  ibta_rate rate;
  
  switch(link_rate) {
  case 40:
    rate = IBTA_RATE_40_GBPS;
    break;
  case 20:
    rate = IBTA_RATE_20_GBPS;
    break;
  case 10:
    rate = IBTA_RATE_10_GBPS;
    break;
  case 5:
    rate = IBTA_RATE_5_GBPS;
    break;
  case 2:
    rate = IBTA_RATE_2_5_GBPS;
    break;
  default:
    rate = IBTA_RATE_PORT_CURRENT;
  }
  
  return rate;
}

static psm_error_t
ips_none_get_path_rec(struct ips_proto *proto,
		  uint16_t slid, uint16_t dlid, uint16_t desthca_type,
		  unsigned long timeout, ips_path_rec_t **prec)
{
  psm_error_t err = PSM_OK;
  ENTRY elid, *epath = NULL;
  char eplid[128];
  ips_path_rec_t *path_rec;
  
  /* Query the path record cache */
  snprintf(eplid, sizeof(eplid), "%x_%x", slid, dlid);
  elid.key = eplid;
  hsearch_r(elid, FIND, &epath, &proto->ips_path_rec_hash);
  
  if (!epath) {
    elid.key = psmi_calloc(proto->ep, UNDEFINED, 1, strlen(eplid) + 1);
    path_rec = (ips_path_rec_t*) 
      psmi_calloc(proto->ep, UNDEFINED, 1, sizeof(ips_path_rec_t));
    if (!elid.key || !path_rec) {
	if (elid.key) psmi_free(elid.key);
	if (path_rec) psmi_free(path_rec);
	return PSM_NO_MEMORY;
    }
    
    /* Create path record */
    path_rec->epr_slid = slid;
    path_rec->epr_dlid = dlid;
    path_rec->epr_mtu  = proto->epinfo.ep_mtu;
    path_rec->epr_pkey = proto->epinfo.ep_pkey;
    path_rec->epr_sl   = proto->epinfo.ep_sl;

    /* Determine the IPD based on our local link rate and default link rate for
     * remote hca type.
     */
    path_rec->epr_static_rate = 
      ips_default_hca_rate(desthca_type);  
    path_rec->epr_static_ipd = 
      proto->ips_ipd_delay[path_rec->epr_static_rate];

    /* Setup CCA parameters for path */
    if (path_rec->epr_sl > 15) {
	psmi_free(elid.key);
	psmi_free(path_rec);
	return PSM_INTERNAL_ERR;
    }
    if (!(proto->ccti_ctrlmap&(1<<path_rec->epr_sl))) {
	_IPATH_CCADBG("No CCA for sl %d, disable CCA\n", path_rec->epr_sl);
	proto->flags &= ~IPS_PROTO_FLAG_CCA;
    }
    path_rec->proto = proto;
    path_rec->epr_ccti_min = proto->cace[path_rec->epr_sl].ccti_min;
    path_rec->epr_ccti = path_rec->epr_ccti_min;
    psmi_timer_entry_init(&path_rec->epr_timer_cca,
			  ips_cca_timer_callback, path_rec);
    
    /* Determine active IPD for path. Is max of static rate and CCT table */
    if ((path_rec->epr_static_ipd) && 
	((path_rec->epr_static_ipd + 1) > 
	 (proto->cct[path_rec->epr_ccti] & CCA_IPD_MASK))) {
      path_rec->epr_active_ipd = path_rec->epr_static_ipd + 1;
      path_rec->epr_cca_divisor = 0;
    }
    else {
      /* Pick it from the CCT table */
      path_rec->epr_active_ipd = proto->cct[path_rec->epr_ccti] & CCA_IPD_MASK;
      path_rec->epr_cca_divisor = 
	proto->cct[path_rec->epr_ccti] >> CCA_DIVISOR_SHIFT;
    }
    
    /* Setup default errorcheck timeout. */
    path_rec->epr_timeout_ack = 
      proto->epinfo.ep_timeout_ack;
    path_rec->epr_timeout_ack_max = 
      proto->epinfo.ep_timeout_ack_max;
    path_rec->epr_timeout_ack_factor = 
      proto->epinfo.ep_timeout_ack_factor;
    
    /* Add path record into cache */
    strcpy(elid.key, eplid);
    elid.data = (void*) path_rec;
    hsearch_r(elid, ENTER, &epath, &proto->ips_path_rec_hash);
  }
  else
    path_rec = (ips_path_rec_t*) epath->data;

  /* Return IPS path record */
  *prec = path_rec;
  
  return err;
}

static psm_error_t 
ips_none_path_rec(struct ips_proto *proto,
		  uint16_t slid, uint16_t dlid, uint16_t desthca_type,
		  unsigned long timeout, 
		  ips_epaddr_t *ipsaddr)
{
  psm_error_t err = PSM_OK;
  uint16_t pidx, num_path = (1 << proto->epinfo.ep_lmc);
  uint16_t base_slid, base_dlid;
  psmi_context_t *context = &proto->ep->context;
  
  /* For the "none" path record resolution all paths are assumed to be of equal
   * priority however since we want to isolate all control traffic (acks, naks)
   * to a separate path for non zero LMC subnets the "first path" between a 
   * pair of endpoints is always the "higher" priority paths. The rest of the
   * paths are the normal (and low priority) paths.
   */
  
  /* If base lids are only used then reset num_path to 1 */
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_BASE)
    num_path = 1;
  
  if (num_path > 1) {
    /* One control path and (num_path - 1) norm and low priority paths */
    ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY] = 1;
    ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY] = num_path - 1;
    ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY] = num_path - 1;
  }
  else {
    /* LMC of 0. Use the same path for all priorities */
    ipsaddr->epr.epr_num_paths[IPS_PATH_HIGH_PRIORITY] = 1;
    ipsaddr->epr.epr_num_paths[IPS_PATH_NORMAL_PRIORITY] = 1;
    ipsaddr->epr.epr_num_paths[IPS_PATH_LOW_PRIORITY] = 1;
  }
    
  /* For "none" path record we just setup 2^lmc paths. To get better load
   * balance
   */
  for (pidx = 0; pidx < num_path; pidx++) {
    ips_path_rec_t *path;

    base_slid = __cpu_to_be16(__be16_to_cpu(slid) + pidx);
    base_dlid = __cpu_to_be16(__be16_to_cpu(dlid) + pidx);
    
    err = ips_none_get_path_rec(proto, base_slid, base_dlid, desthca_type,
				timeout, &path);
    if (err != PSM_OK)
      goto fail;
        
    if (num_path > 1) {
      if (pidx == 0) {
	/* First path is always the high priority path */
	ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0] = path;
      }
      else {
	ipsaddr->epr.epr_path[IPS_PATH_NORMAL_PRIORITY][pidx-1] = path;
	ipsaddr->epr.epr_path[IPS_PATH_LOW_PRIORITY][pidx-1] = path;
      }
    }
    else {
      ipsaddr->epr.epr_path[IPS_PATH_HIGH_PRIORITY][0] = path;
      ipsaddr->epr.epr_path[IPS_PATH_NORMAL_PRIORITY][0] = path;
      ipsaddr->epr.epr_path[IPS_PATH_LOW_PRIORITY][0] = path;
    }
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
    _IPATH_PRDBG("Unable to get path record for LID %x <---> DLID %x.\n", slid, dlid);
  return err;
}

static psm_error_t ips_none_path_rec_init(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;
  union psmi_envvar_val psm_set_hca_pkey;

  /* Obtain the SL and PKEY to use from the environment (IPATH_SL & PSM_KEY) */
  proto->epinfo.ep_sl = psmi_epid_sl(proto->ep->epid);
  proto->epinfo.ep_pkey    = (uint16_t) proto->ep->network_pkey;

  /*
   * Parse the err_chk settings from the environment.
   * <min_timeout>:<max_timeout>:<timeout_factor>
   */
  {
    union psmi_envvar_val env_to;
    char *errchk_to = PSM_TID_TIMEOUT_DEFAULT;
    int tvals[3] = {
      IPS_PROTO_ERRCHK_MS_MIN_DEFAULT,
      IPS_PROTO_ERRCHK_MS_MAX_DEFAULT,
      IPS_PROTO_ERRCHK_FACTOR_DEFAULT };
    
    if (!psmi_getenv("PSM_ERRCHK_TIMEOUT",
		     "Errchk timeouts in mS <min:max:factor>",
		     PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_STR,
		     (union psmi_envvar_val) errchk_to, &env_to))
      {
	/* Not using default values, parse what we can */
	errchk_to = env_to.e_str;
	psmi_parse_str_tuples(errchk_to, 3, tvals);
	/* Adjust for max smaller than min, things would break */
	if (tvals[1] < tvals[0]) 
	  tvals[1] = tvals[0];
      }
    proto->epinfo.ep_timeout_ack     = ms_2_cycles(tvals[0]);
    proto->epinfo.ep_timeout_ack_max = ms_2_cycles(tvals[1]);
    proto->epinfo.ep_timeout_ack_factor = tvals[2];
  }

  /* With no path records queries set pkey manually if PSM_SET_HCA_PKEY is
   * set.
   */
  psmi_getenv("PSM_SET_HCA_PKEY",
	      "Force write of PKey to HCA (default is disabled)",
	      PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_UINT_FLAGS,
	      (union psmi_envvar_val) 0, &psm_set_hca_pkey);
  
  if (psm_set_hca_pkey.e_uint) {
    if (ipath_set_pkey(proto->ep->context.ctrl,
		       (uint16_t) proto->ep->network_pkey) != 0) {
      err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
			      "Couldn't set device pkey %d: %s",
			      (int) proto->ep->network_pkey,
			      strerror(errno));
      goto fail;
    }
  }

  proto->ibta.get_path_rec = ips_none_path_rec;
  proto->ibta.fini = NULL;

 fail:
  return err;
}

/* (Re)load the SL2VL table */
psm_error_t ips_ibta_init_sl2vl_table(struct ips_proto *proto)
{
  int ret, sli;

  /* Get SL2VL table for unit, port */
  for (sli = 0; sli < 16; sli++) {
    if ((ret = ipath_get_port_sl2vl(proto->ep->context.base_info.spi_unit,
				    proto->ep->context.base_info.spi_port,
				    (uint8_t) sli)) < 0) {
      /* Unable to get SL2VL. Set it to default */
      ret = PSMI_VL_DEFAULT;
    }
    
    proto->sl2vl[sli] = ret;
  }
  
  return PSM_OK;
}

/* On link up/down we need to update some state */
psm_error_t ips_ibta_link_updown_event(struct ips_proto *proto) 
{
  psm_error_t err = PSM_OK;
  int ret;

  /* Get base lid, lmc and rate as these may have changed if the link bounced */
  proto->epinfo.ep_base_lid       = 
    __cpu_to_be16((uint16_t) psm_epid_nid(proto->ep->context.epid)); 
  if ((ret = ipath_get_port_lmc(proto->ep->context.base_info.spi_unit,
				proto->ep->context.base_info.spi_port)) < 0) {
    err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
			    "Could obtain LMC for unit %u:%d. Error: %s",
			    proto->ep->context.base_info.spi_unit,
			    proto->ep->context.base_info.spi_port,
			    strerror(errno));
    goto fail;
  }
  proto->epinfo.ep_lmc = min(ret, IPS_MAX_PATH_LMC);

  if ((ret = ipath_get_port_rate(proto->ep->context.base_info.spi_unit,
				 proto->ep->context.base_info.spi_port)) < 0) {
    err = psmi_handle_error(proto->ep, PSM_EP_DEVICE_FAILURE,
			    "Could obtain link rate for unit %u:%d. Error: %s",
			    proto->ep->context.base_info.spi_unit,
			    proto->ep->context.base_info.spi_port,
			    strerror(errno));
    goto fail;
  }  
  proto->epinfo.ep_link_rate = ips_rate_to_enum(ret);

  /* Load the SL2VL table */
  ips_ibta_init_sl2vl_table(proto);
  
  /* Regenerate new IPD table for the updated link rate. */
  ips_gen_ipd_table(proto);
  
  /* Generate the CCT table.  */
  err = ips_gen_cct_table(proto);

 fail:
  return err;
}

psm_error_t ips_ibta_init(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;
  union psmi_envvar_val psm_path_policy;
  union psmi_envvar_val disable_cca;

  /* Get the path selection policy */
  psmi_getenv("PSM_PATH_SELECTION",
	      "Policy to use if multiple paths are available between endpoints. Options are adaptive, static_src, static_dest, static_base. Default is adaptive.",
	      PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
	      (union psmi_envvar_val) "adaptive",
	      &psm_path_policy);
  
  if (!strcasecmp((const char*) psm_path_policy.e_str, "adaptive"))
    proto->flags |= IPS_PROTO_FLAG_PPOLICY_ADAPTIVE;
  else if (!strcasecmp((const char*) psm_path_policy.e_str, "static_src"))
    proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_SRC;
  else if (!strcasecmp((const char*) psm_path_policy.e_str, "static_dest"))
    proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_DST;
  else if (!strcasecmp((const char*) psm_path_policy.e_str, "static_base"))
    proto->flags |= IPS_PROTO_FLAG_PPOLICY_STATIC_BASE;
  
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_ADAPTIVE)
    _IPATH_PRDBG("Using adaptive path selection.\n");
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_SRC)
    _IPATH_PRDBG("Static path selection: Src Context\n");
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_DST)
    _IPATH_PRDBG("Static path selection: Dest Context\n");
  if (proto->flags & IPS_PROTO_FLAG_PPOLICY_STATIC_BASE)
    _IPATH_PRDBG("Static path selection: Base LID \n");

  psmi_getenv("PSM_DISABLE_CCA",
	      "Disable use of Congestion Control Architecure (CCA) [enabled] ",
	      PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
	      (union psmi_envvar_val) 0,
	      &disable_cca);
  if (disable_cca.e_uint) 
    _IPATH_CCADBG("CCA is disabled for congestion control.\n");
  else
    proto->flags |= IPS_PROTO_FLAG_CCA;
  
  {
    /* Get CCA related parameters from the environment */
    union psmi_envvar_val ccti_incr;
    union psmi_envvar_val ccti_timer;
    union psmi_envvar_val ccti_size;
    int i;
    char ccabuf[256];
    uint8_t *p;

/*
 * If user set any environment variable, use self CCA.
 */
    if (getenv("PSM_CCTI_INCREMENT") || getenv("PSM_CCTI_TIMER") || getenv("PSM_CCTI_TABLE_SIZE")) {
	goto selfcca;
    }

/*
 * Check qib driver CCA setting, and try to use it if available.
 * Fall to self CCA setting if errors.
 */
    i = ipath_get_cc_settings_bin(proto->ep->context.base_info.spi_unit,
		proto->ep->context.base_info.spi_port, ccabuf);
    if (i <= 0) {
	goto selfcca;
    }
    p = (uint8_t *)ccabuf;
    memcpy(&proto->ccti_portctrl, p, 2); p += 2;
    memcpy(&proto->ccti_ctrlmap, p, 2); p += 2;
    for (i=0; i<16; i++) {
	proto->cace[i].ccti_increase = *p; p++;
	memcpy(&proto->cace[i].ccti_timer_cycles, p, 2); p += 2;
	proto->cace[i].ccti_timer_cycles =
	    us_2_cycles(proto->cace[i].ccti_timer_cycles);
	proto->cace[i].ccti_threshold = *p; p++;
	proto->cace[i].ccti_min = *p; p++;
    }

    i = ipath_get_cc_table_bin(proto->ep->context.base_info.spi_unit,
		proto->ep->context.base_info.spi_port, &proto->cct);
    if (i < 0) {
	err = PSM_NO_MEMORY;
	goto fail;
    } else if (i == 0) {
	goto selfcca;
    }
    proto->ccti_limit = i;
    proto->ccti_size = proto->ccti_limit + 1;
    goto finishcca;

/*
 * Since there is no qib driver CCA settings, use self built CCA.
 */
    selfcca:
    psmi_getenv("PSM_CCTI_INCREMENT",
		"IBTA_CCA: Index increment for CCT table on receipt of a BECN packet (less than table size, default 1)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) 1,
		&ccti_incr);
    
    psmi_getenv("PSM_CCTI_TIMER",
		"IBTA_CCA: CCT table congestion timer (>0, default 1 us)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) 1,
		&ccti_timer);
 
    psmi_getenv("PSM_CCTI_TABLE_SIZE",
		"IBTA_CCA: Number of entries in CCT table (multiple of 64, default 128)",
		PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT_FLAGS,
		(union psmi_envvar_val) DF_CCT_TABLE_SIZE, //128
		&ccti_size);

    /* Check the invalid values. */
    if (ccti_size.e_uint < 64 || ccti_size.e_uint%64) {
        _IPATH_INFO("Invalid PSM_CCTI_TABLE_SIZE=%d, at least 64 and multiple of 64, setting to default 128\n",
                ccti_size.e_uint);
        ccti_size.e_uint = 128;
    }
    proto->ccti_size = ccti_size.e_uint;
    /* For now the CCT limit is same as table size.
     * This does not have to be the case. */
    proto->ccti_limit = proto->ccti_size - 1;

    if (ccti_timer.e_uint <= 0) {
        _IPATH_INFO("Invalid PSM_CCTI_TIMER=%d, should be bigger than 0, setting to default 1\n",
                ccti_timer.e_uint);
        ccti_timer.e_uint = 1;
    }
    if (ccti_incr.e_uint <= 0 || ccti_incr.e_uint >= ccti_size.e_uint) {
        _IPATH_INFO("Invalid PSM_CCTI_INCREMENT=%d, should be less than table size, setting to default 1\n",
                ccti_incr.e_uint);
        ccti_incr.e_uint = 1;
    }

    /* Setup CCA parameters for port */
    proto->ccti_portctrl = 1;	/* SL/Port based congestion control */
    proto->ccti_ctrlmap = 0xFFFF;
    for (i=0; i<16; i++) {
	proto->cace[i].ccti_increase = ccti_incr.e_uint; 
	proto->cace[i].ccti_timer_cycles = us_2_cycles(ccti_timer.e_uint); 
	proto->cace[i].ccti_threshold = 8;
	proto->cace[i].ccti_min = 0;
    }
  }

  finishcca:
  /* Seed the random number generator with our pid */
  srand(getpid());

  /* Initialize path record hash table */
  hcreate_r(DF_PATH_REC_HASH_SIZE, &proto->ips_path_rec_hash);

  /* On startup treat it as a link up/down event to setup state . */
  if ((err = ips_ibta_link_updown_event(proto)) != PSM_OK)
    goto fail;

  /* Setup the appropriate query interface for the endpoint */
  switch(proto->ep->path_res_type) {
  case PSM_PATH_RES_OPP:
    err = ips_opp_init(proto);
    if (err != PSM_OK)
      _IPATH_ERROR("Unable to use OFED Plus Plus for path record queries.\n");
    break;
  case PSM_PATH_RES_UMAD:
    _IPATH_ERROR("Path record queries using UMAD is not supported in PSM version %d.%dx\n", PSM_VERNO_MAJOR, PSM_VERNO_MINOR);
    err = PSM_EPID_PATH_RESOLUTION;
    break;
  case PSM_PATH_RES_NONE:
  default:
    err = ips_none_path_rec_init(proto);
  }
  
 fail:  
  return err;
}

psm_error_t ips_ibta_fini(struct ips_proto *proto)
{
  psm_error_t err = PSM_OK;

  if (proto->ibta.fini)
    err = proto->ibta.fini(proto);
  
  /* Destroy the path record hash */
  hdestroy_r(&proto->ips_path_rec_hash);
  
  return err;
}
