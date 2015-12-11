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

#ifdef __MIC__
#include <scif.h>
#endif

#define PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT   1
static int      psmi_get_hca_selection_algorithm(void);
static psm_error_t psmi_init_userinfo_params(psm_ep_t ep, 
		int unit_id, int port,
		psm_uuid_t const unique_job_key,
		struct ipath_user_info *user_info);

psm_error_t
psmi_context_interrupt_set(psmi_context_t *context, int enable)
{
    int poll_type;
    int ret;

    if (( enable &&  (context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED)) ||
	(!enable && !(context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED)))
	return PSM_OK;

    if (enable) 
	poll_type = IPATH_POLL_TYPE_URGENT;
    else
	poll_type = 0;

    ret = ipath_poll_type(context->ctrl, poll_type);

    if (ret != 0)
	return PSM_EP_NO_RESOURCES;
    else {
	if (enable)
	    context->runtime_flags |= PSMI_RUNTIME_INTR_ENABLED;
	else
	    context->runtime_flags &= ~PSMI_RUNTIME_INTR_ENABLED;
	
	return PSM_OK;
    }
}

int
psmi_context_interrupt_isenabled(psmi_context_t *context)
{
    return context->runtime_flags & PSMI_RUNTIME_INTR_ENABLED;
}

static
char *
runtime_flags_string(char *buf, size_t len, uint32_t runtime_flags)
{
    size_t off = 0;
    int flag = 0;
    char *s;

    psmi_assert(len > 0 && buf != NULL);
    buf[0] = '\0';

    for (flag = 0; off < len && flag < 32; flag++) {
	switch((1<<flag) & runtime_flags) {
	    case IPATH_RUNTIME_PCIE:
		s = "pcie";
		break;
	    case IPATH_RUNTIME_SDMA:
		s = "dmasend";
		break;
	    case IPATH_RUNTIME_FORCE_WC_ORDER:
		s = "force_wc_order";
		break;
	    case IPATH_RUNTIME_HDRSUPP:
	        s = "hdrsupp";
		break;
	    case IPATH_RUNTIME_RCVHDR_COPY:
		s = "rcvhdr_copy";
		break;
	    case IPATH_RUNTIME_MASTER:
		s = "sub_master";
		break;
	    case IPATH_RUNTIME_NODMA_RTAIL:
		s = "nodma_rtail";
		break;
	    case IPATH_RUNTIME_SPECIAL_TRIGGER:
		s = "pio_special_trigger";
		break;
	    case IPATH_RUNTIME_FORCE_PIOAVAIL:
		s = "pioavail_force";
		break;
	    case IPATH_RUNTIME_PIO_REGSWAPPED:
		s = "pioreg_swapped";
		break;
	    case PSMI_RUNTIME_RCVTHREAD:
		s = "psm_rcvthread";
		break;
	    case PSMI_RUNTIME_INTR_ENABLED:
		s = "psm_intr_on";
		break;
	    default:
		s = NULL;
		break;
	}
	if (s == NULL)
	    continue;
	off += snprintf(buf + off, len - off - 1, "%s,", s);
    }

    if (off > 1) {
	size_t c = strlen(buf);
	buf[c - 1] = '\0';
    }
    return buf;
}

psm_error_t
psmi_context_open(const psm_ep_t ep, long unit_id, long port,
	      psm_uuid_t const job_key, 
	      int64_t timeout_ns, psmi_context_t *context)
{
    long open_timeout = 0;
    int lid;
    uint64_t gid_hi, gid_lo;
    char dev_name[MAXPATHLEN];
    psm_error_t err = PSM_OK;
    uint32_t driver_verno, hca_type;
    int retry_delay = 0;

    /*
     * If shared contexts are enabled, try our best to schedule processes
     * across one or many devices
     */

    if (timeout_ns > 0)
	open_timeout = (long)(timeout_ns/MSEC_ULL);
    if (unit_id != IPATH_UNIT_ID_ANY && unit_id >= 0)
        snprintf(dev_name, sizeof(dev_name), "%s%u", "/dev/ipath", (unsigned)unit_id);
    else
        snprintf(dev_name, sizeof(dev_name), "%s", "/dev/ipath");

    context->fd = ipath_context_open(unit_id, port, open_timeout);
    if (context->fd == -1) {
	err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
		    "PSM can't open %s for reading and writing",
		    dev_name);
	goto bail;
    }

    if ((err = psmi_init_userinfo_params(ep, (int) unit_id, (int)port, job_key,
				&context->user_info))) 
	goto bail;

retry_open:
    context->ctrl = ipath_userinit(context->fd, &context->user_info,
		                &context->base_info);

    if (!context->ctrl) {

      /* ipath_userinit returns EBUSY on ipath and ENODEV on qib when
       * no contexts are available. Handle both drivers. 
       */
      if ((errno != ENETDOWN) && (errno != EBUSY) && (errno != ENODEV))
	goto fail;
      
      if ((open_timeout == -1L) || (errno == EBUSY) || (errno == ENODEV)) {
	    if(!retry_delay) {
		_IPATH_PRDBG("retrying open: %s, network down\n", dev_name);
		retry_delay = 1;
	    }
	    else if(retry_delay<17)
		retry_delay <<= 1;
	    
	    /* If device is still busy after 3 attempts give up. No contexts
	     * available.
	     */
	    if (((errno == EBUSY) || (errno == ENODEV)) && retry_delay > 4)
	      goto fail;
	    
	    sleep(retry_delay);
	    goto retry_open;
	}
      
	err = psmi_handle_error(NULL, PSM_EP_NO_NETWORK,
		"can't open %s, network down", dev_name);
	goto bail;
    }

    if ((lid = ipath_get_port_lid(context->base_info.spi_unit,
				  context->base_info.spi_port)) == -1) {
	err = psmi_handle_error(NULL, 
	        PSM_EP_DEVICE_FAILURE, 
		"Can't get InfiniBand LID in psm_ep_open: is SMA running?");
	goto fail;
    }
    if (ipath_get_port_gid(context->base_info.spi_unit,
			   context->base_info.spi_port,
			   &gid_hi, &gid_lo) == -1) {
	err = psmi_handle_error(NULL, 
	        PSM_EP_DEVICE_FAILURE, 
		"Can't get InfiniBand GID in psm_ep_open: is SMA running?");
	goto fail;
    }
    ep->unit_id = context->base_info.spi_unit;
    ep->portnum = context->base_info.spi_port;
    ep->gid_hi = gid_hi;
    ep->gid_lo = gid_lo;

    context->ep = (psm_ep_t) ep;
    context->runtime_flags = context->base_info.spi_runtime_flags;
    
    /* Get type of hca assigned to context */
    hca_type = psmi_get_hca_type(context);
    
    /* Endpoint out_sl contains the default SL to use for this endpoint. */
    context->epid = 
      PSMI_EPID_PACK_EXT(lid, context->base_info.spi_context,
			 context->base_info.spi_subcontext, 
			 hca_type, ep->out_sl);
    
    /*
     * With driver 1.5 (release 2.1), assume we always need the force.
     * Starting with 1.6, the flag is based on chip rev.
     */
    driver_verno = context->base_info.spi_sw_version;
    if (driver_verno == PSMI_MAKE_DRIVER_VERSION(1, 5))
	context->runtime_flags |= IPATH_RUNTIME_FORCE_PIOAVAIL;

    /*
     * We only know of register-swapped pio bufs before driver 1.6
     * Starting with 1.6, the flag is based on chip rev.
     */
    if (driver_verno < PSMI_MAKE_DRIVER_VERSION(1, 6))
	context->runtime_flags |= IPATH_RUNTIME_PIO_REGSWAPPED;

    /* We are overloading this runtime flags for PSM options so make sure
     * something can never go horribly bad */
    psmi_assert_always(context->runtime_flags < _PSMI_RUNTIME_LAST);
    context->spi_status = (volatile uint64_t *)
			context->ctrl->__ipath_spi_status;

    {
	char buf[192];
	_IPATH_PRDBG("Opened context %d.%d on device %s (LID=%d,epid=%llx), "
		 "runtime_flags=0x%x (%s), driver=%d.%d\n", 
		context->base_info.spi_context,
		context->base_info.spi_subcontext, dev_name, lid,
		(long long) context->epid, context->runtime_flags,
		runtime_flags_string(buf, sizeof buf, context->runtime_flags),
		context->base_info.spi_sw_version >> 16,
		context->base_info.spi_sw_version & 0xffff);
    }
    goto ret;

fail:
    switch (errno) {
    case ENOENT:
    case ENODEV:
	err = psmi_handle_error(NULL, PSM_EP_NO_DEVICE,
		"%s not found", dev_name);
	break;
    case ENXIO:
	err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE,
		"%s failure", dev_name);
	break;
    case EBUSY:
	err = psmi_handle_error(NULL, PSM_EP_NO_PORTS_AVAIL,
		"No free InfiniPath contexts available on %s", dev_name);
	break;
    default:
	err = psmi_handle_error(NULL, PSM_EP_DEVICE_FAILURE, 
		"Driver initialization failure on %s", dev_name);
	break;
    }
bail:
    _IPATH_PRDBG("%s open failed: %d (%s)\n", dev_name, err, strerror(errno));
    if (context->fd != -1) {
	ipath_context_close(context->fd);
	context->fd = -1;
    }
ret: 
    return err;
}

psm_error_t
psmi_context_close(psmi_context_t *context)
{
    if (context->fd >= 0) {
	ipath_context_close(context->fd);
	context->fd = -1;
    }
    return PSM_OK;
}

/* 
 * This function works whether a context is intiialized or not in a psm_ep.
 *
 * Returns one of
 *
 * PSM_OK: Port status is ok (or context not intialized yet but still "ok")
 * PSM_OK_NO_PROGRESS: Cable pulled
 * PSM_EP_NO_NETWORK: No network, no lid, ...
 * PSM_EP_DEVICE_FAILURE: Chip failures, rxe/txe parity, etc.
 * The message follows the per-port status
 * As of 7322-ready driver, need to check port-specific qword for IB
 * as well as older unit-only.  For now, we don't have the port interface
 * defined, so just check port 0 qword for spi_status
 */

#define STATUS_MASK     (IPATH_STATUS_CHIP_PRESENT |	    \
			      IPATH_STATUS_HWERROR |	    \
			      IPATH_STATUS_IB_CONF |	    \
			      IPATH_STATUS_IB_READY)

#define STATUS_NO_ERROR_VAL   (IPATH_STATUS_CHIP_PRESENT |   \
			       IPATH_STATUS_IB_CONF |	    \
			       IPATH_STATUS_IB_READY)
psm_error_t
psmi_context_check_status(const psmi_context_t *contexti)
{
    psm_error_t err = PSM_OK;
    uint64_t status, ibstatus;
    char *errmsg = NULL;
    psmi_context_t *context = (psmi_context_t *) contexti;

    if (context->spi_status == NULL) 
	goto ret;

    status = context->spi_status[0];
    ibstatus = context->spi_status[1];

    /* Fatal chip-related errors */
    if ( !(status & IPATH_STATUS_CHIP_PRESENT) ||
          (status & (IPATH_STATUS_HWERROR))) {

	err = PSM_EP_DEVICE_FAILURE;
	if (err != context->spi_status_lasterr) { /* report once */
	    volatile char *errmsg_sp = (volatile char *)&context->spi_status[2];
	    if (*errmsg_sp) 
		psmi_handle_error(context->ep, err, 
				      "Hardware problem: %s", errmsg_sp);
	    else {
		if (status & IPATH_STATUS_HWERROR)
		    errmsg = "Hardware error";
		else
		    errmsg = "Hardware not found";

		psmi_handle_error(context->ep, err, errmsg, "%s");
	    }
	}
    }

    /* Fatal network-related errors */
    else if (!(status & IPATH_STATUS_IB_CONF) &&
	    !(ibstatus & IPATH_STATUS_IB_CONF)) {
	err = PSM_EP_NO_NETWORK;
	if (err != context->spi_status_lasterr) { /* report once */
	    volatile char *errmsg_sp = (volatile char *)&context->spi_status[1];
	    psmi_handle_error(context->ep, err,
			"%s", *errmsg_sp ? errmsg_sp : "Network down");
	}
    }

    /* These errors are not fatal, they are log only */
    else if (!(status & IPATH_STATUS_IB_READY) &&
	    !(ibstatus & IPATH_STATUS_IB_READY)) {
	err = PSM_OK_NO_PROGRESS; /* Cable pulled, switch rebooted, ... */
	if (err != context->spi_status_lasterr) { /* report once */
#if 0
	    psmi_handle_error(PSMI_EP_LOGEVENT, PSM_EP_NO_NETWORK,
		    "IB Link is down");
#endif
	}
    }

    if (err == PSM_OK && context->spi_status_lasterr != PSM_OK) 
	context->spi_status_lasterr = PSM_OK;  /* clear error */
    else if (err != PSM_OK)
	context->spi_status_lasterr = err; /* record error */

ret:
    return err;
}

/*
 * Prepare user_info params for driver open, used only in psmi_context_open
 */
static
psm_error_t
psmi_init_userinfo_params(psm_ep_t ep, int unit_id, int port,
		psm_uuid_t const unique_job_key,
		struct ipath_user_info *user_info)
{
    /* static variables, shared among rails */
    static int shcontexts_enabled = -1, rankid, nranks;
    static int subcontext_id_start = -1;

    int avail_contexts = 0, max_contexts, ask_contexts, ranks_per_context = 0;
    uint32_t job_key;
    uint16_t *jkp;
    psm_error_t err = PSM_OK;
    union psmi_envvar_val env_maxctxt, env_ranks_per_context;

    memset(user_info, 0, sizeof *user_info);
    user_info->spu_userversion = IPATH_USER_SWVERSION;
    user_info->spu_subcontext_id = 0;
    user_info->spu_subcontext_cnt = 0;
    user_info->spu_port_alg = psmi_get_hca_selection_algorithm();

    if (shcontexts_enabled == -1) {
        shcontexts_enabled = psmi_sharedcontext_params(&nranks, &rankid);
    }

    if (!shcontexts_enabled)
	return err;

    avail_contexts = ipath_get_num_contexts(unit_id);
    jkp = (uint16_t *) unique_job_key;

    /* Use a unique subcontext id based on uuid.  This is just to optimistically
     * prevent sharing a context across two unrelated jobs that would start at the
     * same time */
    job_key =  ((jkp[2] ^ jkp[3]) >> 8) | ((jkp[0] ^ jkp[1]) << 8);
    job_key ^= ((jkp[6] ^ jkp[7]) >> 8) | ((jkp[4] ^ jkp[5]) << 8);
    /* comment out, because it has more chance to generate the same job_key for
     * two unrelated jobs that would start at the same time, and causes context
     * allocation failure */
    //job_key &= ~0xff; /* just to make more readable */

    if (avail_contexts == 0) {
	err = psmi_handle_error(NULL, PSM_EP_NO_DEVICE,
		"PSM found 0 available contexts on InfiniPath device(s).");
	goto fail;
    }

    /* See if the user wants finer control over context assignments */
    if (!psmi_getenv("PSM_SHAREDCONTEXTS_MAX", 
		    "Maximum number of contexts for this PSM job",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val) avail_contexts,
		    &env_maxctxt)) {
	max_contexts = max(env_maxctxt.e_int, 1); /* needs to be non-negative */
	ask_contexts = min(max_contexts, avail_contexts); /* needs to be available */
    }
    else
	ask_contexts = max_contexts = avail_contexts;

    if (!psmi_getenv("PSM_RANKS_PER_CONTEXT", 
		    "Number of ranks per context",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val) 1,
		    &env_ranks_per_context)) {
        ranks_per_context = max(env_ranks_per_context.e_int, 1);
	ranks_per_context = min(ranks_per_context, INFINIPATH_MAX_SUBCONTEXT);
    }

    /* 
     * See if we could get a valid local rank.  If not, pre-attach to the
     * shm segment to obtain a unique shmidx.
     */
    if (rankid == -1) {
	if ((err = psmi_shm_attach(ep, &rankid)))
	    goto fail;
    }

    /* 
     * See if we could get a valid ppn.  If not, approximate it to be the
     * number of cores.  
     */
    if (nranks == -1) {
	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	if (nproc < 1) 
	    nranks = 1;
	else
	    nranks = nproc;
    }

    /* 
     * Make sure that our guesses are good educated guesses
     */
    if (rankid >= nranks) {
	_IPATH_PRDBG("PSM_SHAREDCONTEXTS disabled because lrank=%d,ppn=%d\n",
		     rankid, nranks);
	goto fail;
    }

    if (ranks_per_context) {
        int contexts = (nranks + ranks_per_context - 1) / ranks_per_context;
	if (contexts > ask_contexts) {
	    err = psmi_handle_error(NULL, PSM_EP_NO_DEVICE,
		    "Context required %d (nranks %d, ranks_per_context %d) "
		    "is less than allowed context %d which is either the "
		    "total avail_context %d or set by PSM_SHAREDCONTEXTS_MAX\n",
		    contexts, nranks, ranks_per_context, ask_contexts, avail_contexts);
	    goto fail;
	}
	ask_contexts = contexts;
    }

    user_info->spu_port = port; /* requested IB port if > 0 */
    if (subcontext_id_start == -1) {
#ifdef __MIC__
	/* this query is moved from ipath_userinit() to here,
	 * it is also used there by ipath_cmd_assign_context() call. */
	if (scif_get_nodeIDs(NULL, 0, (uint16_t*)&user_info->_spu_scif_nodeid) < 0) {
	    _IPATH_INFO("scif_get_nodeIDs() call failed: %s\n", strerror(errno));
	    goto fail;
	}
	/*
 	 * When processes from different MICs to use the same HCA, and
 	 * context sharing is enabled, we can't mix them, only processes
 	 * from the same MIC node can share a context, so we need to
 	 * generate a unique id. Here we use the queried nodeID to do it,
 	 * avail_contexts is a constant for all MICs.
 	 */
	subcontext_id_start = avail_contexts * user_info->_spu_scif_nodeid;
#else
	subcontext_id_start = 0;
#endif
    }

    /* "unique" id based on job key */
    user_info->spu_subcontext_id = subcontext_id_start +
			job_key + rankid % ask_contexts;
    /* this is for multi-rail, when we setup a new rail,
     * we can not use the same subcontext ID as the previous
     * rail, otherwise, the driver will match previous rail
     * and fail.
     */
    subcontext_id_start += ask_contexts;

    /* Need to compute with how many *other* peers we will be sharing the
     * context */
    if (nranks > ask_contexts) {
	user_info->spu_subcontext_cnt = nranks / ask_contexts;
	/* If ppn != multiple of contexts, some contexts get an uneven 
	 * number of subcontexts */
	if (nranks % ask_contexts > rankid % ask_contexts)
	    user_info->spu_subcontext_cnt++;
	/* The case of 1 process "sharing" a context (giving 1 subcontext) 
	 * is supcontexted by the driver and PSM. However, there is no 
	 * need to share in this case so disable context sharing. */
	if (user_info->spu_subcontext_cnt == 1)
	    user_info->spu_subcontext_cnt = 0;
    }
    /* else spu_subcontext_cnt remains 0 and context sharing is disabled. */

    _IPATH_PRDBG("PSM_SHAREDCONTEXTS lrank=%d,ppn=%d,avail_contexts=%d,"
		 "max_contexts=%d,ask_contexts=%d,"
                 "ranks_per_context=%d,id=%u,peers=%d,port=%d\n",
		 rankid, nranks, avail_contexts, max_contexts, ask_contexts, 
		 ranks_per_context,
		 (int) user_info->spu_subcontext_id,
		 (int) user_info->spu_subcontext_cnt,
		 (int) user_info->spu_port);
fail:
    return err;
}

int
psmi_sharedcontext_params(int *nranks, int *rankid)
{
    union psmi_envvar_val enable_shcontexts;
    char *ppn_env = NULL, *lrank_env = NULL, *c;

    *rankid = -1;
    *nranks = -1;

#if 0
    /* DEBUG: Used to selectively test possible shared context and shm-only
     * settings */
    unsetenv("PSC_MPI_NODE_RANK");
    unsetenv("PSC_MPI_PPN");
    unsetenv("MPI_LOCALRANKID");
    unsetenv("MPI_LOCALRANKS");
#endif

    /* New name in 2.0.1, keep observing old name */
    if (psmi_getenv("PSM_SHAREDCONTEXTS", "Enable shared contexts",
		    PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_YESNO,
		    (union psmi_envvar_val)
		    PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT, 
		    &enable_shcontexts)) 
    {
	psmi_getenv("PSM_SHAREDPORTS", "Enable shared contexts",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_YESNO,
		    (union psmi_envvar_val)
		    PSMI_SHARED_CONTEXTS_ENABLED_BY_DEFAULT, 
		    &enable_shcontexts); 
    }

    if (!enable_shcontexts.e_int)
	return 0;

    /* We support two types of syntaxes to let users give us a hint what
     * our local rankid is.  Moving towards MPI_, but still support PSC_ */
    if ((c = getenv("MPI_LOCALRANKID")) && *c != '\0') { 
	lrank_env = "MPI_LOCALRANKID";
	ppn_env = "MPI_LOCALNRANKS";
    }
    else if ((c = getenv("PSC_MPI_PPN")) && *c != '\0') { 
	ppn_env = "PSC_MPI_PPN";
	lrank_env = "PSC_MPI_NODE_RANK";
    }

    if (ppn_env != NULL && lrank_env != NULL) {
	union psmi_envvar_val env_rankid, env_nranks;

	psmi_getenv(lrank_env, "Shared context rankid",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val) -1,
		    &env_rankid); 

	psmi_getenv(ppn_env, "Shared context numranks",
		    PSMI_ENVVAR_LEVEL_HIDDEN, PSMI_ENVVAR_TYPE_INT,
		    (union psmi_envvar_val) -1,
		    &env_nranks); 

	*rankid = env_rankid.e_int;
	*nranks = env_nranks.e_int;
    }
    return 1;
}

static 
int      
psmi_get_hca_selection_algorithm(void)
{
  union psmi_envvar_val env_hca_alg;
  int hca_alg = IPATH_PORT_ALG_ACROSS;

  /* If a specific unit is set in the environment, use that one. */
  psmi_getenv("IPATH_HCA_SELECTION_ALG", 
	      "HCA Device Selection Algorithm to use. Round Robin (Default) "
	      "or Packed",
	      PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
	      (union psmi_envvar_val) "Round Robin",
	      &env_hca_alg);

  if (!strcasecmp(env_hca_alg.e_str, "Round Robin"))
    hca_alg = IPATH_PORT_ALG_ACROSS;
  else if (!strcasecmp(env_hca_alg.e_str, "Packed"))
    hca_alg = IPATH_PORT_ALG_WITHIN;
  else {
    _IPATH_ERROR("Unknown HCA selection algorithm %s. Defaulting to Round Robin "
		 "allocation of HCAs.\n", env_hca_alg.e_str);
    hca_alg = IPATH_PORT_ALG_ACROSS;
  }
  
  return hca_alg;
}
