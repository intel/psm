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

#include <dlfcn.h>
#include "psm_user.h"

static int psmi_verno_major = PSM_VERNO_MAJOR;
static int psmi_verno_minor = PSM_VERNO_MINOR;
static int psmi_verno = PSMI_VERNO_MAKE(PSM_VERNO_MAJOR, PSM_VERNO_MINOR);
static int psmi_verno_client_val = 0;

#define PSMI_NOT_INITIALIZED    0
#define PSMI_INITIALIZED        1
#define PSMI_FINALIZED         -1 /* Prevent the user from calling psm_init
				   * once psm_finalize has been called. */
static int psmi_isinit = PSMI_NOT_INITIALIZED;

int
psmi_verno_client()
{
    return psmi_verno_client_val;
}

#ifdef PSMI_PLOCK_IS_SPINLOCK
psmi_spinlock_t psmi_progress_lock;
#elif defined(PSMI_PLOCK_IS_MUTEXLOCK)
pthread_mutex_t psmi_progress_lock = PTHREAD_MUTEX_INITIALIZER;
#elif defined(PSMI_PLOCK_IS_MUTEXLOCK_DEBUG)
pthread_mutex_t psmi_progress_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
pthread_t	psmi_progress_lock_owner = PSMI_PLOCK_NO_OWNER;
#endif

/* This function is used to determine whether the current library build can
 * successfully communicate with another library that claims to be version
 * 'verno'.
 *
 * PSM 1.x is always ABI compatible, but this checks to see if two different
 * versions of the library can coexist.
 */
int
psmi_verno_isinteroperable(uint16_t verno)
{
    /* 
     * Up and including 1.03, all peers require to be 1.03 (or later).
     */
    if (PSMI_VERNO_GET_MAJOR(verno) != PSM_VERNO_MAJOR) 
	return 0;

    /* This -1 tries to make sure that we always update this function for each
     * new release of the library.  There's an internal check to make sure that
     * verno_iscompatible is always updated.  Each new version should have an
     * entry in the switch statement below. */
    int iscompat = -1;

    switch (psmi_verno) {
       case 0x0110:
       case 0x010f:
	 /* Multi-rail is supported in this version, since the packet header
	  * sequence number is shrunk from 24bits to 16bits, old version
	  * can not process such packet. The freed 8bits and another 8bits
	  * are used to form the message sequence number to keep message order
	  * in multi-rail case.
	  */
	    iscompat = (verno >= 0x010f);
	    break;
       case 0x010e:
	 /* Allow specification of send buffer descriptors in addition to send
	  * network buffers for IPS. Having a large number of send descriptors
	  * can be beneficial on large scale clusters with bursty network IO.
	  */
       case 0x010d:
	 /* Wire protocol is same as QOFED 1.4.2. Added support to specify
	  * path record resolution mechanism as well as service ID to use
	  * for endpoint. Required to implement support for alternate
	  * network topolgies.
	  */
       case 0x010c:
	 /* Added support for generic psm_set|getopt methods. Also exposed
	  * "some" internal implementation details via components that these
	  * methods operate on. Wire protocol remains the same but we need
	  * to bump the version number as the API changes so ULPs can detect
	  * if these methods are available.
	  */
       case 0x010b:
	 /* Removed VL specification per endpoint however is wire level
	  * compatible with 0x010a version. Use SL2VL mapping table coupled
	  * with the SL for endpoint to select VL.
	  */
       case 0x010a:
	 /* 0x010a updates wire protocol with support for AM requests with
	  * no replies (OPCODE_AM_REQUEST_NOREPLY).
	  */
	    iscompat = (verno >= 0x010a);
	    break;
       case 0x0109:
	 /* 0x0109 updates the wire protocol to pad writes upto cache line size
	  * to mitigate overhead of partial cache line writes on some processor
	  * architectures. Only MQ sends upto 2K bytes are padded.
	  */
	     iscompat = (verno >= 0x0109);
	     break;
        case 0x0108:
	  /* 0x0108 moved subcontext bits out of KPFlags and into ips header.
	   * This is incompatible with previous version. */
	     iscompat = (verno >= 0x0108);
	     break;
	case 0x0107:
	case 0x0106:
	case 0x0105:
	    /* 0x0105 coincides with release 2.1 which introduced a new
	     * expected send protocol.  Anything before that is incompatible */
	    iscompat = (verno >= 0x0105);
	    break;
	case 0x0104:
	case 0x0103:
	    /* Nothing below 1.03 is supported by 1.03 */
	    iscompat = (verno >= 0x0103);
	    break;
	default:
	    iscompat = -1;
    }
    return iscompat;
}

int
psmi_isinitialized()
{
    return (psmi_isinit == PSMI_INITIALIZED);
}

extern char psmi_infinipath_revision[];

psm_error_t
__psm_init(int *major, int *minor)
{
    psm_error_t	err = PSM_OK;
    union psmi_envvar_val env_tmask;

    if (psmi_isinit == PSMI_INITIALIZED)
	goto update;

    if (psmi_isinit == PSMI_FINALIZED) {
	err = PSM_IS_FINALIZED;
	goto fail;
    }

    if (major == NULL || minor == NULL) {
	err = PSM_PARAM_ERR;
	goto fail;
    }

#ifdef PSM_DEBUG
    if (!getenv("PSM_NO_WARN")) 
	fprintf(stderr, "!!! WARNING !!! You are running an internal-only PSM *DEBUG* build.\n");
#endif

#ifdef PSM_PROFILE
    if (!getenv("PSM_NO_WARN")) 
	fprintf(stderr, "!!! WARNING !!! You are running an internal-only PSM *PROFILE* build.\n");
#endif

    /* Make sure we complain if fault injection is enabled */
    if (getenv("PSM_FI") && !getenv("PSM_NO_WARN")) 
	fprintf(stderr, "!!! WARNING !!! You are running with fault injection enabled!\n");

    /* Make sure, as an internal check, that this version knows how to detect
     * cmopatibility with other library versions it may communicate with */
    if (psmi_verno_isinteroperable(psmi_verno) != 1) {
	err = psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
		"psmi_verno_isinteroperable() not updated for current version!");
	goto fail;
    }

    /* The only way to not support a client is if the major number doesn't
     * match */
    if (*major != PSM_VERNO_MAJOR) {
	err = psmi_handle_error(NULL, PSM_INIT_BAD_API_VERSION,
		    "This library does not implement version %d.%d", 
		    *major, *minor);
	goto fail;
    }

    /* Make sure we don't keep track of a client that claims a higher version
     * number than we are */
    psmi_verno_client_val = min(PSMI_VERNO_MAKE(*major, *minor), psmi_verno);

    psmi_isinit = PSMI_INITIALIZED;
    /* infinipath_debug lives in libinfinipath.so */
    psmi_getenv("PSM_TRACEMASK",
                "Mask flags for tracing",
                PSMI_ENVVAR_LEVEL_USER,
                PSMI_ENVVAR_TYPE_ULONG_FLAGS,
                (union psmi_envvar_val) infinipath_debug,
                &env_tmask);
    infinipath_debug = (long) env_tmask.e_ulong;

    /* The "real thing" is done in ipath_proto.c as a constructor function, but
     * we getenv it here to report what we're doing with the setting */
    {
	extern int __ipath_malloc_no_mmap; 
	union psmi_envvar_val env_mmap;
	char *env = getenv("IPATH_DISABLE_MMAP_MALLOC");
	int broken = (env && *env && !__ipath_malloc_no_mmap);
	psmi_getenv("IPATH_DISABLE_MMAP_MALLOC",
		broken ?  "Skipping mmap disable for malloc()" :
		"Disable mmap for malloc()",
		PSMI_ENVVAR_LEVEL_USER,
		PSMI_ENVVAR_TYPE_YESNO,
		(union psmi_envvar_val) 0,
		&env_mmap);
	if (broken) 
	    _IPATH_ERROR("Couldn't successfully disable mmap in mallocs "
			 "with mallopt()\n");
    }

    if (getenv("PSM_IDENTIFY")) {
	Dl_info info_psm, info_ipath;
	_IPATH_INFO("%s from %s:%s\n", psmi_infinipath_revision,
	    dladdr(psm_init, &info_psm) ? info_psm.dli_fname : 
					  "libpsm not available",
	    dladdr(ipath_userinit, &info_ipath) ? info_ipath.dli_fname : 
						  "libinfinipath not available");
    }

#ifdef PSMI_PLOCK_IS_SPINLOCK
    psmi_spin_init(&psmi_progress_lock);
#endif

    if (getenv("PSM_DIAGS")) {
	_IPATH_INFO("Running diags...\n");
	psmi_diags();
    }

    psmi_faultinj_init();

    psmi_epid_init();

update:
    *major = (int) psmi_verno_major;
    *minor = (int) psmi_verno_minor;
fail:
    return err;
}
PSMI_API_DECL(psm_init)

psm_error_t
__psm_finalize(void)
{
    struct psmi_eptab_iterator itor;
    char *hostname;
    psm_ep_t ep;
    extern psm_ep_t psmi_opened_endpoint; /* in psm_endpoint.c */

    PSMI_ERR_UNLESS_INITIALIZED(NULL);

    ep = psmi_opened_endpoint;
    while (ep != NULL) {
	psmi_opened_endpoint = ep->user_ep_next;
	psm_ep_close(ep, PSM_EP_CLOSE_GRACEFUL,
	    2*PSMI_MIN_EP_CLOSE_TIMEOUT);
	ep = psmi_opened_endpoint;
    }

    psmi_epid_fini();

    psmi_faultinj_fini();

    /* De-allocate memory for any allocated space to store hostnames */
    psmi_epid_itor_init(&itor, PSMI_EP_HOSTNAME);
    while ((hostname = psmi_epid_itor_next(&itor)))
	psmi_free(hostname);
    psmi_epid_itor_fini(&itor);

    psmi_isinit = PSMI_FINALIZED;
    return PSM_OK;
}
PSMI_API_DECL(psm_finalize)

/*
 * Function exposed in >= 1.05
 */
psm_error_t
__psm_map_nid_hostname(int num, const uint64_t *nids, const char **hostnames)
{
    int i;
    psm_error_t err = PSM_OK;

    PSMI_ERR_UNLESS_INITIALIZED(NULL);

    PSMI_PLOCK();

    if (nids == NULL || hostnames == NULL) {
	err = PSM_PARAM_ERR;
	goto fail;
    }

    for (i = 0; i < num; i++) {
	if ((err = psmi_epid_set_hostname(nids[i], hostnames[i], 1)))
	    break;
    }

fail:
    PSMI_PUNLOCK();
    return err;
}
PSMI_API_DECL(psm_map_nid_hostname)

void
__psm_epaddr_setlabel(psm_epaddr_t epaddr, char const *epaddr_label)
{
    return; /* ignore this function */
}
PSMI_API_DECL(psm_epaddr_setlabel)

void
__psm_epaddr_setctxt(psm_epaddr_t epaddr, void *ctxt)
{
  
  /* Eventually deprecate this API to use set/get opt as this is unsafe. */
  psm_setopt(PSM_COMPONENT_CORE, (const void*) epaddr, 
	     PSM_CORE_OPT_EP_CTXT, (const void*) ctxt, sizeof(void*));
  
}
PSMI_API_DECL(psm_epaddr_setctxt)

void * 
__psm_epaddr_getctxt(psm_epaddr_t epaddr)
{
  psm_error_t err;
  uint64_t optlen = sizeof(void*);
  void *result = NULL;
  
  /* Evetually deprecate this API to use set/get opt as this is unsafe. */
  err = psm_getopt(PSM_COMPONENT_CORE, (const void*) epaddr, 
		   PSM_CORE_OPT_EP_CTXT, (void*) &result, &optlen);
  
  if (err == PSM_OK)
    return result;
  else
    return NULL;
}
PSMI_API_DECL(psm_epaddr_getctxt)

psm_error_t
__psm_setopt(psm_component_t component, const void *component_obj,
	     int optname, const void *optval, uint64_t optlen)
{  
  switch(component) {
  case PSM_COMPONENT_CORE:
    return psmi_core_setopt(component_obj, optname, optval, optlen);
    break;
  case PSM_COMPONENT_MQ:
    /* Use the deprecated MQ set/get opt for now which does not use optlen */
    return psm_mq_setopt((psm_mq_t) component_obj, optname, optval);
    break;
  case PSM_COMPONENT_AM:
    /* Hand off to active messages */
    return psmi_am_setopt(component_obj, optname, optval, optlen);
    break;
  case PSM_COMPONENT_IB:
    /* Hand off to IPS ptl to set option */
    return psmi_ptl_ips.setopt(component_obj, optname, optval, optlen);
    break;
  }

  /* Unrecognized/unknown component */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown component %u", component);
  
}

PSMI_API_DECL(psm_setopt);

psm_error_t
__psm_getopt(psm_component_t component, const void *component_obj,
	     int optname, void *optval, uint64_t *optlen)
{  
  switch(component) {
  case PSM_COMPONENT_CORE:
    return psmi_core_getopt(component_obj, optname, optval, optlen);
    break;
  case PSM_COMPONENT_MQ:
    /* Use the deprecated MQ set/get opt for now which does not use optlen */
    return psm_mq_getopt((psm_mq_t) component_obj, optname, optval);
    break;
  case PSM_COMPONENT_AM:
    /* Hand off to active messages */
    return psmi_am_getopt(component_obj, optname, optval, optlen);
    break;
  case PSM_COMPONENT_IB:
    /* Hand off to IPS ptl to set option */
    return psmi_ptl_ips.getopt(component_obj, optname, optval, optlen);
    break;
  }

  /* Unrecognized/unknown component */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown component %u", component);
}
PSMI_API_DECL(psm_getopt);

psm_error_t __recvpath
__psmi_poll_noop(ptl_t *ptl, int replyonly)
{
    return PSM_OK_NO_PROGRESS;
}
PSMI_API_DECL(psmi_poll_noop)

psm_error_t __recvpath
__psm_poll(psm_ep_t ep)
{
    psm_error_t err1 = PSM_OK, err2 = PSM_OK;
    psm_ep_t tmp;

    PSMI_ASSERT_INITIALIZED();

    PSMI_PLOCK();

    tmp = ep;
    do {
    err1 = ep->ptl_amsh.ep_poll(ep->ptl_amsh.ptl, 0); /* poll reqs & reps */
    if (err1 > PSM_OK_NO_PROGRESS) { /* some error unrelated to polling */
	PSMI_PUNLOCK();
	return err1;
    }

    err2 = ep->ptl_ips.ep_poll(ep->ptl_ips.ptl, 0); /* get into ips_do_work */
    if (err2 > PSM_OK_NO_PROGRESS) { /* some error unrelated to polling */
	PSMI_PUNLOCK();
	return err2;
    }
    ep = ep->mctxt_next;
    } while (ep != tmp);

    /* This is valid because..
     * PSM_OK & PSM_OK_NO_PROGRESS => PSM_OK
     * PSM_OK & PSM_OK => PSM_OK
     * PSM_OK_NO_PROGRESS & PSM_OK => PSM_OK
     * PSM_OK_NO_PROGRESS & PSM_OK_NO_PROGRESS => PSM_OK_NO_PROGRESS */
    PSMI_PUNLOCK();
    return (err1 & err2);
}
PSMI_API_DECL(psm_poll)

psm_error_t __recvpath
__psmi_poll_internal(psm_ep_t ep, int poll_amsh)
{
    psm_error_t err1 = PSM_OK_NO_PROGRESS;
    psm_error_t err2;
    psm_ep_t tmp;

    PSMI_PLOCK_ASSERT();

    tmp = ep;
    do {
    if (poll_amsh) {
	err1 = ep->ptl_amsh.ep_poll(ep->ptl_amsh.ptl, 0); /* poll reqs & reps */
	if (err1 > PSM_OK_NO_PROGRESS) /* some error unrelated to polling */
	    return err1;
    }

    err2 = ep->ptl_ips.ep_poll(ep->ptl_ips.ptl, 0); /* get into ips_do_work */
    if (err2 > PSM_OK_NO_PROGRESS) /* some error unrelated to polling */
	return err2;

    ep = ep->mctxt_next;
    } while (ep != tmp);

    return (err1 & err2);
}
PSMI_API_DECL(psmi_poll_internal)

#ifdef PSM_PROFILE
/* These functions each have weak symbols */
void 
psmi_profile_block()
{
    ; // empty for profiler
}

void 
psmi_profile_unblock()
{
    ; // empty for profiler
}

void 
psmi_profile_reblock(int did_no_progress)
{
    ; // empty for profiler
}
#endif

