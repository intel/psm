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

#define PSMI_NOLOG  -1

struct psm_error_token
{
    psm_ep_t	ep;
    psm_error_t	error;
    char	err_string[PSM_ERRSTRING_MAXLEN];
};

static
psm_error_t
psmi_errhandler_noop(psm_ep_t ep, const psm_error_t err, 
		     const char *error_string, psm_error_token_t token)
{
    return err;
}

static
psm_error_t
psmi_errhandler_psm(psm_ep_t ep, 
			const psm_error_t err, 
			const char *error_string, 
			psm_error_token_t token)
{
    /* we want the error to be seen through ssh, etc., so we flush and then
     * sleep a bit.   Not perfect, but not doing so means it almost never
     * gets seen. */
    fprintf(stderr, "%s%s\n", ipath_get_mylabel(), token->err_string);
    fflush(stdout);
    fflush(stderr);

    /* XXX Eventually, this will hook up to a connection manager, and we'll
     * issue an upcall into the connection manager at shutdown time */
    sleep(3);

    /* We use this "special" ep internally to handle internal errors that are 
     * triggered from within code that is not expected to return to the user.
     * Errors of this sort on not expected to be handled by users and always
     * mean we have an internal PSM bug. */ 
    if (err == PSM_INTERNAL_ERR)
	abort();
    else
	exit(-1);
}

psm_ep_errhandler_t psmi_errhandler_global = psmi_errhandler_noop;

psm_error_t
__psm_error_defer(psm_error_token_t token)
{
    return psmi_errhandler_psm(token->ep, token->error, token->err_string, token);
}
PSMI_API_DECL(psm_error_defer)

psm_error_t
__psm_error_register_handler(psm_ep_t ep, const psm_ep_errhandler_t errhandler)
{
    psm_ep_errhandler_t *errh;
    if (ep == NULL)
	errh = &psmi_errhandler_global;
    else
	errh = &ep->errh;

    if (errhandler == PSM_ERRHANDLER_PSM_HANDLER)
	*errh = psmi_errhandler_psm;
    else if (errhandler == PSM_ERRHANDLER_NO_HANDLER)
	*errh = psmi_errhandler_noop;
    else
	*errh = errhandler;

    return PSM_OK;
}
PSMI_API_DECL(psm_error_register_handler)

psm_error_t
psmi_handle_error(psm_ep_t ep, psm_error_t error, const char *buf, ...) 
{
    va_list argptr;
    int syslog_level;
    int console_print = 0;
    psm_error_t newerr;
    struct psm_error_token token;
    char *c, fullmsg[PSM_ERRSTRING_MAXLEN];
    token.error = error;
    snprintf(fullmsg, PSM_ERRSTRING_MAXLEN-1, "%s", buf);
    fullmsg[PSM_ERRSTRING_MAXLEN-1] = '\0';
    va_start(argptr, buf);
      vsnprintf(token.err_string, PSM_ERRSTRING_MAXLEN-1, fullmsg, argptr);
    va_end(argptr);
    token.err_string[PSM_ERRSTRING_MAXLEN-1] = '\0';

    /* Unless the user has set PSM_NO_VERBOSE_ERRORS, always print errors to
     * console */
    c = getenv("PSM_NO_VERBOSE_ERRORS");
    console_print = 0;
    if (ep == PSMI_EP_LOGEVENT)
	console_print = 1;
    else if (!c || *c == '\0') { /* no desire to prevent verbose errors */
	/* Remove the console print if we're internally handling the error */
	if (ep == PSMI_EP_NORETURN)
	    console_print = 0;
	else if (ep == NULL && psmi_errhandler_global != psmi_errhandler_psm) 
	    console_print = 1;
	else if (ep != NULL && ep->errh != psmi_errhandler_psm)
	    console_print = 1;
    }

    /* Before we let the user even handle the error, send to syslog */
    syslog_level = psmi_error_syslog_level(error);
    if (syslog_level != PSMI_NOLOG || ep == PSMI_EP_LOGEVENT) 
	psmi_syslog(ep, console_print, 
		    ep == PSMI_EP_LOGEVENT ? LOG_NOTICE : syslog_level, 
		    "%s (err=%d)",
		    token.err_string, error);

    if (ep == PSMI_EP_LOGEVENT) /* we're just logging */
	newerr = PSM_OK;
    else if (ep == PSMI_EP_NORETURN)
        newerr = psmi_errhandler_psm(NULL, error, token.err_string, &token);
    else if (ep == NULL)
	newerr = psmi_errhandler_global(NULL, error, token.err_string, &token); 
    else
	newerr = ep->errh(ep, error, token.err_string, &token);

    return newerr;
}

/* Returns the "worst" error out of errA and errB */
psm_error_t
psmi_error_cmp(psm_error_t errA, psm_error_t errB)
{
#define _PSMI_ERR_IS(err) if (errA == (err) || errB == (err)) return (err)

    /* Bad runtime or before initialization */
    _PSMI_ERR_IS(PSM_NO_MEMORY);
    _PSMI_ERR_IS(PSM_INTERNAL_ERR);
    _PSMI_ERR_IS(PSM_INIT_NOT_INIT);
    _PSMI_ERR_IS(PSM_INIT_BAD_API_VERSION);

    /* Before we cget an endpoint */
    _PSMI_ERR_IS(PSM_EP_NO_DEVICE);
    _PSMI_ERR_IS(PSM_EP_UNIT_NOT_FOUND);
    _PSMI_ERR_IS(PSM_EP_DEVICE_FAILURE);
    _PSMI_ERR_IS(PSM_EP_NO_PORTS_AVAIL);
    _PSMI_ERR_IS(PSM_TOO_MANY_ENDPOINTS);

    /* As we open/close the endpoint */
    _PSMI_ERR_IS(PSM_EP_NO_NETWORK);
    _PSMI_ERR_IS(PSM_SHMEM_SEGMENT_ERR);
    _PSMI_ERR_IS(PSM_EP_CLOSE_TIMEOUT);
    _PSMI_ERR_IS(PSM_EP_INVALID_UUID_KEY);
    _PSMI_ERR_IS(PSM_EP_NO_RESOURCES);

    /* In connect phase */
    _PSMI_ERR_IS(PSM_EPID_NETWORK_ERROR);
    _PSMI_ERR_IS(PSM_EPID_INVALID_NODE);
    _PSMI_ERR_IS(PSM_EPID_INVALID_CONNECT);
    _PSMI_ERR_IS(PSM_EPID_INVALID_PKEY);
    _PSMI_ERR_IS(PSM_EPID_INVALID_VERSION);
    _PSMI_ERR_IS(PSM_EPID_INVALID_UUID_KEY);
    _PSMI_ERR_IS(PSM_EPID_INVALID_MTU);

    /* Timeout if nothing else */
    _PSMI_ERR_IS(PSM_TIMEOUT);

    /* Last resort */
    return max(errA,errB);
}

struct psmi_error_item {
    int	syslog_level;
    const char *error_string;
};

static
struct psmi_error_item
psmi_error_items[] = {
    { PSMI_NOLOG, "Success" }, /*  PSM_OK = 0, */
    { PSMI_NOLOG, "No events were progressed in psm_poll" }, /* PSM_OK_NO_PROGRESS = 1 */
    { PSMI_NOLOG, "unknown 2" },
    { PSMI_NOLOG, "Error in a function parameter" }, /* PSM_PARAM_ERR = 3 */
    { LOG_CRIT  , "Ran out of memory" }, /* PSM_NO_MEMORY = 4 */
    { PSMI_NOLOG, "PSM has not been initialized by psm_init" }, /* PSM_INIT_NOT_INIT = 5 */ 
    { LOG_INFO  , "API version passed in psm_init is incompatible" }, /* PSM_INIT_BAD_API_VERSION = 6 */
    { PSMI_NOLOG, "PSM Could not set affinity" }, /* PSM_NO_AFFINITY = 7 */
    { LOG_ALERT , "PSM Unresolved internal error" }, /* PSM_INTERNAL_ERR = 8 */
    { LOG_CRIT  , "PSM could not set up shared memory segment" }, /* PSM_SHMEM_SEGMENT_ERR = 9 */
    { PSMI_NOLOG, "PSM option is a read-only option" }, /* PSM_OPT_READONLY = 10 */
    { PSMI_NOLOG, "Operation timed out" }, /* PSM_TIMEOUT = 11 */
    { LOG_INFO  , "Exceeded supported amount of endpoints" }, 
		/* PSM_TOO_MANY_ENDPOINTS = 12 */
    { PSMI_NOLOG, "PSM is in the finalized state" }, /* PSM_IS_FINALIZED = 13 */
    { PSMI_NOLOG, "unknown 14" },
    { PSMI_NOLOG, "unknown 15" },
    { PSMI_NOLOG, "unknown 16" },
    { PSMI_NOLOG, "unknown 17" },
    { PSMI_NOLOG, "unknown 18" },
    { PSMI_NOLOG, "unknown 19" },
    { PSMI_NOLOG, "Endpoint was closed" }, /* PSM_EP_WAS_CLOSED = 20 */ 
    { LOG_ALERT , "PSM Could not find an InfiniPath Unit" }, /* PSM_EP_NO_DEVICE = 21 */
    { PSMI_NOLOG, "User passed a bad unit number" }, /* PSM_EP_UNIT_NOT_FOUND = 22 */
    { LOG_ALERT , "Failure in initializing endpoint" }, /* PSM_EP_DEVICE_FAILURE = 23 */ 
    { PSMI_NOLOG, "Error closing the endpoing error" }, /* PSM_EP_CLOSE_TIMEOUT = 24 */  
    { PSMI_NOLOG, "No free contexts could be obtained" }, /* PSM_EP_NO_PORTS_AVAIL = 25 */ 
    { LOG_ALERT , "Could not detect network connectivity" }, /* PSM_EP_NO_NETWORK = 26 */  
    { LOG_INFO  , "Invalid Unique job-wide UUID Key" }, /* PSM_EP_INVALID_UUID_KEY = 27 */
    { LOG_INFO  , "Out of endpoint resources" }, /* PSM_EP_NO_RESOURCES = 28 */
    { PSMI_NOLOG, "unknown 29" },
    { PSMI_NOLOG, "unknown 30" },
    { PSMI_NOLOG, "unknown 31" },
    { PSMI_NOLOG, "unknown 32" },
    { PSMI_NOLOG, "unknown 33" },
    { PSMI_NOLOG, "unknown 34" },
    { PSMI_NOLOG, "unknown 35" },
    { PSMI_NOLOG, "unknown 36" },
    { PSMI_NOLOG, "unknown 37" },
    { PSMI_NOLOG, "unknown 38" },
    { PSMI_NOLOG, "unknown 39" },
    { PSMI_NOLOG, "Unknown/unresolved connection status (other errors occurred)" }, /* PSM_EPID_UNKNOWN = 40 */
    { PSMI_NOLOG, "Endpoint could not be reached" }, /* PSM_EPID_UNREACHABLE = 41 */
    { PSMI_NOLOG, "unknown 42" },
    { LOG_CRIT  , "Invalid node (mismatch in bit width 32/64 or byte order)" }, /* PSM_EPID_INVALID_NODE = 43 */
    { LOG_CRIT  , "Invalid MTU" }, /* PSM_EPID_INVALID_MTU =  44 */
    { PSMI_NOLOG, "UUID key mismatch" },  /* PSM_EPID_INVALID_UUID_KEY = 45 */
    { LOG_ERR   , "Incompatible PSM version" }, /* PSM_EPID_INVALID_VERSION = 46 */
    { LOG_CRIT  , "Connect received garbled connection information" }, /* PSM_EPID_INVALID_CONNECT = 47 */
    { PSMI_NOLOG, "Endpoint was already connected" }, /* PSM_EPID_ALREADY_CONNECTED = 48 */
    { LOG_CRIT  , "Two or more endpoints have the same network id (LID)" }, /* PSM_EPID_NETWORK_ERROR = 49 */
    { LOG_CRIT,   "Endpoint provided incompatible Partition Key" },
    { LOG_CRIT,   "Unable to resolve network path. Is the SM running?" },
    { PSMI_NOLOG, "unknown 51" },
    { PSMI_NOLOG, "unknown 52" },
    { PSMI_NOLOG, "unknown 53" },
    { PSMI_NOLOG, "unknown 54" },
    { PSMI_NOLOG, "unknown 55" },
    { PSMI_NOLOG, "unknown 56" },
    { PSMI_NOLOG, "unknown 57" },
    { PSMI_NOLOG, "unknown 58" },
    { PSMI_NOLOG, "unknown 59" },
    { PSMI_NOLOG, "MQ Non-blocking request is incomplete" }, /* PSM_MQ_NO_COMPLETIONS = 60 */
    { PSMI_NOLOG, "MQ Message has been truncated at the receiver" }, /* PSM_MQ_TRUNCATION = 61 */
    { PSMI_NOLOG, "unknown 62" },
    { PSMI_NOLOG, "unknown 63" },
    { PSMI_NOLOG, "unknown 64" },
    { PSMI_NOLOG, "unknown 65" },
    { PSMI_NOLOG, "unknown 66" },
    { PSMI_NOLOG, "unknown 67" },
    { PSMI_NOLOG, "unknown 68" },
    { PSMI_NOLOG, "unknown 69" },
    { PSMI_NOLOG, "Invalid AM reply" },
    { PSMI_NOLOG, "unknown 71" },
    { PSMI_NOLOG, "unknown 72" },
    { PSMI_NOLOG, "unknown 73" },
    { PSMI_NOLOG, "unknown 74" },
    { PSMI_NOLOG, "unknown 75" },
    { PSMI_NOLOG, "unknown 76" },
    { PSMI_NOLOG, "unknown 77" },
    { PSMI_NOLOG, "unknown 78" },
    { PSMI_NOLOG, "unknown 79" },
    { PSMI_NOLOG, "unknown 80" },
};

const char *
__psm_error_get_string(psm_error_t error)
{
    if (error >= PSM_ERROR_LAST)
	return "unknown";
    else
	return psmi_error_items[error].error_string;
}
PSMI_API_DECL(psm_error_get_string)

int
psmi_error_syslog_level(psm_error_t error)
{
    if (error >= PSM_ERROR_LAST)
	return PSMI_NOLOG;
    else
	return psmi_error_items[error].syslog_level;
}

