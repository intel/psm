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

/* IPS - Interconnect Protocol Stack */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipserror.h>

char * ips_err_str(int ips_error)
{
    static char err_str[128];

    switch (ips_error) {
    case IPS_RC_OK:
        return "OK!";

    case IPS_RC_ERROR:
        return "general error";

    case IPS_RC_PENDING:
        return "request pending";

    case IPS_RC_EXIST:
        return "entry exist";

    case IPS_RC_MAX_ENTRIES_EXCEEDED:
        return "max entries has been exceeded";

    case IPS_RC_NOT_ENOUGH_BUFFERS:
        return "not enough buffers to complete request";

    case IPS_RC_NO_FREE_MEM:
        return "no free memory";

    case IPS_RC_NAME_LOOKUP_FAILED:
        return "name lookup failed";

    case IPS_RC_PARAM_ERROR:
        return "invalid parameter";

    case IPS_RC_UNKNOWN_DEVICE:
        return "unknown device";

    case IPS_RC_DEVICE_INIT_FAILED:
        return "device init failed";

    case IPS_RC_DATA_TRUNCATED:
        return "data truncated";

    case IPS_RC_INVALID_RANK:
        return "invalid rank";

    case IPS_RC_INVALID_OPCODE:
        return "invalid op code";

    case IPS_RC_PEER_NOT_READY:
        return "peer is not ready";

    case IPS_RC_PEER_CLOSED :
        return "peer is closed";

    case IPS_RC_DEST_EQUAL_LOCAL_RANK:
        return "src and dest rank is equal";

    case IPS_RC_DEVICE_ERROR:
        return "InfiniPath hardware not found, hardware problem, or disabled";

    case IPS_RC_NETWORK_DOWN:
        return "The link is down";

    case IPS_RC_NOT_ENOUGH_FREE_TIDS:
        return "Not enough free TIDS to complete request";

    case IPS_RC_NO_RESOURCE_AVAILABLE:
        return "Internal resources exhausted";

    case IPS_RC_HW_UPDATE_FAILED:
        return "Failed TID update for rendevous, allocation problem";

    case IPS_RC_PARTITION_ERROR:
        return "One or more nodes is on a different partition";

    case IPS_RC_RUN_ERROR:
        return "One or more nodes is still running the previous job";

    case IPS_RC_ALREADY_OPEN:
        return "Open/init has already been called";

    case IPS_RC_WAS_CLOSED:
        return "Close has already been called";

    case IPS_RC_DEST_EQUAL_LOCAL_LID:
        return "src and dest LID is equal";

    case IPS_RC_BUFFER_ALIGMENT_ERROR:
        return "Buffer start address is not 32 bit aligned";

    case IPS_RC_LENGTH_ALIGMENT_ERROR:
        return "Buffer length is not a whole # of 32 bit words";

    case IPS_RC_INVALID_DATA_LENGTH:
        return "invalid data length";

    case IPS_RC_BUSY:
        return "Device is busy";

    case IPS_RC_INIT_TIMEOUT_EXPIRED:
        return "Could not connect to other nodes";

    case IPS_RC_NO_PORTS_AVAILABLE:
        return "All InfiniPath ports are in use.";

    /* Performance Counters codes */
    case IPS_RCPERF_INIT_FAILED:
         return "Initialization of performance counters failed";

    case IPS_RCPERF_EVENT_SETUP_FAILED:
         return "Setting performance counter events failed";

    case IPS_RCPERF_REG_DEFAULT_SET:
         return "Default event set for one of the counters";

    case IPS_RCPERF_UNSUPPORTED_CPU:
         return "This CPU type is not supported";

    case IPS_RCPERF_REG_GET_FAILED:
         return "Failed to get register value for event";

    case IPS_RCPERF_SET_EVENT_STR_FAILED:
         return "Failed to find event description";

    case IPS_RCPERF_INVALID_REGISTER:
         return "Register index out of range of available counters";

    case IPS_RC_SYSERR: // we hope errno hasn't changed since this was set...
        snprintf(err_str, sizeof err_str, "System error: %s", strerror(errno));
        return err_str;

    default:
        snprintf(err_str, sizeof err_str, "Error code %i: <no interpretation>", ips_error);
        return err_str;
    }
}
