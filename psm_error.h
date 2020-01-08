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

#ifndef _PSMI_IN_USER_H
#error psm_error.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef _PSMI_ERROR_H
#define _PSMI_ERROR_H

#define PSMI_EP_NONE		    (NULL)
#define PSMI_EP_NORETURN	    ((psm_ep_t) -2)
#define PSMI_EP_LOGEVENT	    ((psm_ep_t) -3)

extern psm_ep_errhandler_t psmi_errhandler_global;

psm_error_t psmi_handle_error(psm_ep_t ep, psm_error_t error, 
			      const char *buf, ...)
	    __attribute__((format(printf, 3, 4)));

psm_error_t psmi_error_cmp(psm_error_t errA, psm_error_t errB);
int	    psmi_error_syslog_level(psm_error_t error);

#endif /* _PSMI_ERROR_H */
