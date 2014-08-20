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

#define __USE_GNU
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>

#include "ipath_user.h"

#define SYSLOG_MAXLEN	512

extern char *__ipath_mylabel;

void 
ipath_vsyslog(const char *prefix, int to_console, int level, 
	     const char *format, va_list ap)
{
    char logprefix[SYSLOG_MAXLEN];

    if (to_console) {
	char hostname[80];
	va_list ap_cons;
	va_copy(ap_cons, ap);
	size_t len = strlen(format);
	gethostname(hostname, sizeof hostname);
	hostname[sizeof hostname - 1] = '\0';

	if (__ipath_mylabel)
	    fprintf(stderr, "%s", __ipath_mylabel);
	else
	    fprintf(stderr, "%s: ", hostname);

	vfprintf(stderr, format, ap_cons);
	if (format[len] != '\n')
	    fprintf(stderr, "\n");
	fflush(stderr);
	va_end(ap_cons);
    }

    (void)snprintf(logprefix, sizeof(logprefix), 
	  "(ipath/%s)[%d]: %s", prefix ? prefix : "ipath", (int) getpid(),
	  format);

    vsyslog(level | LOG_USER, logprefix, ap);

    return;
}

void 
ipath_syslog(const char *prefix, int to_console, int level, 
	     const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    ipath_vsyslog(prefix, to_console, level, format, ap);
    va_end(ap);
}

