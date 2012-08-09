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

#ifndef _IPATH_UDEBUG_H
#define _IPATH_UDEBUG_H

#include <stdio.h>
#include "ipath_debug.h"

extern unsigned infinipath_debug;
const char *ipath_get_unit_name(int unit);
extern char *__progname;

#if _IPATH_DEBUGGING

extern char *__ipath_mylabel;
void ipath_set_mylabel(char *);
char *ipath_get_mylabel();
extern FILE *__ipath_dbgout;

#define _IPATH_UNIT_ERROR(unit,fmt,...) \
	do { \
		_Pragma_unlikely \
		printf("%s%s: " fmt, __ipath_mylabel, __progname, \
		       ##__VA_ARGS__); \
	} while(0)

#define _IPATH_ERROR(fmt,...) \
	do { \
		_Pragma_unlikely \
		printf("%s%s: " fmt, __ipath_mylabel, __progname, \
		       ##__VA_ARGS__); \
	} while(0)

#define _IPATH_INFO(fmt,...) \
	do { \
		_Pragma_unlikely \
		if(unlikely(infinipath_debug&__IPATH_INFO))  \
			printf("%s%s: " fmt, __ipath_mylabel, __func__, \
			       ##__VA_ARGS__); \
	} while(0)

#define __IPATH_PKTDBG_ON unlikely(infinipath_debug & __IPATH_PKTDBG)

#define __IPATH_DBG_WHICH(which,fmt,...) \
	do { \
		_Pragma_unlikely \
		if(unlikely(infinipath_debug&(which))) \
			fprintf(__ipath_dbgout, "%s%s: " fmt, __ipath_mylabel, __func__, \
			       ##__VA_ARGS__); \
	} while(0)

#define __IPATH_DBG_WHICH_NOFUNC(which,fmt,...) \
	do { \
		_Pragma_unlikely \
		if(unlikely(infinipath_debug&(which))) \
			fprintf(__ipath_dbgout, "%s" fmt, __ipath_mylabel, \
			       ##__VA_ARGS__); \
	} while(0)

#define _IPATH_DBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_DBG,fmt,##__VA_ARGS__)
#define _IPATH_VDBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_VERBDBG,fmt,##__VA_ARGS__)
#define _IPATH_PDBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_PKTDBG,fmt,##__VA_ARGS__)
#define _IPATH_EPDBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_EPKTDBG,fmt,##__VA_ARGS__)
#define _IPATH_PRDBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_PROCDBG,fmt,##__VA_ARGS__)
#define _IPATH_ENVDBG(lev,fmt,...) \
	__IPATH_DBG_WHICH_NOFUNC(					    \
		(lev==0) ? __IPATH_INFO :				    \
		    (lev>1?__IPATH_ENVDBG:(__IPATH_PROCDBG|__IPATH_ENVDBG)),\
		"env " fmt,##__VA_ARGS__)
#define _IPATH_MMDBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_MMDBG,fmt,##__VA_ARGS__)
#define _IPATH_CCADBG(fmt,...) __IPATH_DBG_WHICH(__IPATH_CCADBG,fmt,##__VA_ARGS__)

#else				/* ! _IPATH_DEBUGGING */

#define _IPATH_UNIT_ERROR(unit,fmt,...) \
	do { \
		printf ("%s" fmt, "", ##__VA_ARGS__); \
	} while(0)

#define _IPATH_ERROR(fmt,...) \
	do { \
		printf ("%s" fmt, "", ##__VA_ARGS__); \
	} while(0)

#define _IPATH_INFO(fmt,...)

#define __IPATH_PKTDBG_ON 0

#define _IPATH_DBG(fmt,...)
#define _IPATH_PDBG(fmt,...)
#define _IPATH_EPDBG(fmt,...)
#define _IPATH_PRDBG(fmt,...)
#define _IPATH_VDBG(fmt,...)
#define _IPATH_MMDBG(fmt,...)
#define _IPATH_CCADBG(fmt,...)

#endif				/* _IPATH_DEBUGGING */

#endif				/* _IPATH_DEBUG_H */
