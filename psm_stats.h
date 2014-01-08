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

#ifndef _PSMI_IN_USER_H
#error psm_stats.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef _PSM_STATS_H
#define _PSM_STATS_H

#include "mpspawn_stats.h"

#define PSMI_STATSTYPE_MQ	    0x00001
#define PSMI_STATSTYPE_RCVTHREAD    0x00100	/* num_wakups, ratio, etc. */
#define PSMI_STATSTYPE_IPSPROTO	    0x00200	/* acks,naks,err_chks */
#define PSMI_STATSTYPE_TIDS	    0x00400
#define PSMI_STATSTYPE_MEMORY	    0x01000
#define PSMI_STATSTYPE_IPATH	    (PSMI_STATSTYPE_RCVTHREAD|	\
				     PSMI_STATSTYPE_IPSPROTO |  \
				     PSMI_STATSTYPE_MEMORY |  \
				     PSMI_STATSTYPE_TIDS)
#define PSMI_STATSTYPE_P2P	    0x00800	/* ep-to-ep details */
#define PSMI_STATSTYPE_DEVCOUNTERS  0x10000
#define PSMI_STATSTYPE_DEVSTATS	    0x20000
#define PSMI_STATSTYPE_ALL	    0xfffff
#define _PSMI_STATSTYPE_DEVMASK	    0xf0000

/* Used to determine how many stats in static array decl. */
#define PSMI_STATS_HOWMANY(entries)	    \
	    (sizeof(entries)/sizeof(entries[0]))

#define PSMI_STATS_NO_HEADING    NULL

#define PSMI_STATS_DECL(_desc,_flags,_getfn,_val)   \
	{  .desc  = _desc,			    \
	   .flags = _flags,			    \
	   .getfn = _getfn,			    \
	   .u.val = _val,			    \
	}

#define PSMI_STATS_DECLU64(_desc,_val)					  \
	    PSMI_STATS_DECL(_desc,					  \
		MPSPAWN_STATS_REDUCTION_ALL | MPSPAWN_STATS_SKIP_IF_ZERO, \
		NULL,							  \
		_val)

struct psmi_stats_entry {
    const char *desc;
    uint16_t	flags;
    uint64_t	(*getfn)(void *context); /* optional fn ptr to get value */
    union {
	uint64_t    *val;  /* where value is stored if getfn is NULL */
	uint64_t    off;   /* of offset if that makes more sense */
    } u;
};

/*
 * Copy the array of entries and keep track of the context
 */
psm_error_t
psmi_stats_register_type(const char *heading, 
			 uint32_t statstype,
			 const struct psmi_stats_entry *entries,
			 int num_entries,
			 void *context);

psm_error_t
psmi_stats_deregister_all(void);

#endif /* PSM_STATS_H */
