/*
 * Copyright (c) 2006-2010. QLogic Corporation. All rights reserved.
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

#ifndef _PSM_NOSHIP_H_
#define _PSM_NOSHIP_H_

#include "psm.h"

typedef struct psm_epinfo {
  psm_ep_t ep;
  psm_epid_t epid;
  psm_uuid_t uuid;
  char uuid_str[64];
} psm_epinfo_t;

typedef struct psm_epconn {
  psm_epaddr_t addr;
  psm_ep_t ep;
  psm_mq_t mq;
} psm_epconn_t;

psm_error_t 
psm_ep_query (int *num_of_epinfo, psm_epinfo_t *array_of_epinfo);

psm_error_t 
psm_ep_epid_lookup (psm_epid_t epid, psm_epconn_t *epconn);
#endif
