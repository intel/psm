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

#ifndef __IPS_SUBPORT_H
#define __IPS_SUBPORT_H

#include "psm_user.h"
#include "ips_recvhdrq.h"
#include "ips_writehdrq.h"

/* This data structure is allocated in ureg page of each subport process */

struct ips_subport_ureg {
    pthread_spinlock_t port_lock;		/* only used in master ureg */
    struct ips_recvhdrq_state recvq_state;	/* only used in master ureg */
    struct ips_writehdrq_state writeq_state;	/* used in all ureg pages */
};

psm_error_t
ips_subport_ureg_get(ptl_t *ptl, const psmi_port_t *port,
                     struct ips_subport_ureg **uregp);

psm_error_t
ips_subport_ureg_initialize(ptl_t *ptl, uint32_t subport,
                            struct ips_subport_ureg *uregp);

#endif
