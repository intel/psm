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

#ifndef _IPS_PROTO_INTERNAL_H
#define _IPS_PROTO_INTERNAL_H

#include "ips_proto_header.h"
#include "ips_expected_proto.h"
#include "ips_proto_help.h"

/*
 * Connect protocol.
 *
 * On receive, handled by upcalling into the connect interface.
 * On send, handled by ips_proto by having connect compose the message.
 */
psm_error_t ips_proto_process_connect(struct ips_proto *proto, psm_epid_t epid, 
				      uint8_t opcode,
				      struct ips_message_header *p_hdr, 
				      void *payload, uint32_t paylen);
int ips_proto_build_connect_message(struct ips_proto *proto, 
				    struct ips_proto_ctrl_message *msg, 
			            ips_epaddr_t *ptladdr, uint8_t opcode, 
				    void *payload);

psm_error_t ips_proto_timer_ack_callback(struct psmi_timer *, uint64_t);
psm_error_t ips_proto_timer_send_callback(struct psmi_timer *, uint64_t);
psm_error_t ips_proto_timer_ctrlq_callback(struct psmi_timer *, uint64_t);
psm_error_t ips_proto_timer_pendq_callback(struct psmi_timer *, uint64_t);
psm_error_t ips_cca_adjust_rate(ips_path_rec_t *path_rec, int cct_increment);
psm_error_t ips_cca_timer_callback(struct psmi_timer *current_timer, uint64_t current);
void
ips_proto_rv_scbavail_callback(struct ips_scbctrl *scbc, void *context);

psm_error_t ips_proto_recv_init(struct ips_proto *proto);
psm_error_t ips_proto_recv_fini(struct ips_proto *proto);

#define IPS_PROTO_MQ_CTS_MSGSIZE    64

#endif /* _IPS_PROTO_INTERNAL_H */
