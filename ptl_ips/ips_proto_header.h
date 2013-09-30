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

#ifndef _IPS_PROTO_HEADER_H
#define _IPS_PROTO_HEADER_H

/* The actual size of the message header is determined by three paramters:
 * IPS_HEADER_QUEUE_IWORDS (fixed at 5 by hardware)
 *    InfiniBand words contain LRH and BTH
 * IPS_HEADER_QUEUE_HWORDS (fixed at 7 by ips protocol)
 *    IPS header words contain ips-protocol-specific data
 * IPS_HEADER_QUEUE_UWORDS (variable sized, from 2 to 32)
 *    Size depends on the target.  The connect protocol always assumes 2
 *    uwords, and post-connect communication will use a length determined at
 *    connect time.
 *
 * The header message size is determined to as IWORDS + HWORDS + UWORDS
 */
struct ips_message_header {
	__be16 lrh[4];
	__be32 bth[3];
	/* fields below this point are in host byte order */
	struct ipath_header iph;
	__u8 sub_opcode;
	__u8 flags;
	__u16 commidx;
	/* 24 bits. The upper 8 bit is available for other use */
	union {
	  /* NOTE: always access src_context with HEADER_SRCCONTEXT macros.
	   * actual context value is split to preserve wire compatibility */
	  struct {
	    unsigned ack_seq_num:24;
	    unsigned src_context:4;
	    unsigned src_subcontext:2;
	    unsigned src_context_ext:2;
	  };
	  __u32 ack_seq_num_org;
	};
	__u8 flowid;
	__u8 hdr_dlen;	/* data length in header */

        union {
	  struct {
	    __u16 mqhdr : 14;    /* PSM matched queues */
	    __u16 dst_subcontext : 2; /* Destination subcontext */
	  };
	  struct {    /* for PSM Active Messages */
	    __u16 amhdr_hidx  : 8; 
	    __u16 amhdr_nargs : 3;
	    __u16 amhdr_flags : 3; /* Reduced from 5 bits previously */
	  };
	  __u16 mqhdr_org;
	};
	/* Access to uwords  */
	union {
	    ptl_arg_t	hdr_data[2];
	    ptl_arg_t	data[0];
	    __u32	uwords[4];
	};
};

#define IPS_HEADER_QUEUE_IWORDS	5   /* LRH+BTH (fixed) */

/* These two define the same thing, but they exist in sizeof and as a constant
 * for sanity checking */
#define IPS_HEADER_QUEUE_IPS_PROTOCOL_WORDS 5
#define IPS_HEADER_QUEUE_HWORDS		    5

/* Min is used by the connect protocol.
 * Max bounds the size of the preallocated communication headers.
 * Req is the current desired receive header queue size.  The actual size is
 *     returned after userinit. */
#define IPS_HEADER_QUEUE_UWORDS_MIN 4
#define IPS_HEADER_QUEUE_UWORDS_MAX 32
#define IPS_HEADER_QUEUE_UWORDS_REQ 12

#define IPS_HEADER_QUEUE_PBC_WORDS  2

/* Figure out "real" size of ips_message_header given the size of the receive
 * header queue entry */
/* Actual message length includes iwords */
#define IPS_HEADER_MSGLEN(rcvhdrq_size)       \
	((IPS_HEADER_QUEUE_IWORDS+(rcvhdrq_size))<<2)

/* Old define */
#define IPS_HEADER_QUEUE_WORDS	\
	((sizeof(struct ips_message_header) - \
	  offsetof(struct ips_message_header, iph)) >> 2)

/* sub OpCodes - ips  */
#define OPCODE_SEQ_DATA 0x01
#define OPCODE_SEQ_CTRL 0x02

#define OPCODE_SEQ_MQ_DATA    0x03
#define OPCODE_SEQ_MQ_CTRL    0x04
#define OPCODE_SEQ_MQ_HDR     0x05
#define OPCODE_SEQ_MQ_EXPTID  0x06
#define OPCODE_SEQ_MQ_EXPTID_UNALIGNED 0x07

#define OPCODE_ACK 0x10
#define OPCODE_NAK 0x11

#define OPCODE_ERR_CHK_OLD 0x20
#define OPCODE_ERR_CHK_PLS 0x21
#define OPCODE_ERR_CHK 0x22       /* error check with ip + pid */
#define OPCODE_ERR_CHK_BAD 0x23   /* error check out of context */
#define OPCODE_ERR_CHK_GEN 0x24   /* TF protocol error check */

/* Pre-2.0 startup */
#define OPCODE_STARTUP 0x30
#define OPCODE_STARTUP_ACK 0x31
#define OPCODE_STARTUP_NAK 0x32
#define OPCODE_STARTUP_EXT 0x34
#define OPCODE_STARTUP_ACK_EXT 0x35
#define OPCODE_STARTUP_NAK_EXT 0x36
/* 2.0+ startup */
#define OPCODE_CONNECT_REQUEST 0x60
#define OPCODE_CONNECT_REPLY   0x61
#define OPCODE_DISCONNECT_REQUEST 0x62
#define OPCODE_DISCONNECT_REPLY   0x63

#define OPCODE_AM_REQUEST   0x70
#define OPCODE_AM_REPLY   0x71
#define OPCODE_AM_REQUEST_NOREPLY 0x72

#define OPCODE_TIDS_RELEASE 0x40
#define OPCODE_TIDS_RELEASE_CONFIRM 0x41
#define OPCODE_TIDS_GRANT 0x42
#define OPCODE_TIDS_GRANT_ACK 0x43

#define OPCODE_CLOSE 0x50
#define OPCODE_CLOSE_ACK 0x51

/* Explicit CCA related messages */
#define OPCODE_FLOW_CCA_BECN 0x80

/*
 * like OPCODE_CLOSE, but no complaint if other side has already closed.
 * Used when doing abort(), MPI_Abort(), etc.
 */
#define OPCODE_ABORT 0x52

#endif /* _IPS_PROTO_HEADER_H */
