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

#ifndef _IPS_PROTO_PARAMS_H
#define _IPS_PROTO_PARAMS_H

/* Packet header formats */
#define CRC_SIZE_IN_BYTES 4
#define PCB_SIZE_IN_BYTES 8
#define LRH_VL_SHIFT 12
#define BTH_OPCODE_SHIFT 24
#define BTH_EXTRA_BYTE_SHIFT 20
#define BTH_BECN_SHIFT 30
#define BTH_FECN_SHIFT 31
#define BYTE2WORD_SHIFT 2
#define LOWER_24_BITS 0xFFFFFF
#define LOWER_16_BITS 0xFFFF
#define LOWER_8_BITS 0xFF
#define MAX_VL_SUPPORTED 8
#define PSM_CRC_SIZE_IN_BYTES 8 /* Change in ipath_user.h as well */
#define PSM_CACHE_LINE_BYTES 64
#define PSM_FLOW_CREDITS 64

#ifndef BITS_PER_BYTE
#  define BITS_PER_BYTE 8
#endif

/* Send retransmission */
#define IPS_PROTO_SPIO_RETRY_US_DEFAULT	2    /* in uS */

#define IPS_PROTO_ERRCHK_MS_MIN_DEFAULT	8     /* in millisecs */
#define IPS_PROTO_ERRCHK_MS_MAX_DEFAULT	32    /* in millisecs */
#define IPS_PROTO_ERRCHK_FACTOR_DEFAULT 2
#define PSM_TID_TIMEOUT_DEFAULT "8:32:2" /* update from above params */

#define IPS_HDR_TID(p_hdr)				    \
	((__le32_to_cpu((p_hdr)->iph.ver_context_tid_offset) >> \
	  INFINIPATH_I_TID_SHIFT) & INFINIPATH_I_TID_MASK)

/* time conversion macros */
#define us_2_cycles(us) nanosecs_to_cycles(1000ULL*(us))
#define ms_2_cycles(ms)  nanosecs_to_cycles(1000000ULL*(ms))
#define sec_2_cycles(sec) nanosecs_to_cycles(1000000000ULL*(sec))

/* Per-flow flags */
#define IPS_FLOW_FLAG_NAK_SEND	    0x01
#define IPS_FLOW_FLAG_WRITEV	    0x02
#define IPS_FLOW_FLAG_PENDING_ACK   0x04
#define IPS_FLOW_FLAG_GEN_BECN      0x08
#define IPS_FLOW_FLAG_CONGESTED     0x10
#define IPS_FLOW_FLAG_PENDING_NAK   0x20

/* per-ipsaddr Flags (sess is ipsaddr) */
#define SESS_FLAG_HAS_RCVTHREAD	    0x2
#define SESS_FLAG_LOCK_SESS	    0x4
#define SESS_FLAG_HAS_FLOWID	    0x8

/* tid session expected send flags  */
#define EXP_SEND_FLAG_CLEAR_ALL 0x00
#define EXP_SEND_FLAG_FREE_TIDS 0x01

#define TIMEOUT_INFINITE 0xFFFFFFFFFFFFFFFFULL /* 64 bit all-one's  */

/* ips_scb_t flags, powers of 2, and disjoint from SEND_FLAG_* values.
 * Only the lower 8 bytes are wire-protocol options */
#define IPS_SEND_FLAG_NONE		0x00
// Unused -- future use maybe.
//#define IPS_SEND_FLAG_ACK_REQ_INTR	0x02	/* request ack with intr */
#define IPS_SEND_FLAG_ACK_REQ		0x04	/* request ack (normal) */
#define IPS_SEND_FLAG_UNALIGNED_DATA	0x08	/* unaligned data in hdr */
#define IPS_SEND_FLAG_HAS_CKSUM         0x10    /* Has checksum */
#define IPS_SEND_FLAG_EXPECTED_DONE     0x20    /* Last expected packet */
#define IPS_SEND_FLAG_CCA_BECN          0x40    /* BECN bit for congestion */
#define IPS_SEND_FLAG_PROTO_OPTS	0xff

#define IPS_SEND_FLAG_PENDING		0x0100
#define IPS_SEND_FLAG_PERSISTENT	0x0200 
#define IPS_SEND_FLAG_INTR		0x0400
#define IPS_SEND_FLAG_WAIT_SDMA		0x0800
#define IPS_SEND_FLAG_HDR_SUPPRESS      0x1000

#define IPS_PROTO_FLAG_MQ_ENVELOPE_SDMA	0x01
#define IPS_PROTO_FLAG_MQ_EAGER_SDMA	0x02
#define IPS_PROTO_FLAG_MQ_EXPECTED_SDMA	0x04
#define IPS_PROTO_FLAG_MQ_MASK		0x0f /* contains all MQ proto flags */
#define IPS_PROTO_FLAG_CTRL_SDMA	0x10

/* Alias for use send dma for everything */
#define IPS_PROTO_FLAGS_ALL_SDMA	0x17

#define IPS_PROTO_FLAG_CKSUM            0x20
/* Coalesced ACKs (On by default) */
#define IPS_PROTO_FLAG_COALESCE_ACKS    0x80

/* Use Path Record query (off by default) */
#define IPS_PROTO_FLAG_QUERY_PATH_REC   0x100

/* Path selection policies:
 * 
 * (a) Adaptive - Dynamically determine the least loaded paths using various
 * feedback mechanism - Completion time via ACKs, NAKs, CCA using BECNs.
 *
 * (b) Static schemes  -
 *     (i) static_src  - Use path keyed off source context
 *    (ii) static_dest - Use path keyed off destination context
 *   (iii) static_base - Use only the base lid path - default till Oct'09.
 *
 * The default is adaptive. If a zero lmc network is used then there exists
 * just one path between endpoints the (b)(iii) case above.
 *
 */

#define IPS_PROTO_FLAG_PPOLICY_ADAPTIVE 0x200
#define IPS_PROTO_FLAG_PPOLICY_STATIC_SRC 0x400
#define IPS_PROTO_FLAG_PPOLICY_STATIC_DST 0x800
#define IPS_PROTO_FLAG_PPOLICY_STATIC_BASE 0x1000

/* All static policies */
#define IPS_PROTO_FLAG_PPOLICY_STATIC 0x1c00

/* IBTA CCA Protocol support */
#define IPS_PROTO_FLAG_CCA 0x2000

/* By default, we use dma in eager (based on PSM_MQ_EAGER_SDMA_SZ) and
 * always use it in expected.
 */
#define IPS_PROTO_FLAGS_DEFAULT		(IPS_PROTO_FLAG_MQ_EAGER_SDMA | \
					 IPS_PROTO_FLAG_MQ_EXPECTED_SDMA | \
					 IPS_PROTO_FLAG_COALESCE_ACKS)

#define IPS_PROTOEXP_FLAG_ENABLED	0x01 /* default */
//#define IPS_PROTOEXP_FLAG_NAKOPT	0x02 /* *not* default, broken */
#define IPS_PROTOEXP_FLAG_TID_DEBUG	0x04 /* *not* default */
#define IPS_PROTOEXP_FLAG_HDR_SUPP      0x08 /* Header suppression enabled */

#define IPS_PROTOEXP_FLAGS_DEFAULT	(IPS_PROTOEXP_FLAG_ENABLED | \
					 IPS_PROTOEXP_FLAG_HDR_SUPP)

/* We have to get an MTU of at least 2K, or else this breaks some assumptions
 * in the packets that handle tid descriptors
 */
#define IPS_PROTOEXP_MIN_MTU		2048

/* Bound on the number of packets to feed to send dma at a time.  This ensures
 * we don't "disappear" in the kernel for too long.
 */
#define IPS_SDMA_MAX_SCB		32

/* Fault injection, becomes parameters to psmi_faultinj_getspec so
 * a comma-delimited list of 
 *   "spec_name", num, denom
 * Where num/denom means fault num out of every denom.
 * The defines set 'denum' and assume that num is set to 1
 *
 * These values are all defaults, each is overridable via
 * PSM_FI_<spec_name> in the environment (and yes, spec_name is in lowercase
 * *in the environment* just to minimize it appearing in the wild).  The format
 * there is <num:denom:initial_seed> so the same thing except that one can set
 * a specific seed to the random number generator.
 */
#if 1
#define IPS_FAULTINJ_DMALOST	20	/* 1 every 20 dma writev get lost */
#define IPS_FAULTINJ_PIOLOST	100	/* 1 every 100 pio writes get lost */
#define IPS_FAULTINJ_PIOBUSY	10	/* 1 every 10 pio sends get busy */
#define IPS_FAULTINJ_RECVLOST	200	/* 1 every 200 pkts dropped at recv */
#else
#define IPS_FAULTINJ_DMALOST	500	/* 1 every 500 dma writev get lost */
#define IPS_FAULTINJ_PIOLOST	3000	/* 1 every 3000 pio writes get lost */
#define IPS_FAULTINJ_PIOBUSY	100	/* 1 every 100 pio sends get busy */
#define IPS_FAULTINJ_RECVLOST	500	/* 1 every 500 pkts dropped at recv */
#endif

#endif /* _IPS_PROTO_PARAMS_H */
