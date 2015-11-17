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

#ifndef _IPATH_COMMON_H
#define _IPATH_COMMON_H

/*
 * This file contains defines, structures, etc. that are used
 * to communicate between kernel and user code.
 */

/* BEGIN_NOSHIP_TO_OPENIB */
#include <asm/types.h>
#ifndef __KERNEL__
// Pointer annotations used by the "sparse" checker tool.
#define __iomem
#include "ipath_byteorder.h"
#endif
/* END_NOSHIP_TO_OPENIB */

/* This is the IEEE-assigned OUI for QLogic Inc. InfiniPath */
#define IPATH_SRC_OUI_1 0x00
#define IPATH_SRC_OUI_2 0x11
#define IPATH_SRC_OUI_3 0x75

/* version of protocol header (known to chip also). In the long run,
 * we should be able to generate and accept a range of version numbers;
 * for now we only accept one, and it's compiled in.
 */
#define IPS_PROTO_VERSION 2

/*
 * These are compile time constants that you may want to enable or disable
 * if you are trying to debug problems with code or performance.
 * IPATH_VERBOSE_TRACING define as 1 if you want additional tracing in
 * fastpath code
 * IPATH_TRACE_REGWRITES define as 1 if you want register writes to be
 * traced in faspath code
 * _IPATH_TRACING define as 0 if you want to remove all tracing in a
 * compilation unit
 * _IPATH_DEBUGGING define as 0 if you want to remove debug prints
 */

/*
 * valid states passed to ipath_set_linkstate() user call
 */
#define IPATH_IB_LINKDOWN		0
#define IPATH_IB_LINKARM		1
#define IPATH_IB_LINKACTIVE		2
#define IPATH_IB_LINKINIT		3
#define IPATH_IB_LINKDOWN_SLEEP		4
#define IPATH_IB_LINKDOWN_DISABLE	5
#define IPATH_IB_LINK_LOOPBACK	6 /* enable local loopback */
#define IPATH_IB_LINK_EXTERNAL	7 /* normal, disable local loopback */

/*
 * These are the status bits readable (in ascii form, 64bit value)
 * from the "status" sysfs file.
 */
#define IPATH_STATUS_INITTED       0x1	/* basic initialization done */
/* Chip has been found and initted */
#define IPATH_STATUS_CHIP_PRESENT 0x20
/* IB link is at ACTIVE, usable for data traffic */
#define IPATH_STATUS_IB_READY     0x40
/* link is configured, LID, MTU, etc. have been set */
#define IPATH_STATUS_IB_CONF      0x80
/* no link established, probably no cable */
#define IPATH_STATUS_IB_NOCABLE  0x100
/* A Fatal hardware error has occurred. */
#define IPATH_STATUS_HWERROR     0x200

/*
 * The list of usermode accessible registers.  Also see Reg_* later in file.
 */
typedef enum _ipath_ureg {
	/* (RO)  DMA RcvHdr to be used next. */
	ur_rcvhdrtail = 0,
	/* (RW)  RcvHdr entry to be processed next by host. */
	ur_rcvhdrhead = 1,
	/* (RO)  Index of next Eager index to use. */
	ur_rcvegrindextail = 2,
	/* (RW)  Eager TID to be processed next */
	ur_rcvegrindexhead = 3,
	/* For internal use only; max register number (Shared contexts). */
	_IPATH_UregMax = 4,
	/* (RW) RcvTIDFlow table for expected sends in QLE73XX */
	ur_rcvtidflow = 512
} ipath_ureg;

/* bit values for spi_runtime_flags */
#define IPATH_RUNTIME_PCIE	0x2
#define IPATH_RUNTIME_FORCE_WC_ORDER	0x4
#define IPATH_RUNTIME_RCVHDR_COPY	0x8
#define IPATH_RUNTIME_MASTER	0x10
#define IPATH_RUNTIME_RCHK	0x20
#define IPATH_RUNTIME_NODMA_RTAIL 0x80
#define IPATH_RUNTIME_SPECIAL_TRIGGER 0x100
#define IPATH_RUNTIME_SDMA 0x200
#define IPATH_RUNTIME_FORCE_PIOAVAIL 0x400
#define IPATH_RUNTIME_PIO_REGSWAPPED 0x800
/*
 * MEA: below means chip expects 7322-style context/qp mapping,
 * not 7220-style. This needs work, because we actually care what
 * the remote chip uses, not what the local chip uses, other
 * than to somehow tell the remote endpoint.
 */
#define IPATH_RUNTIME_CTXT_MSB_IN_QP 0x1000
#define IPATH_RUNTIME_CTXT_REDIRECT 0x2000
#define IPATH_RUNTIME_HDRSUPP 0x4000

/*
 * This structure is returned by ipath_userinit() immediately after
 * open to get implementation-specific info, and info specific to this
 * instance.
 *
 * This struct must have explict pad fields where type sizes
 * may result in different alignments between 32 and 64 bit
 * programs, since the 64 bit * bit kernel requires the user code
 * to have matching offsets
 */
struct ipath_base_info {
	/* version of hardware, for feature checking. */
	__u32 spi_hw_version;
	/* version of software, for feature checking. */
	__u32 spi_sw_version;
	/* InfiniPath context assigned, goes into sent packets */
	__u16 spi_context;
	__u16 spi_subcontext;
	/*
	 * IB MTU, packets IB data must be less than this.
	 * The MTU is in bytes, and will be a multiple of 4 bytes.
	 */
	__u32 spi_mtu;
	/*
	 * Size of a PIO buffer in byts.  Any given packet's total size must
	 * be less than this.  Included is the starting control word, so
	 * if 2052 is returned, then total pkt size is 2048 bytes or less.
	 */
	__u32 spi_piosize;
	/* size of the TID cache in infinipath, in entries */
	__u32 spi_tidcnt;
	/* size of the TID Eager list in infinipath, in entries */
	__u32 spi_tidegrcnt;
	/* size of a single receive header queue entry in words. */
	__u32 spi_rcvhdrent_size;
	/*
	 * Count of receive header queue entries allocated.
	 * This may be less than the spu_rcvhdrcnt passed in!.
	 */
	__u32 spi_rcvhdr_cnt;

	/* per-chip and other runtime features bitmap (IPATH_RUNTIME_*) */
	__u32 spi_runtime_flags;

	/* address where receive buffer queue is mapped into */
	__u64 spi_rcvhdr_base;

	/* user program. */

	/* base address of eager TID receive buffers. */
	__u64 spi_rcv_egrbufs;

	/* Allocated by initialization code, not by protocol. */

	/*
	 * Size of each TID buffer in host memory, starting at
	 * spi_rcv_egrbufs.  The buffers are virtually contiguous.
	 */
	__u32 spi_rcv_egrbufsize;
	/*
	 * The special QP (queue pair) value that identifies an infinipath
	 * protocol packet from standard IB packets.  More, probably much
	 * more, to be added.
	 */
	__u32 spi_qpair;

	/*
	 * User register base for init code, not to be used directly by
	 * protocol or applications.  Always maps real chip register space.
	 */
         __u64 spi_uregbase;

	/*
	 * Maximum buffer size in bytes that can be used in a single TID
	 * entry (assuming the buffer is aligned to this boundary).  This is
	 * the minimum of what the hardware and software support Guaranteed
	 * to be a power of 2.
	 */
	__u32 spi_tid_maxsize;
	/*
	 * alignment of each pio send buffer (byte count
	 * to add to spi_piobufbase to get to second buffer)
	 */
	__u32 spi_pioalign;
	/*
	 * The index of the first pio buffer available to this process;
	 * needed to do lookup in spi_pioavailaddr; not added to
	 * spi_piobufbase.
	 */
	__u32 spi_pioindex;
	 /* number of buffers mapped for this process */
	__u32 spi_piocnt;

	/*
	 * Base address of writeonly pio buffers for this process.
	 * Each buffer has spi_piosize bytes, and is aligned on spi_pioalign
	 * boundaries.  spi_piocnt buffers are mapped from this address
	 */
	__u64 spi_piobufbase;

	/*
	 * Base address of readonly memory copy of the pioavail registers.
	 * There are 2 bits for each buffer.
	 */
	__u64 spi_pioavailaddr;

	/*
	 * Address where driver updates a copy of the interface and driver
	 * status (IPATH_STATUS_*) as a 64 bit value.  It's followed by a
	 * link status qword (formerly combined with driver status), then a
	 * string indicating hardware error, if there was one.
	 */
	__u64 spi_status;

	/* number of chip contexts available to user processes */
	__u32 spi_ncontexts;
	__u16 spi_unit; /* unit number of chip we are using; */
	__u16 spi_port; /* IB port number we are using for send */
	/* num bufs in each contiguous set */
	__u32 spi_rcv_egrperchunk;
	/* size in bytes of each contiguous set */
	__u32 spi_rcv_egrchunksize;
	/* total size of mmap to cover full rcvegrbuffers */
	__u32 spi_rcv_egrbuftotlen;
	__u32 spi_rhf_offset; /* dword offset in hdrqent for rcvhdr flags */
	/* address of readonly memory copy of the rcvhdrq tail register. */
	__u64 spi_rcvhdr_tailaddr;

        /*
	 * shared memory pages for subctxts if ctxt is shared; these cover
	 * all the processes in the group sharing a single context.
	 * all have enough space for the num_subcontexts value on this job.
	 */
	__u64 spi_subctxt_uregbase;
	__u64 spi_subctxt_rcvegrbuf;
	__u64 spi_subctxt_rcvhdr_base;

	/* shared memory page for send buffer disarm status */
	__u64 spi_sendbuf_status;
} __attribute__ ((aligned(8)));

/*
 * This version number is given to the driver by the user code during
 * initialization in the spu_userversion field of ipath_user_info, so
 * the driver can check for compatibility with user code.
 *
 * The major version changes when data structures
 * change in an incompatible way.  The driver must be the same or higher
 * for initialization to succeed.  In some cases, a higher version
 * driver will not interoperate with older software, and initialization
 * will return an error.
 */
#define IPATH_USER_SWMAJOR 1

/*
 * Minor version differences are always compatible
 * a within a major version, however if user software is larger
 * than driver software, some new features and/or structure fields
 * may not be implemented; the user code must deal with this if it
 * cares, or it must abort after initialization reports the difference.
 */
#define IPATH_USER_SWMINOR 13

#define IPATH_USER_SWVERSION ((IPATH_USER_SWMAJOR<<16) | IPATH_USER_SWMINOR)

/* BEGIN_NOSHIP_TO_OPENIB */
#ifndef IPATH_KERN_TYPE
/* END_NOSHIP_TO_OPENIB */
#define IPATH_KERN_TYPE 0
/* BEGIN_NOSHIP_TO_OPENIB */
#endif
/* END_NOSHIP_TO_OPENIB */

/*
 * Similarly, this is the kernel version going back to the user.  It's
 * slightly different, in that we want to tell if the driver was built as
 * part of a QLogic release, or from the driver from openfabrics.org,
 * kernel.org, or a standard distribution, for support reasons.
 * The high bit is 0 for non-QLogic and 1 for QLogic-built/supplied.
 *
 * It's returned by the driver to the user code during initialization in the
 * spi_sw_version field of ipath_base_info, so the user code can in turn
 * check for compatibility with the kernel.
*/
#define IPATH_KERN_SWVERSION ((IPATH_KERN_TYPE<<31) | IPATH_USER_SWVERSION)

/*
 * If the unit is specified via open, HCA choice is fixed.  If port is
 * specified, it's also fixed.  Otherwise we try to spread contexts
 * across ports and HCAs, using different algorithims.  WITHIN is
 * the old default, prior to this mechanism.
*/
#define IPATH_PORT_ALG_ACROSS 0 /* round robin contexts across HCAs, then
                                * ports; this is the default */
#define IPATH_PORT_ALG_WITHIN 1 /* use all contexts on an HCA (round robin
                                * active ports within), then next HCA */
#define IPATH_PORT_ALG_COUNT 2 /* number of algorithm choices */

/*
 * This structure is passed to ipath_userinit() to tell the driver where
 * user code buffers are, sizes, etc.   The offsets and sizes of the
 * fields must remain unchanged, for binary compatibility.  It can
 * be extended, if userversion is changed so user code can tell, if needed
 */
struct ipath_user_info {
	/*
	 * version of user software, to detect compatibility issues.
	 * Should be set to IPATH_USER_SWVERSION.
	 */
	__u32 spu_userversion;

	__u32 _spu_scif_nodeid; /* used for mic processes */

	/* size of struct base_info to write to */
	__u32 spu_base_info_size;

	__u32 spu_port_alg; /* which IPATH_PORT_ALG_*; unused user minor < 11 */

	/*
	 * If two or more processes wish to share a context, each process
	 * must set the spu_subcontext_cnt and spu_subcontext_id to the same
	 * values.  The only restriction on the spu_subcontext_id is that
	 * it be unique for a given node.
	 */
	__u16 spu_subcontext_cnt;
	__u16 spu_subcontext_id;

	__u32 spu_port; /* IB port requested by user if > 0 */

	/*
	 * address of struct base_info to write to
	 */
	__u64 spu_base_info;

} __attribute__ ((aligned(8)));

/* User commands. */

#define __IPATH_CMD_USER_INIT   16      /* old set up userspace */
#define IPATH_CMD_CTXT_INFO	17	/* find out what resources we got */
#define IPATH_CMD_RECV_CTRL	18	/* control receipt of packets */
#define IPATH_CMD_TID_UPDATE	19	/* update expected TID entries */
#define IPATH_CMD_TID_FREE	20	/* free expected TID entries */
#define IPATH_CMD_SET_PART_KEY	21	/* add partition key */
#define __IPATH_CMD_SLAVE_INFO  22      /* return info on slave processes */
#define IPATH_CMD_ASSIGN_CONTEXT 23	/* allocate HCA and context (or port, historically) */
#define IPATH_CMD_USER_INIT 	24	/* set up userspace */
#define IPATH_CMD_PIOAVAILCHK	25	/* check if pio send stuck */
#define IPATH_CMD_TIDCHKFIX	26	/* check expected tid, and fixup */
#define IPATH_CMD_PIOAVAILUPD	27	/* force an update of PIOAvail reg */
#define IPATH_CMD_POLL_TYPE	28	/* set the kind of polling we want */
#define IPATH_CMD_ARMLAUNCH_CTRL       29 /* armlaunch detection control */
/* 30 is unused */
#define IPATH_CMD_SDMA_INFLIGHT 31	/* latest sdma inflight count */
#define IPATH_CMD_SDMA_COMPLETE	32	/* try to complete pending sdma */
/* CMD 33 is available (used to be to enable backpressure). Removed in IFS 5.1*/
#define IPATH_CMD_DISARM_BUFS	34	/* disarm send buffers w/ errors */
#define IPATH_CMD_ACK_EVENT     35	/* ack & clear bits *spi_sendbuf_status */
/* MIC to setup memory with mic driver */
#define IPATH_CMD_MIC_MEM_INFO	41	/* mic memory setup operation */

/*
 * IPATH_CMD_ACK_EVENT obsoletes IPATH_CMD_DISARM_BUFS, but we keep it for
 * compatibility with libraries from previous release.   The ACK_EVENT
 * will take appropriate driver action (if any, just DISARM for now),
 * then clear the bits passed in as part of the mask.  These bits are
 * in the first 64bit word at spi_sendbuf_status, and are passed to
 * the driver in 
 */
#define IPATH_EVENT_DISARM_BUFS		(1ULL << 0)
#define IPATH_EVENT_LINKDOWN		(1ULL << 1)
#define IPATH_EVENT_LID_CHANGE		(1ULL << 2)
#define IPATH_EVENT_LMC_CHANGE		(1ULL << 3)
#define IPATH_EVENT_SL2VL_CHANGE	(1ULL << 4)

/*
 * The following ipath commands are only used for mic system to send
 * commands to host daemon. All commands above are also used by mic.
 */
#define IPATH_CMD_CONTEXT_OPEN		51	/* open a context */
#define IPATH_CMD_CONTEXT_CLOSE		52	/* close a context */

#define IPATH_CMD_GET_NUM_UNITS		61	/* number of hca units */
#define IPATH_CMD_GET_NUM_CTXTS		62	/* number of contexts */
#define IPATH_CMD_GET_PORT_LID		63	/* port lid */
#define IPATH_CMD_GET_PORT_GID		64	/* port gid */
#define IPATH_CMD_GET_PORT_LMC		65	/* port lmc */
#define IPATH_CMD_GET_PORT_RATE		66	/* port rate */
#define IPATH_CMD_GET_PORT_S2V		67	/* port sl2vl */

#define IPATH_CMD_GET_STATS_NAMES	68	/* stats names */
#define IPATH_CMD_GET_STATS		69	/* stats */
#define IPATH_CMD_GET_CTRS_UNAMES	70	/* counters unit names */
#define IPATH_CMD_GET_CTRS_UNIT		71	/* counters unit */
#define IPATH_CMD_GET_CTRS_PNAMES	72	/* counters port names */
#define IPATH_CMD_GET_CTRS_PORT		73	/* counters port */

#define IPATH_CMD_GET_CC_SETTINGS	74	/* get cc settings */
#define IPATH_CMD_GET_CC_TABLE		75	/* get cc table */

/* cmd for diag code */
#define IPATH_CMD_WAIT_FOR_PACKET       76
#define IPATH_CMD_GET_UNIT_FLASH        77
#define IPATH_CMD_PUT_UNIT_FLASH        78

/*
 * Poll types
 */

#define IPATH_POLL_TYPE_ANYRCV   0
#define IPATH_POLL_TYPE_URGENT	 0x01

struct ipath_ctxt_info {
	__u16 num_active;	/* number of active units */
	__u16 unit;		/* unit (chip) assigned to caller */
	__u16 port;		/* IB port assigned to caller */
	__u16 context;		/* context on unit assigned to caller */
	__u16 subcontext;	/* subcontext on unit assigned to caller */
	__u16 num_contexts;	/* number of contexts available on unit */
	__u16 num_subcontexts;	/* number of subcontexts opened on context */
	__u16 rec_cpu;		/* cpu # for affinity (ffff if none) */
};

struct ipath_tid_info {
	__u32 tidcnt;
	/* make structure same size in 32 and 64 bit */
	__u32 tid__unused;
	/* virtual address of first page in transfer */
	__u64 tidvaddr;
	/* pointer (same size 32/64 bit) to __u16 tid array */
	__u64 tidlist;

	/*
	 * pointer (same size 32/64 bit) to bitmap of TIDs used
	 * for this call; checked for being large enough at open
	 */
	__u64 tidmap;
};

/*
 * To send general info between PSM on mic and psmd on host.
 * this structure should be not more that "structure ipath_user_info".
 */
struct ipath_mic_info {
	int unit;		/* unit number */
	int port;		/* port number */
	int data1;		/* return data or -1 */
	int data2;		/* errno if data1=-1 */
	__u64 data3;		/* other data */
	__u64 data4;		/* other data */
} __attribute__ ((aligned(8)));

/*
 * PSM tells mic driver how to operate memores. flags:
 * 0x1: map remote host buffer, offset is the SCIF offset
 * 0x2: allocate knx memory in kernel.
 * 0x4: allocate physically contiguous knx memory in kernel.
 * 0x8: SCIF register knx memory, and copy offset to first 8 bytes.
 */
struct ipath_mem_info {
        uint32_t        key;            /* key to match mmap offset */
        uint32_t        flags;          /* flags indicate what to do */
        size_t          length;         /* buffer length in bytes */
        off_t           offset;         /* remotely registerd offset */
};

struct ipath_cmd {
	__u32 type;			/* command type */
	union {
		struct ipath_mem_info mem_info;	/* mic memory */
		struct ipath_mic_info mic_info;
		struct ipath_tid_info tid_info;
		struct ipath_user_info user_info;
		/* send dma inflight/completion counter */
		__u64 sdma_cntr;
		/* address in userspace of struct ipath_ctxt_info to
		   write result to */
		__u64 ctxt_info;
		/* enable/disable receipt of packets */
		__u32 recv_ctrl;
		/* enable/disable armlaunch errors (non-zero to enable) */
		__u32 armlaunch_ctrl;
		/* partition key to set */
		__u16 part_key;
		/* user address of __u32 bitmask of active slaves */
		__u64 slave_mask_addr;
		/* type of polling we want */
		__u16 poll_type;
		/* back pressure enable bit for one particular context */
		__u8 ctxt_bp;
		/* ipath_event_ack(), IPATH_EVENT_* bits */
		__u64 event_mask;
	} cmd;
};

struct ipath_iovec {
	/* Pointer to data, but same size 32 and 64 bit */
	__u64 iov_base;

	/*
	 * Length of data; don't need 64 bits, but want
	 * ipath_sendpkt to remain same size as before 32 bit changes, so...
	 */
	__u64 iov_len;
};

/*
 * Describes a single packet for send.  Each packet can have one or more
 * buffers, but the total length (exclusive of IB headers) must be less
 * than the MTU, and if using the PIO method, entire packet length,
 * including IB headers, must be less than the ipath_piosize value (words).
 * Use of this necessitates including sys/uio.h
 */
struct __ipath_sendpkt {
	__u32 sps_flags;	/* flags for packet (TBD) */
	__u32 sps_cnt;		/* number of entries to use in sps_iov */
	/* array of iov's describing packet. TEMPORARY */
	struct ipath_iovec sps_iov[4];
};

/* Passed into diag data special file's ->write method. */
struct ipath_diag_pkt {
	__u32 unit;
	__u64 data;
	__u32 len;
};

/*
 * Data layout in I2C flash (for GUID, etc.)
 * All fields are little-endian binary unless otherwise stated
 */
#define IPATH_FLASH_VERSION 2
struct ipath_flash {
	/* flash layout version (IPATH_FLASH_VERSION) */
	__u8 if_fversion;
	/* checksum protecting if_length bytes */
	__u8 if_csum;
	/*
	 * valid length (in use, protected by if_csum), including
	 * if_fversion and if_csum themselves)
	 */
	__u8 if_length;
	/* the GUID, in network order */
	__u8 if_guid[8];
	/* number of GUIDs to use, starting from if_guid */
	__u8 if_numguid;
	/* the (last 10 characters of) board serial number, in ASCII */
	char if_serial[12];
	/* board mfg date (YYYYMMDD ASCII) */
	char if_mfgdate[8];
	/* last board rework/test date (YYYYMMDD ASCII) */
	char if_testdate[8];
	/* logging of error counts, TBD */
	__u8 if_errcntp[4];
	/* powered on hours, updated at driver unload */
	__u8 if_powerhour[2];
	/* ASCII free-form comment field */
	char if_comment[32];
	/* Backwards compatible prefix for longer QLogic Serial Numbers */
	char if_sprefix[4];
	/* 82 bytes used, min flash size is 128 bytes */
	__u8 if_future[46];
};

/*
 * The next set of defines are for packet headers, and chip register
 * and memory bits that are visible to and/or used by user-mode software
 * The other bits that are used only by the driver or diags are in
 * ipath_registers.h
 */

/* RcvHdrFlags bits */
#define INFINIPATH_RHF_LENGTH_MASK 0x7FF
#define INFINIPATH_RHF_LENGTH_SHIFT 0
#define INFINIPATH_RHF_RCVTYPE_MASK 0x7
#define INFINIPATH_RHF_RCVTYPE_SHIFT 11
#define INFINIPATH_RHF_EGRINDEX_MASK 0xFFF
#define INFINIPATH_RHF_EGRINDEX_SHIFT 16
#define INFINIPATH_RHF_SEQ_MASK 0xF
#define INFINIPATH_RHF_SEQ_SHIFT 0
#define INFINIPATH_RHF_HDRQ_OFFSET_MASK 0x7FF
#define INFINIPATH_RHF_HDRQ_OFFSET_SHIFT 4
#define INFINIPATH_RHF_H_ICRCERR   0x80000000
#define INFINIPATH_RHF_H_VCRCERR   0x40000000
#define INFINIPATH_RHF_H_PARITYERR 0x20000000
#define INFINIPATH_RHF_H_LENERR    0x10000000
#define INFINIPATH_RHF_H_MTUERR    0x08000000
#define INFINIPATH_RHF_H_IHDRERR   0x04000000
#define INFINIPATH_RHF_H_TIDERR    0x02000000
#define INFINIPATH_RHF_H_MKERR     0x01000000
#define INFINIPATH_RHF_H_IBERR     0x00800000
#define INFINIPATH_RHF_H_TFGENERR  0x00400000
#define INFINIPATH_RHF_H_TFSEQERR  0x00200000
#define INFINIPATH_RHF_H_ERR_MASK  0xFFE00000
#define INFINIPATH_RHF_L_USE_EGR   0x80000000
#define INFINIPATH_RHF_L_SWA       0x00008000
#define INFINIPATH_RHF_L_SWB       0x00004000

/* TidFlow related bits */
#define INFINIPATH_TF_SEQNUM_SHIFT                 0
#define INFINIPATH_TF_SEQNUM_MASK                  0x7ff
#define INFINIPATH_TF_GENVAL_SHIFT                 11
#define INFINIPATH_TF_GENVAL_MASK                  0xff
#define INFINIPATH_TF_ISVALID_SHIFT                19
#define INFINIPATH_TF_ISVALID_MASK                 0x1
#define INFINIPATH_TF_ENABLED_SHIFT                20
#define INFINIPATH_TF_ENABLED_MASK                 0x1
#define INFINIPATH_TF_KEEP_AFTER_SEQERR_SHIFT      21
#define INFINIPATH_TF_KEEP_AFTER_SEQERR_MASK       0x1
#define INFINIPATH_TF_KEEP_AFTER_GENERR_SHIFT      22
#define INFINIPATH_TF_KEEP_AFTER_GENERR_MASK       0x1
#define INFINIPATH_TF_STATUS_SHIFT                 27
#define INFINIPATH_TF_STATUS_MASK                  0x3
#define INFINIPATH_TF_STATUS_SEQMISMATCH_SHIFT     27
#define INFINIPATH_TF_STATUS_SEQMISMATCH_MASK      0x1
#define INFINIPATH_TF_STATUS_GENMISMATCH_SHIFT     28
#define INFINIPATH_TF_STATUS_GENMISMATCH_MASK      0x1

#define INFINIPATH_TF_FLOWID_SHIFT                 19
#define INFINIPATH_TF_NFLOWS                       32

/* infinipath header fields */
#define INFINIPATH_I_VERS_MASK 0xF
#define INFINIPATH_I_VERS_SHIFT 28
#define INFINIPATH_I_CONTEXT_MASK 0xF
#define INFINIPATH_I_CONTEXT_SHIFT 24
#define INFINIPATH_I_TID_MASK 0x7FF
#define INFINIPATH_I_TID_SHIFT 13
#define INFINIPATH_I_OFFSET_MASK 0x1FFF
#define INFINIPATH_I_OFFSET_SHIFT 0

/* K_PktFlags bits */
#define INFINIPATH_KPF_INTR 0x1
#define INFINIPATH_KPF_HDRSUPP 0x2
#define INFINIPATH_KPF_INTR_HDRSUPP_MASK 0x3
#define INFINIPATH_KPF_COMMIDX_MASK 0x003C
#define INFINIPATH_KPF_COMMIDX_SHIFT 2
#define INFINIPATH_KPF_RESERVED_BITS(pktflags)            \
  ((__le16_to_cpu(pktflags) & INFINIPATH_KPF_COMMIDX_MASK) \
    << IPS_EPSTATE_COMMIDX_SHIFT) \

#define INFINIPATH_MAX_SUBCONTEXT	4

#define IPATH_MAX_UNIT  4 /* max units supported */
#define IPATH_MAX_PORT	2 /* no boards have more than 2 IB ports */

/* SendPIO per-buffer control */
/* BEGIN_NOSHIP_TO_OPENIB */
// #define INFINIPATH_SP_LENGTHP1_MASK 0x3FF	/* unused currently */
// #define INFINIPATH_SP_LENGTHP1_SHIFT 0	/* unused currently */
// #define INFINIPATH_SP_INTR    0x80		/* unused currently */
/* END_NOSHIP_TO_OPENIB */
#define INFINIPATH_SP_TEST    0x40
#define INFINIPATH_SP_TESTEBP 0x20

/* these are currently used only on 7322 chips; they should be referenced
 * only at the lowest level pio send buffer fill routines; they go into 
 * the pbcflags field.  OLSON: need to clean this up.  */
#define __PBC_IBPORT (1U << 26)
#define __PBC_VLSHIFT (27)

/* this portion only defines what we currently use */
union ipath_pbc {
	__u64 qword;
	__u32 dword;
	struct {
		__u16 length;
		__u16 fill1;
		__u32 pbcflags;
	};
};

/* SendPIOAvail bits */
#define INFINIPATH_SENDPIOAVAIL_BUSY_SHIFT 1
#define INFINIPATH_SENDPIOAVAIL_CHECK_SHIFT 0

/* infinipath header format */
struct ipath_header {
	/*
	 * Version - 4 bits, Context (or port, historically) - 4 bits, 
	 * TID - 10 bits and Offset.
	 * 14 bits before ECO change ~28 Dec 03.  After that, Vers 4,
	 * Port 4, TID 11, offset 13.
	 */
	__le32 ver_context_tid_offset;
	__le16 chksum;
	__le16 pkt_flags;
};

/* infinipath user message header format.
 * This structure contains the first 4 fields common to all protocols
 * that employ infinipath.
 */
struct ipath_message_header {
	__be16 lrh[4];
	__be32 bth[3];
	/* fields below this point are in host byte order */
	struct ipath_header iph;
	__u8 sub_opcode;
};

/* infinipath ethernet header format */
struct ether_header {
	__be16 lrh[4];
	__be32 bth[3];
	struct ipath_header iph;
	__u8 sub_opcode;
	__u8 cmd;
	__be16 lid;
	__u16 mac[3];
	__u8 frag_num;
	__u8 seq_num;
	__le32 len;
	/* MUST be of word size due to PIO write requirements */
	__le32 csum;
	__le16 csum_offset;
	__le16 flags;
	__u16 first_2_bytes;
	__u8 unused[2];		/* currently unused */
};

/* BEGIN_NOSHIP_TO_OPENIB */
/*
 * The PIO buffer used for sending infinipath messages must only be written
 * in 32-bit words, all the data must be written, and no writes can occur
 * after the last word is written (which transfers "ownership" of the buffer
 * to the chip and triggers the message to be sent).
 * Since the Linux sk_buff structure can be recursive, non-aligned, and
 * any number of bytes in each segment, we use the following structure
 * to keep information about the overall state of the copy operation.
 * This is used to save the information needed to store the checksum
 * in the right place before sending the last word to the hardware and
 * to buffer the last 0-3 bytes of non-word sized segments.
 */
struct copy_data_s {
	struct ether_header *hdr;
	/* addr of PIO buf to write csum to */
	__u32 __iomem *csum_pio;
	__u32 __iomem *to;	/* addr of PIO buf to write data to */
	__u32 device;		/* which device to allocate PIO bufs from */
	__s32 error;		/* set if there is an error. */
	__s32 extra;		/* amount of data saved in u.buf below */
	__u32 len;		/* total length to send in bytes */
	__u32 flen;		/* frament length in words */
	__u32 csum;		/* partial IP checksum */
	__u32 pos;		/* position for partial checksum */
	__u32 offset;		/* offset to where data currently starts */
	__s32 checksum_calc;	/* set to 1 when csum has been calculated */
	struct sk_buff *skb;
	union {
		__u32 w;
		__u8 buf[4];
	} u;
};
/* END_NOSHIP_TO_OPENIB */

/* IB - LRH header consts */
#define IPATH_LRH_GRH 0x0003	/* 1. word of IB LRH - next header: GRH */
#define IPATH_LRH_BTH 0x0002	/* 1. word of IB LRH - next header: BTH */

/* misc. */
#define SIZE_OF_CRC 1

#define IPATH_DEFAULT_SERVICE_ID 0x1000117500000000ULL
#define IPATH_DEFAULT_P_KEY 0xFFFF
#define IPATH_PERMISSIVE_LID 0xFFFF
#define IPATH_AETH_CREDIT_SHIFT 24
#define IPATH_AETH_CREDIT_MASK 0x1F
#define IPATH_AETH_CREDIT_INVAL 0x1F
#define IPATH_PSN_MASK 0xFFFFFF
#define IPATH_MSN_MASK 0xFFFFFF
#define IPATH_QPN_MASK 0xFFFFFF
#define IPATH_MULTICAST_LID_BASE 0xC000
/* BEGIN_NOSHIP_TO_OPENIB */
#define IPATH_EAGER_TID_ID INFINIPATH_I_TID_MASK
/* END_NOSHIP_TO_OPENIB */
#define IPATH_MULTICAST_QPN 0xFFFFFF

/* Receive Header Queue: receive type (from infinipath) */
#define RCVHQ_RCV_TYPE_EXPECTED  0
#define RCVHQ_RCV_TYPE_EAGER     1
#define RCVHQ_RCV_TYPE_NON_KD    2
#define RCVHQ_RCV_TYPE_ERROR     3

/* BEGIN_NOSHIP_TO_OPENIB */
/* OpCodes  */
#define IPATH_OPCODE_USER1 0xC0
#define IPATH_OPCODE_ITH4X 0xC1

/* OpCode 30 is use by stand-alone test programs  */
#define IPATH_OPCODE_RAW_DATA 0xDE
/* last OpCode (31) is reserved for test  */
#define IPATH_OPCODE_TEST 0xDF
/* END_NOSHIP_TO_OPENIB */

/* sub OpCodes - ith4x  */
#define IPATH_ITH4X_OPCODE_ENCAP 0x81
#define IPATH_ITH4X_OPCODE_LID_ARP 0x82

/* Value set in ips_common.h for IPS_HEADER_QUEUE_WORDS */
#define IPATH_HEADER_QUEUE_WORDS 9

/* functions for extracting fields from rcvhdrq entries for the driver.
 */
static inline __u32 ipath_hdrget_err_flags(const __le32 * rbuf)
{
	return __le32_to_cpu(rbuf[1]) & INFINIPATH_RHF_H_ERR_MASK;
}

static inline __u32 ipath_hdrget_rcv_type(const __le32 * rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> INFINIPATH_RHF_RCVTYPE_SHIFT)
	    & INFINIPATH_RHF_RCVTYPE_MASK;
}

static inline __u32 ipath_hdrget_length_in_bytes(const __le32 * rbuf)
{
	return ((__le32_to_cpu(rbuf[0]) >> INFINIPATH_RHF_LENGTH_SHIFT)
		& INFINIPATH_RHF_LENGTH_MASK) << 2;
}

static inline __u32 ipath_hdrget_index(const __le32 * rbuf)
{
	return (__le32_to_cpu(rbuf[0]) >> INFINIPATH_RHF_EGRINDEX_SHIFT)
	    & INFINIPATH_RHF_EGRINDEX_MASK;
}

static inline __u32 ipath_hdrget_seq(const __le32 * rbuf)
{
	return (__le32_to_cpu(rbuf[1]) >> INFINIPATH_RHF_SEQ_SHIFT)
	    & INFINIPATH_RHF_SEQ_MASK;
}

static inline __u32 ipath_hdrget_offset(const __le32 * rbuf)
{
	return (__le32_to_cpu(rbuf[1]) >> INFINIPATH_RHF_HDRQ_OFFSET_SHIFT)
	    & INFINIPATH_RHF_HDRQ_OFFSET_MASK;
}

static inline __u32 ipath_hdrget_use_egr_buf(const __le32 * rbuf)
{
	return __le32_to_cpu(rbuf[0]) & INFINIPATH_RHF_L_USE_EGR;
}

static inline __u32 ipath_hdrget_ipath_ver(__le32 hdrword)
{
	return (__le32_to_cpu(hdrword) >> INFINIPATH_I_VERS_SHIFT)
	    & INFINIPATH_I_VERS_MASK;
}

#endif				/* _IPATH_COMMON_H */
