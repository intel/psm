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

#ifndef _IPATH_USER_H
#define _IPATH_USER_H

//  This file contains all of the data structures and routines that are
//  publicly visible and usable (to low level infrastructure code; it is
//  not expected that any application, or even normal application-level library,
//  will ever need to use any of this).

//  Additional entry points and data structures that are used by these routines
//  may be referenced in this file, but they should not be generally available;
//  they are visible here only to allow use in inlined functions.  Any variable,
//  data structure, or function that starts with a leading "_" is in this
//  category.

//  Include header files we need that are unlikely to otherwise be needed by
//  programs.
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <syslog.h>
#include "ipath_intf.h"
#include "ipath_common.h"
#include "ipath_byteorder.h"
#include "ipath_udebug.h"
#include "ipath_service.h"

// interval timing routines
// Convert a count of cycles to elapsed nanoseconds
// this is only accurate for reasonably large numbers of cycles (at least tens)
static __inline__ uint64_t cycles_to_nanosecs(uint64_t)
    __attribute__ ((always_inline));
// convert elapsed nanoseconds to elapsed cycles
// this is only accurate for reasonably large numbers of nsecs (at least tens)
static __inline__ uint64_t nanosecs_to_cycles(uint64_t)
    __attribute__ ((always_inline));
// get current count of nanoseconds from unspecified base value (only useful for
// intervals)
static __inline__ uint64_t get_nanoseconds() __attribute__ ((always_inline));

// This block will eventually move to a separate file, but for now we'll leave
// it here.
typedef struct _ipath_dev {
  int32_t spd_fd;
  int32_t spd_type;	// ipath_type  
  volatile uint64_t *spd_uregbase; // mmap'ed to chip or virtual user regs
  volatile uint64_t *spd_piobase;	// mmap'ed access to chip PIO buffers
  uint64_t __pad[8]; // placeholder for future binary compat expansion     
} ipath_dev;

struct _ipath_ctrl {
	ipath_dev spc_dev;	// for use by "driver" code only, other code treats as an opaque cookie.

// some local storages in some condition:
// as storage of __ipath_rcvtidflow in ipath_userinit().
	__le32 regs[INFINIPATH_TF_NFLOWS << 1];
// as storage of __ipath_tidflow_wmb in ipath_userinit().
	__le32 tidflow_wmb_location;
// as storage of spi_sendbuf_status in ipath_userinit().
	uint64_t sendbuf_status;
// for ipath_check_unit_status(), ipath_proto.c
	int lasterr;

// location to which InfiniPath writes the rcvhdrtail
// register whenever it changes, so that no chip registers are read in
// the performance path. 
	volatile __le32 *__ipath_rcvtail;
// address where ur_rcvhdrhead is written
	volatile __le32 *__ipath_rcvhdrhead;
// address where ur_rcvegrindexhead is written
	volatile __le32 *__ipath_rcvegrhead;
// address where ur_rcvegrindextail is read
	volatile __le32 *__ipath_rcvegrtail;
// number of eager buffers
	uint32_t __ipath_tidegrcnt;
// address where ur_rcvtidflow is written
	volatile __le32 *__ipath_rcvtidflow;
// Serialize writes to tidflow QLE73XX
	volatile __le32 *__ipath_tidflow_wmb;

// save away spi_status for use in ipath_check_unit_status()
	volatile __u64 *__ipath_spi_status;
};

// PIO write routines assume that the message header is always 56 bytes.
#define IPATH_MESSAGE_HDR_SIZE	56
// Usable bytes in header (hdrsize - lrh - bth)
#define IPATH_MESSAGE_HDR_SIZE_IPATH	(IPATH_MESSAGE_HDR_SIZE-20) 
// Must be same as PSM_CRC_SIZE_IN_BYTES in ips_proto_params.h
#define IPATH_CRC_SIZE_IN_BYTES 8

// After the device is opened, ipath_userinit() is called to give the driver the
// parameters the user code wants to use, and to get the implementation values,
// etc. back.  0 is returned on success, a positive value is a standard errno,
// and a negative value is reserved for future use.  The first argument is
// the filedescriptor returned by the device open.
//
// It is allowed to have multiple devices (and of different types)
// simultaneously opened and initialized, although this won't be fully
// implemented initially.  This routine is used by the low level
// infinipath protocol code (and any other code that has similar low level
// functionality).
// This is the only routine that takes a file descriptor, rather than an
// struct _ipath_ctrl *.  The struct _ipath_ctrl * used for everything
// else is returned by this routine.
struct _ipath_ctrl *ipath_userinit(int32_t, struct ipath_user_info *,
				   struct ipath_base_info *b);

// don't inline these; it's all init code, and not inlining makes the
// overall code shorter and easier to debug
void ipath_touch_mmap(void *, size_t) __attribute__ ((noinline));

int32_t ipath_update_tid_err(void);	// handle update tid errors out of line
int32_t ipath_free_tid_err(void);	// handle free tid errors out of line

// set the BTH pkey to check for this process.
// This is for receive checks, not for sends.  It isn't necessary
// to set the default key, that's always allowed by the hardware.
// If too many pkeys are in use for the hardware to support, this
// will return EAGAIN, and the caller should then fail and exit
// or use the default key and check the pkey in the received packet
// checking.
int32_t ipath_set_pkey(struct _ipath_ctrl *, uint16_t);

// flush the eager buffers, by setting the
// eager index head register == eager index tail, if queue is full
void ipath_flush_egr_bufs(struct _ipath_ctrl *ctrl);

int ipath_wait_for_packet(struct _ipath_ctrl *);

// stop_start == 0 disables receive on the context, for use in queue overflow
// conditions.  stop_start==1 re-enables, and returns value of tail register,
// to be used to re-init the software copy of the head register
int ipath_manage_rcvq(struct _ipath_ctrl *ctrl, uint32_t stop_start);

// ctxt_bp == 0 disables fabric back pressure on the context.
// ctxt_bp == 1 enables fabric back pressure on the context.
int ipath_manage_bp(struct _ipath_ctrl *ctrl, uint8_t ctxt_bp);

// enable == 1 enables armlaunch (normal), 0 disables (only used
// ipath_pkt_test -B at the moment, needed for linda).
int ipath_armlaunch_ctrl(struct _ipath_ctrl *ctrl, uint32_t enable);

// force an update of the PIOAvail register to memory
int ipath_force_pio_avail_update(struct _ipath_ctrl *ctrl);

// Disarm any send buffers which need disarming.
int ipath_disarm_bufs(struct _ipath_ctrl *ctrl);

// New user event mechanism, using spi_sendbuf_status IPATH_EVENT_* bits
// obsoletes ipath_disarm_bufs(), and extends it, although old mechanism
// remains for binary compatibility.
int ipath_event_ack(struct _ipath_ctrl *ctrl, __u64 ackbits);

// Return send dma's current "in flight counter "
int ipath_sdma_inflight(struct _ipath_ctrl *ctrl, uint32_t *counter);

// Return send dma's current "completion counter"
int ipath_sdma_complete(struct _ipath_ctrl *ctrl, uint32_t *counter);

// set whether we want an interrupt on all packets, or just urgent ones
int ipath_poll_type(struct _ipath_ctrl *ctrl, uint16_t poll_type);

static int32_t __inline__ ipath_free_tid(struct _ipath_ctrl *,
					 uint32_t, uint64_t)
    __attribute__ ((always_inline));

// check the unit status, and return an IPS_RC_* code if it is not in a
// usable state.   It will also print a message if not in a usable state
int ipath_check_unit_status(struct _ipath_ctrl *ctrl);

// Statistics maintained by the driver
const char * infinipath_get_next_name(char **names);
uint64_t infinipath_get_single_stat(const char *attr, uint64_t *s);
int infinipath_get_stats_names_count(void);
// Counters maintained in the chip, globally, and per-prot
int infinipath_get_ctrs_unit_names_count(int unitno);
int infinipath_get_ctrs_port_names_count(int unitno);

uint64_t infinipath_get_single_unitctr(int unit, const char *attr, uint64_t *s);
int infinipath_get_single_portctr(int unit, int port, const char *attr,
				  uint64_t *c);
void infinipath_release_names(char *namep);

// Syslog wrapper
// 
// level is one of LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR, LOG_WARNING,
//                 LOG_NOTICE, LOG_INFO, LOG_DEBUG.
//
// prefix should be a short string to describe which part of the software stack
// is using syslog, i.e. "PSM", "mpi", "mpirun".
//
void ipath_syslog(const char *prefix, int to_console, int level, 
		  const char *format, ...)
	    __attribute__((format(printf, 4, 5)));

void ipath_vsyslog(const char *prefix, int to_console, int level, 
		  const char *format, va_list ap);

/* parameters for PBC for pio write routines, to avoid passing lots
 * of args; we instead pass the structure pointer.  */
struct ipath_pio_params {
  uint16_t length;
  uint8_t vl;
  uint8_t port;
  uint32_t cksum_is_valid;
  uint32_t cksum;
  uint32_t rate;
};

// write pio buffers.  The ipath_write_pio_force_order() version assumes
// that the processor does not write store buffers to i/o devices in the
// order in which they are writte, and that when flushing partially
// filled store buffers, the words are not ordered either.   The ipath_write_pio()
// form is used when the processor writes store buffers to i/o in the order
// in which they are filled, and writes partially filled buffers in increasing
// address order (assuming they are filled that way).
// The arguments are pio buffer address, payload length, header, and payload
void ipath_write_pio_vector(volatile uint32_t *, const struct ipath_pio_params *,
	void *, void *);  
void ipath_write_pio(volatile uint32_t *, const struct ipath_pio_params *,
	void *, void *);  
void ipath_write_pio_force_order(volatile uint32_t *,
	const struct ipath_pio_params *, void *, void *);

#define IPATH_SPECIAL_TRIGGER_MAGIC        0xaebecede
// IBA7220 can use a "Special" trigger.  We write to the last dword
// in the mapped SendBuf to trigger the launch.
void ipath_write_pio_special_trigger2k(volatile uint32_t *,
	const struct ipath_pio_params *, void *, void *);
void ipath_write_pio_special_trigger4k(volatile uint32_t *,
	const struct ipath_pio_params *, void *, void *);

/*
 * Copy routine that may copy a byte multiple times but optimized for througput
 * This is not safe to use for PIO routines where we want a guarantee that a 
 * byte is only copied/moved across the bus once.
 */
void ipath_dwordcpy(volatile uint32_t *dest, const uint32_t * src, uint32_t ndwords);

/*
* Safe version of ipath_dwordcpy that is guaranteed to only copy each byte once.
*/
#if defined(__x86_64__)
void ipath_dwordcpy_safe(volatile uint32_t *dest, const uint32_t * src, uint32_t ndwords);
#else
#define ipath_dwordcpy_safe ipath_dwordcpy
#endif

//  From here to the end of the file are implementation details that should not
//  be used outside this file (other than to call the function), except in the
//  one infrastructure file in which they are defined.

// NOTE:  doing paired 32 bit writes to the chip to store 64 bit values (as from
// 32 bit programs) will not work correctly, because there is no sub-qword address
// decode.  Therefore 32 bit programs use only a single 32 bit store; the head
// register values are all less than 32 bits, anyway.   Given that, we use
// only 32 bits even for 64 bit programs, for simplicity.  These functions must
// not be called until after ipath_userinit() is called.
// The ctrl argument is currently unused, but remains useful for adding
// debug code.

static __inline__ void ipath_put_rcvegrindexhead(struct _ipath_ctrl *ctrl,
						 uint32_t val)
{
	*ctrl->__ipath_rcvegrhead = __cpu_to_le32(val);
}

static __inline__ void ipath_put_rcvhdrhead(struct _ipath_ctrl *ctrl,
					    uint32_t val)
{
	*ctrl->__ipath_rcvhdrhead = __cpu_to_le32(val);
}

static __inline__ uint32_t ipath_get_rcvhdrtail(struct _ipath_ctrl *ctrl)
{
    uint32_t res = __le32_to_cpu(*ctrl->__ipath_rcvtail);
    ips_rmb();
    return res;
}

static __inline__ void ipath_tidflow_set_entry(struct _ipath_ctrl *ctrl,
		uint32_t flowid, uint8_t genval, uint16_t seqnum)
{
    ctrl->__ipath_rcvtidflow[flowid << 1] = __cpu_to_le32(
       (1 << INFINIPATH_TF_ISVALID_SHIFT) |
       (1 << INFINIPATH_TF_ENABLED_SHIFT) |
       (1 << INFINIPATH_TF_STATUS_SEQMISMATCH_SHIFT) |
       (1 << INFINIPATH_TF_STATUS_GENMISMATCH_SHIFT) |
       (genval << INFINIPATH_TF_GENVAL_SHIFT) |
       ((seqnum & INFINIPATH_TF_SEQNUM_MASK) << INFINIPATH_TF_SEQNUM_SHIFT));
    /* Write a read-only register to act as a delay between tidflow writes */
    *ctrl->__ipath_tidflow_wmb = 0;
}

static __inline__ void ipath_tidflow_reset(struct _ipath_ctrl *ctrl,
		uint32_t flowid)
{
    ctrl->__ipath_rcvtidflow[flowid << 1] = __cpu_to_le32(
           (1 << INFINIPATH_TF_STATUS_SEQMISMATCH_SHIFT) |
           (1 << INFINIPATH_TF_STATUS_GENMISMATCH_SHIFT));
    /* Write a read-only register to act as a delay between tidflow writes */
    *ctrl->__ipath_tidflow_wmb = 0;
}

/*
 * This should only be used for debugging.
 * Normally, we shouldn't read the chip.
 */
static __inline__ uint32_t ipath_tidflow_get(struct _ipath_ctrl *ctrl,
		uint32_t flowid)
{
  return __le32_to_cpu(ctrl->__ipath_rcvtidflow[flowid << 1]);
}

static __inline__ uint32_t ipath_tidflow_get_seqmismatch(uint32_t val)
{
  return (val >> INFINIPATH_TF_STATUS_SEQMISMATCH_SHIFT) &
    INFINIPATH_TF_STATUS_SEQMISMATCH_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_genmismatch(uint32_t val)
{
  return (val >> INFINIPATH_TF_STATUS_GENMISMATCH_SHIFT) &
    INFINIPATH_TF_STATUS_GENMISMATCH_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_isvalid(uint32_t val)
{
  return (val >> INFINIPATH_TF_ISVALID_SHIFT) & INFINIPATH_TF_ISVALID_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_seqnum(uint32_t val)
{
  return (val >> INFINIPATH_TF_SEQNUM_SHIFT) & INFINIPATH_TF_SEQNUM_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_genval(uint32_t val)
{
  return (val >> INFINIPATH_TF_GENVAL_SHIFT) & INFINIPATH_TF_GENVAL_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_enabled(uint32_t val)
{
  return (val >> INFINIPATH_TF_ENABLED_SHIFT) & INFINIPATH_TF_ENABLED_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_keep_after_seqerr(uint32_t val)
{
  return (val >> INFINIPATH_TF_KEEP_AFTER_SEQERR_SHIFT) &
    INFINIPATH_TF_KEEP_AFTER_SEQERR_MASK;
}

static __inline__ uint32_t ipath_tidflow_get_keep_after_generr(uint32_t val)
{
  return (val >> INFINIPATH_TF_KEEP_AFTER_GENERR_SHIFT) &
    INFINIPATH_TF_KEEP_AFTER_GENERR_MASK;
}

/*
 * This should only be used by a process to write the eager index into
 * a subcontext's eager header entry.
 */
static __inline__ void ipath_hdrset_index(__le32 *rbuf, uint32_t val)
{
	rbuf[0] =
	    (rbuf[0] &
		__cpu_to_le32(~(INFINIPATH_RHF_EGRINDEX_MASK <<
				INFINIPATH_RHF_EGRINDEX_SHIFT))) |
	    __cpu_to_le32((val & INFINIPATH_RHF_EGRINDEX_MASK) <<
			  INFINIPATH_RHF_EGRINDEX_SHIFT);
}

/*
 * This should only be used by a process to update the receive header
 * error flags.
 */
static __inline__ void ipath_hdrset_err_flags(__le32 *rbuf, uint32_t val)
{
	rbuf[1] |= __cpu_to_le32(val);
}

/*
 * This should only be used by a process to write the rhf seq number into
 * a subcontext's eager header entry.
 */
static __inline__ void ipath_hdrset_seq(__le32 *rbuf, uint32_t val)
{
	rbuf[1] =
	    (rbuf[1] &
		__cpu_to_le32(~(INFINIPATH_RHF_SEQ_MASK <<
				INFINIPATH_RHF_SEQ_SHIFT))) |
	    __cpu_to_le32((val & INFINIPATH_RHF_SEQ_MASK) <<
			  INFINIPATH_RHF_SEQ_SHIFT);
}

// Manage TID entries.  It is possible that not all entries
// requested may be allocated.  A matching ipath_free_tid() must be
// done for each ipath_update_tid(), because currently no caching or
// reuse of expected tid entries is allowed, to work around malloc/free
// and mmap/munmap issues.  The driver decides which TID entries to allocate.
// If ipath_free_tid is called to free entries in use by a different
// send by the same process, data corruption will probably occur,
// but only within that process, not for other processes.

// update tidcnt expected TID entries from the array pointed to by tidinfo.
// Returns 0 on success, else an errno.  See full description at declaration
static int32_t __inline__ ipath_update_tid(struct _ipath_ctrl *ctrl,
					   uint32_t tidcnt, uint64_t tidlist,
					   uint64_t vaddr, uint64_t tidmap)
{
	struct ipath_cmd cmd;

	cmd.type = IPATH_CMD_TID_UPDATE;

	cmd.cmd.tid_info.tidcnt = tidcnt;	// number of tid entries to do
	cmd.cmd.tid_info.tidlist = tidlist;	// driver copies tids back directly to this
	cmd.cmd.tid_info.tidvaddr = vaddr;	// base address for this send to map
	cmd.cmd.tid_info.tidmap = tidmap;	// driver copies directly to this
	if (ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1)
		return ipath_update_tid_err();
	return 0;
}

static int32_t __inline__ ipath_free_tid(struct _ipath_ctrl *ctrl,
					 uint32_t tidcnt, uint64_t tidmap)
{
	struct ipath_cmd cmd;

	cmd.type = IPATH_CMD_TID_FREE;

	cmd.cmd.tid_info.tidcnt = tidcnt;
	cmd.cmd.tid_info.tidmap = tidmap;	// driver copies from this
	if (ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1)
		return ipath_free_tid_err();
	return 0;
}

extern uint32_t __ipath_pico_per_cycle;	// only for use in these functions

// this is only accurate for reasonably large numbers of cycles (at least tens)
static __inline__ uint64_t cycles_to_nanosecs(uint64_t cycs)
{
	return (__ipath_pico_per_cycle * cycs) / 1000ULL;
}

// this is only accurate for reasonably large numbers of nsecs (at least tens)
static __inline__ uint64_t nanosecs_to_cycles(uint64_t ns)
{
	return (ns * 1000ULL) / __ipath_pico_per_cycle;
}

static __inline__ uint64_t get_nanoseconds()
{
	return cycles_to_nanosecs(get_cycles());
}

// open the diags device, if supported by driver.  Returns 0 on
// success, errno on failure.  Also tells driver that diags
// is active, which changes some driver behavior
int ipath_diag_open(unsigned);	// unit
int ipath_diag_close(void);

// diags chip read and write routines

int ipathd_read32(uint64_t reg_offset, uint32_t * read_valp);
int ipathd_write32(uint64_t reg_offset, uint32_t write_val);

int ipathd_readmult(uint64_t, unsigned, uint64_t *);	// chip: offset, cnt, ptr
int ipathd_write(uint64_t, uint64_t);	// chip: offset, value

#define IPATH_READ_EEPROM 31337
#define IPATH_WRITE_EEPROM 101

struct ipath_eeprom_req {
    void *addr;
    uint16_t len;
    uint16_t offset;
};

int ipathd_send_pkt(const void *, unsigned);	// send a packet for diags
int ipathd_read_i2c(struct ipath_eeprom_req *);	// diags read i2c flash

__u8 ipath_flash_csum(struct ipath_flash *, int);

int ipathd_reset_hardware(uint32_t);

int ipath_hideous_ioctl_emulator(int unit, int reqtype,
				 struct ipath_eeprom_req *req);

#endif				// _IPATH_USER_H
