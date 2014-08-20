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

// This file contains ipath service routine interface used by the low
// level infinipath protocol code.

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <malloc.h>
#include <time.h>

#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>

#include "ipserror.h"
#include "ipath_user.h"

int __ipath_malloc_no_mmap = 0; // keep track whether we disabled mmap in malloc

// This exists as a separate routine called on (very rare)
// ipath_update_tid() errors, so as to avoid pulling unnecessary code
// into the instruction cache, keeping the fast path code as fast possible.
int ipath_update_tid_err(void)
{
    int ret = errno; // preserve errno for return

    _IPATH_INFO("failed: %s\n", strerror(errno));
    return ret;
}

// This exists as a separate routine called on (very rare)
// ipath_free_tid() errors, so as to avoid pulling unnecessary code
// into the instruction cache, keeping the fast path code as fast possible.
int ipath_free_tid_err(void)
{
    int ret = errno; // preserve errno for return

    _IPATH_INFO("failed: %s\n", strerror(errno));
    return ret;
}

// touch the pages, with a 32 bit read
void ipath_touch_mmap(void *m, size_t bytes)
{
    volatile uint32_t *b = (volatile uint32_t *)m, c;
    size_t i;  // m is always page aligned, so pgcnt exact
    int __ipath_pg_sz;

    /* First get the page size */
    __ipath_pg_sz = sysconf(_SC_PAGESIZE);

    _IPATH_VDBG("Touch %lu mmap'ed pages starting at %p\n", (unsigned long) bytes/__ipath_pg_sz, m);
    bytes /= sizeof c;
    for(i=0; i<bytes; i+=__ipath_pg_sz/sizeof c)
        c = b[i];
}

//
// set the BTH pkey to check for this process.
// This is for receive checks, not for sends.  See the description
// in ipath_user.h
int ipath_set_pkey(struct _ipath_ctrl *ctrl, uint16_t pkey)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_SET_PART_KEY;
    cmd.cmd.part_key = pkey;

    if(ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
	if (errno != EINVAL)
	    _IPATH_INFO("failed: %s\n", strerror(errno));
	return -1;
    }

    return 0;
}

// flush the eager buffers, by setting the eager index head to eager index tail
// if eager buffer queue is full.
//
// Called when we had eager buffer overflows (ERR_TID/INFINIPATH_RHF_H_TIDERR
// was set in RHF errors), and no good eager packets were received, so
// that eager head wasn't adavanced.
//

void ipath_flush_egr_bufs(struct _ipath_ctrl *ctrl)
{
    uint32_t head = __le32_to_cpu(*ctrl->__ipath_rcvegrhead);
    uint32_t tail = __le32_to_cpu(*ctrl->__ipath_rcvegrtail);

    if((head%ctrl->__ipath_tidegrcnt) == ((tail+1)%ctrl->__ipath_tidegrcnt)) {
        _IPATH_DBG("eager array full after overflow, flushing (head %llx, tail %llx\n",
            (long long)head, (long long)tail);
        *ctrl->__ipath_rcvegrhead = __cpu_to_le32(tail);
    }
}

// stop_start == 0 disables receive on the context, for use in queue
// overflow conditions.  stop_start==1 re-enables, to be used to
// re-init the software copy of the head register
int ipath_manage_rcvq(struct _ipath_ctrl *ctrl, uint32_t stop_start)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_RECV_CTRL;
    cmd.cmd.recv_ctrl = stop_start;

    if(ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s\n", strerror(errno));
	return -1;
    }
    return 0;
}

// enable == 1 enables armlaunch (normal), 0 disables (only used
// ipath_pkt_test -B at the moment, needed for linda).
int ipath_armlaunch_ctrl(struct _ipath_ctrl *ctrl, uint32_t enable)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_ARMLAUNCH_CTRL;
    cmd.cmd.armlaunch_ctrl = enable;

    if(ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s\n", strerror(errno));
	return -1;
    }
    return 0;
}

// force PIOAvail register to be updated to memory
int ipath_force_pio_avail_update(struct _ipath_ctrl *ctrl)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_PIOAVAILUPD;

    if(ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s\n", strerror(errno));
	return -1;
    }
    return 0;
}

// ack event bits, and clear them.  Usage is check *spi_sendbuf_status,
// pass bits you are prepared to handle to ipath_event_ack(), perform the
// appropriate actions for bits that were set, and then (if appropriate)
// check the bits again.
int ipath_event_ack(struct _ipath_ctrl *ctrl, __u64 ackbits)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_ACK_EVENT;
    cmd.cmd.event_mask = ackbits;

    if (ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
      if (errno != EINVAL) /* not implemented in driver. */
	_IPATH_DBG("failed: %s\n", strerror(errno));
      return -1;
    }
    return 0;
}

// Disarm any send buffers which need disarming.
int ipath_disarm_bufs(struct _ipath_ctrl *ctrl)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_DISARM_BUFS;

    if (ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
      if (errno != EINVAL) /* not implemented in driver. */
	_IPATH_DBG("failed: %s\n", strerror(errno));
      return -1;
    }
    return 0;
}

// Wait until send dma completion reaches at least 'completion_counter'
int ipath_sdma_complete(struct _ipath_ctrl *ctrl, uint32_t *counter)
{
    struct ipath_cmd cmd;
    int ret;

    cmd.type = IPATH_CMD_SDMA_COMPLETE;
    cmd.cmd.sdma_cntr = (uintptr_t) counter;
    VALGRIND_MAKE_MEM_DEFINED(&cmd, sizeof(struct ipath_cmd));

    *counter = 0;
    if ((ret = ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd))) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s (errno=%d)\n", strerror(errno), errno);
	return -1;
    }
    return 1;
}

// Return send dma's current "in flight counter "
int ipath_sdma_inflight(struct _ipath_ctrl *ctrl, uint32_t *counter)
{
    struct ipath_cmd cmd;
    int ret;

    cmd.type = IPATH_CMD_SDMA_INFLIGHT;
    cmd.cmd.sdma_cntr = (uintptr_t) counter;
    VALGRIND_MAKE_MEM_DEFINED(&cmd, sizeof(struct ipath_cmd));

    *counter = 0;
    if ((ret = ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd))) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s (errno=%d)\n", strerror(errno), errno);
	return -1;
    }
    return 1;
}

// Tell the driver to change the way packets can generate interrupts.
//
// IPATH_POLL_TYPE_URGENT: Generate interrupt only when packet sets
//                         INFINIPATH_KPF_INTR
// IPATH_POLL_TYPE_ANYRCV: wakeup on any rcv packet (when polled on).
//
// PSM: Uses TYPE_URGENT in ips protocol
//
int ipath_poll_type(struct _ipath_ctrl *ctrl, uint16_t poll_type)
{
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_POLL_TYPE;
    cmd.cmd.poll_type = poll_type;

    if(ipath_cmd_write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
	if (errno != EINVAL) /* not implemented in driver */
	    _IPATH_INFO("failed: %s\n", strerror(errno));
	return -1;
    }
    return 0;
}

// wait for a received packet for our context
// This allows us to not busy wait, if nothing has happened for a
// while, which allows better measurements of cpu utilization, and
// in some cases, slightly better performance.  Called where we would
// otherwise call sched_yield().  It is not guaranteed that a packet
// has arrived, so the normal checking loop(s) should be done.
//
// PSM: not used as is, PSM has it's own use of polling for interrupt-only
//      packets (sets ipath_poll_type to TYPE_URGENT)
int ipath_wait_for_packet(struct _ipath_ctrl *ctrl)
{
    return ipath_cmd_wait_for_packet(ctrl->spc_dev.spd_fd);
}

int ipath_hideous_ioctl_emulator(int unit, int reqtype, struct ipath_eeprom_req *req)
{
    switch (reqtype) {
    case IPATH_READ_EEPROM:
    {
        // Emulate a read of a byte range by doing a full read, then
        // getting the bits we want.
        char *data;

        if (infinipath_get_unit_flash(unit, &data) == -1) {
	    if (data) free(data);
            return -1;
	}

        memcpy((char *) (unsigned long) req->addr, data + req->offset,
               req->len);

        free(data);

        break;
    }
    case IPATH_WRITE_EEPROM:
    {
        // Emulate a write to a byte range by doing a full read,
        // modifying the bits we want, then a full write.
        char *data;
        int len;

        len = infinipath_get_unit_flash(unit, &data);

        if (len == -1) {
	    if (data) free(data);
            return -1;
	}

        memcpy(data + req->offset, (char *) (unsigned long) req->addr,
               req->len);

        if (infinipath_put_unit_flash(unit, data, len) == -1) {
	    free(data);
            return -1;
	}

        free(data);

        break;
    }
    default:
        fprintf(stderr, "invalid hideous emulated ioctl: %d\n", reqtype);
        exit(1);
    }
    return 0;
}

// check if the chip/board are in an OK state.  If not,
// print a message and return an error code.   Used at
// places where we are going to be in slow mode anyway,
// such as open, close, and out of pio buffers
// 
// PSM: implemented in context abstraction psmi_context_check_status()
// As of 7322-ready driver, need to check port-specific qword for IB
// as well as older unit-only.  For now, we don't have the port interface
// defined, so just check port 0 qword for spi_status
// Hard-code spmsg as 3rd qword until we have IB port
int ipath_check_unit_status(struct _ipath_ctrl *ctrl)
{
    char *spmsg = NULL, *msg = NULL, buf[80];
    int rc = IPS_RC_OK;
    _Pragma_unlikely

    if(!ctrl->__ipath_spi_status)
        return rc;

    if( !(ctrl->__ipath_spi_status[0] & IPATH_STATUS_CHIP_PRESENT) ||
        (ctrl->__ipath_spi_status[0] & (IPATH_STATUS_HWERROR))) {
        rc = IPS_RC_DEVICE_ERROR;
        if(ctrl->lasterr != rc) { // only report once
            spmsg = (char*)&ctrl->__ipath_spi_status[2];  // string for hardware error, if any
            if(!*spmsg) {
                msg = buf;
                snprintf(buf, sizeof buf, "%s\n",
                    (ctrl->__ipath_spi_status[0] & IPATH_STATUS_HWERROR) ?
                    "Hardware error" : "Hardware not found");
            }
        }
    }
    else if (!(ctrl->__ipath_spi_status[0] & IPATH_STATUS_IB_CONF) && 
	    !(ctrl->__ipath_spi_status[1] & IPATH_STATUS_IB_CONF)) {
        rc = IPS_RC_NETWORK_DOWN;
        if(ctrl->lasterr != rc) // only report once
            spmsg = (char*)&ctrl->__ipath_spi_status[2];  // string for hardware error, if any
    }
    else if (!(ctrl->__ipath_spi_status[0] & IPATH_STATUS_IB_READY) &&
	    !(ctrl->__ipath_spi_status[1] & IPATH_STATUS_IB_READY)) {
        // if only this error, probably cable pulled, switch rebooted, etc.
        // report it the first time, and then treat it same as BUSY, since
        // it could be recovered from within the quiescence period
        rc = IPS_RC_BUSY;
        if(ctrl->lasterr != rc) // only report once
            msg = "IB Link is down";
    }
    if(spmsg && *spmsg) {
        _IPATH_ERROR("Hardware problem: %s\n", spmsg);
        // and try to get it out to user before returning error so mpirun shows
        // since mpi interface code will normally exit immediately on errors
        fflush(stdout);
        sleep(1);
    }
    else if(msg)
        _IPATH_DBG("%s\n", msg);
    if(ctrl->lasterr && rc==IPS_RC_OK)
        ctrl->lasterr = 0; // cleared up, report if it happens again
    else if(rc != IPS_RC_OK)
        ctrl->lasterr = rc;
    return rc;
}

/* These have been fixed to read the values, but they are not
 * compatible with the ipath driver, they return new info with
 * the qib driver
 */
static int infinipath_count_names(const char *namep)
{
	int n = 0;
	while (*namep != '\0') {
		if (*namep == '\n')
			n++;
		namep++;
	}
	return n;
}

const char * infinipath_get_next_name(char **names)
{
	char *p, *start;

	p = start = *names;
	while (*p != '\0' && *p != '\n') {
		p++;
	}
	if (*p == '\n') {
		*p = '\0';
		p++;
		*names = p;
		return start;
	} else
		return NULL;
}

void infinipath_release_names(char *namep)
{
	/* TODO: names were initialised in the data section before. Now
	 * they are allocated when ipath_ipathfs_read() is called. Allocation
	 * for names is done only once at init time. Should we eventually 
	 * have an "stats_type_unregister" type of routine to explicitely 
	 * deallocate memory and free resources ?
	 */
#if 0
	if (namep != NULL)
		free(namep);
#endif
}

int infinipath_get_stats_names_count()
{
	char *namep;
	int c;

	c = infinipath_get_stats_names(&namep);
	free(namep);
	return c;
}

int infinipath_get_ctrs_unit_names_count(int unitno)
{
	char *namep;
	int c;

	c = infinipath_get_ctrs_unit_names(unitno, &namep);
	free(namep);
	return c;
}

int infinipath_get_ctrs_port_names_count(int unitno)
{
	char *namep;
	int c;

	c = infinipath_get_ctrs_port_names(unitno, &namep);
	free(namep);
	return c;
}

int infinipath_lookup_stat(const char *attr, char *namep, uint64_t *stats,
			   uint64_t *s)
{
	const char *p;
	int i, ret = -1, len = strlen(attr);
	int nelem = infinipath_count_names(namep);

	for (i = 0; i < nelem; i++) {
		p = infinipath_get_next_name(&namep);
		if (p == NULL) break;
		if (strncasecmp(p, attr, len+1) == 0) {
			ret = i;
			*s = stats[i];
		}
	}
	return ret;
}

uint64_t infinipath_get_single_stat(const char *attr, uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = infinipath_get_stats_names(&namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = infinipath_get_stats(stats, nelem);
	if (n != nelem)
	       goto bail;
	ret = infinipath_lookup_stat(attr, namep, stats, s);
bail:
	if (namep != NULL)
		free(namep);
	if (stats != NULL)
		free(stats);
	return ret;
}

uint64_t infinipath_get_single_unitctr(int unit, const char *attr, uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = infinipath_get_ctrs_unit_names(unit, &namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = infinipath_get_ctrs_unit(unit, stats, nelem);
	if (n != nelem)
	       goto bail;
	ret = infinipath_lookup_stat(attr, namep, stats, s);
bail:
	if (namep != NULL)
		free(namep);
	if (stats != NULL)
		free(stats);
	return ret;
}

int infinipath_get_single_portctr(int unit, int port, const char *attr,
				       uint64_t *s)
{
	int nelem, n = 0, ret = -1;
	char *namep = NULL;
	uint64_t *stats = NULL;

	nelem = infinipath_get_ctrs_port_names(unit, &namep);
	if (nelem == -1 || namep == NULL)
		goto bail;
	stats = calloc(nelem, sizeof(uint64_t));
	if (stats == NULL)
		goto bail;
	n = infinipath_get_ctrs_port(unit, port, stats, nelem);
	if (n != nelem)
	       goto bail;
	ret = infinipath_lookup_stat(attr, namep, stats, s);
bail:
	if (namep != NULL)
		free(namep);
	if (stats != NULL)
		free(stats);
	return ret;
}

/*
 * Add a constructor function to disable mmap if asked to do so by the user
 */
static void init_mallopt_disable_mmap(void) __attribute__ ((constructor));

static void init_mallopt_disable_mmap(void) 
{
    char *env = getenv("IPATH_DISABLE_MMAP_MALLOC");

    if (env && *env) {
	if (mallopt(M_MMAP_MAX, 0) && mallopt(M_TRIM_THRESHOLD, -1)) {
	    __ipath_malloc_no_mmap = 1;
	}
    }

    return;
}
