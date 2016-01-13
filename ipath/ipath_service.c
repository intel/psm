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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <poll.h>

#include "ipath_service.h"

/*
 * This function is necessary in a udev-based world.  There can be an
 * arbitrarily long (but typically less than one second) delay between
 * a driver getting loaded and any dynamic special files turning up.
 *
 * The timeout is in milliseconds.  A value of zero means "callee
 * decides timeout".  Negative is infinite.
 *
 * Returns 0 on success, -1 on error or timeout.  Check errno to see
 * whether there was a timeout (ETIMEDOUT) or an error (any other
 * non-zero value).
 */
int
ipath_wait_for_device(const char *path, long timeout)
{
    int saved_errno;
    struct stat st;
    long elapsed;
    int ret;

    if (timeout == 0)
        timeout = 15000;

    elapsed = 0;

    while (1) {
        static const long default_ms = 250;
        struct timespec req = { 0 };
        long ms;

        ret = stat(path, &st);
        saved_errno = errno;

        if (ret == 0 || (ret == -1 && errno != ENOENT))
            break;

        if (timeout - elapsed == 0) {
            saved_errno = ETIMEDOUT;
            break;
        }

        if (elapsed == 0) {
            if (timeout == -1)
                _IPATH_DBG("Device file %s not present on first check; "
                           "waiting indefinitely...\n", path);
            else
                _IPATH_DBG("Device file %s not present on first check; "
                           "waiting up to %.1f seconds...\n",
                           path, timeout / 1e3);
        }

        if (timeout < 0 || timeout - elapsed >= default_ms)
            ms = default_ms;
        else
            ms = timeout;

        elapsed += ms;
        req.tv_nsec = ms * 1000000;

        ret = nanosleep(&req, NULL);
        saved_errno = errno;

        if (ret == -1)
            break;
    }

    if (ret == 0)
        _IPATH_DBG("Found %s after %.1f seconds\n", path, elapsed / 1e3);
    else
        _IPATH_INFO("The %s device failed to appear after %.1f seconds: %s\n",
                    path, elapsed / 1e3, strerror(saved_errno));

    errno = saved_errno;
    return ret;
}

#ifdef __MIC__
#include <scif.h>
#define PSM_HOST_PORT		SCIF_OFED_PORT_7	/* predefined port */
#define PSM_HOST_NODE		0			/* host node is always 0 */
scif_epd_t			psmd_epd = -1;
int				qibp_fd = -1;

static scif_epd_t
ipath_psmd_connect(uint16_t node, uint16_t port)
{
    int conn_port, tries = 20;
    struct scif_portID portID;
    scif_epd_t epd;
    uid_t uid;
    gid_t gid;

    epd = scif_open();
    if (epd < 0) {
	fprintf(stderr, "scif_open failed with error %d\n", errno);
	return (scif_epd_t)-1;
    }

    if ((conn_port = scif_bind(epd, 0)) < 0) {
	fprintf(stderr, "scif_bind failed with error %d\n", errno);
	scif_close(epd);
	return (scif_epd_t)-1;
    }

    portID.port = port;
    portID.node = node;
retry:
    if (scif_connect(epd, &portID) < 0) {
	if ((errno == ECONNREFUSED) && (tries > 0)) {
	    tries--;
	    sleep(1);
	    goto retry;
	}
	fprintf(stderr, "scif_connect failed with error %d(%s)\n", errno, strerror(errno));
	fprintf(stderr, "Please check if /usr/sbin/psmd is running on host.\n");
	scif_close(epd);
	return (scif_epd_t)-1;
    }

    uid = geteuid();
    if (scif_send(epd, &uid, sizeof(uid), SCIF_SEND_BLOCK) != sizeof(uid)) {
	fprintf(stderr, "cannot send uid to psmd service\n");
	scif_close(epd);
	return (scif_epd_t)-1;
    }
    gid = getegid();
    if (scif_send(epd, &gid, sizeof(gid), SCIF_SEND_BLOCK) != sizeof(gid)) {
	fprintf(stderr, "cannot send gid to psmd service\n");
	scif_close(epd);
	return (scif_epd_t)-1;
    }

    return epd;
}

static int
ipath_scif_send(void *buf, size_t len)
{
    int ret;

    if (psmd_epd == -1) {
	psmd_epd = ipath_psmd_connect(PSM_HOST_NODE, PSM_HOST_PORT);
	if (psmd_epd == -1) return -1;
    }

    while (len) {
	ret = scif_send(psmd_epd, buf, (uint32_t)len, SCIF_SEND_BLOCK);
	if (ret < 0) {
	    if (errno == EINTR) continue;
	    return ret;
	}
	buf += ret;
	len -= ret;
    }
    return 0;
}

static int
ipath_scif_recv(void *buf, size_t len)
{
    int ret;
    while (len) {
	ret = scif_recv(psmd_epd, buf, (uint32_t)len, SCIF_RECV_BLOCK);
	if (ret < 0) {
	    if (errno == EINTR) continue;
	    return ret;
	}
	buf += ret;
	len -= ret;
    }
    return 0;
}

static int
ipath_qibp_open(void)
{
    char dev_name[MAXPATHLEN];
    int fd;

    snprintf(dev_name, sizeof(dev_name), "%s", "/dev/ipath");

    if (ipath_wait_for_device(dev_name, 0) == -1) {
        fprintf(stderr, "Could not find an InfiniPath qibp device %s\n", dev_name);
	return -1;
    }

    if ((fd = open(dev_name, O_RDWR)) == -1) {
        fprintf(stderr, "mic:Can't open %s for reading and writing\n", dev_name);
	return -1;
    }

    if(fcntl(fd, F_SETFD, FD_CLOEXEC))
        fprintf(stdout, "Failed to set close on exec for device: %s\n",
            strerror(errno));

    return fd;
}

#endif		//__MIC

int
ipath_context_open(int unit, int port, uint64_t open_timeout)
{
    int fd;

#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd;

    /*
     * Re-direct context open request to psmd on host.
     */
    cmd.type = IPATH_CMD_CONTEXT_OPEN;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;
    cmd.cmd.mic_info.data3 = open_timeout;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    fd = cmd.cmd.mic_info.data1; 
    if (fd == -1) {
	errno = cmd.cmd.mic_info.data2;
	return -1;
    }

    /*
     * Open MIC side qibp before context is assigned.
     */
    if (qibp_fd != -1) {
	fprintf(stderr, "ipath_context_open(): qibp already opened\n");
	return -1;
    }
    qibp_fd = ipath_qibp_open();
    if (qibp_fd == -1) return -1;

#else
    char dev_name[MAXPATHLEN];

    if (unit != IPATH_UNIT_ID_ANY && unit >= 0) 
	snprintf(dev_name, sizeof(dev_name), "%s%u", "/dev/ipath", unit);
    else
	snprintf(dev_name, sizeof(dev_name), "%s", "/dev/ipath");

    if (ipath_wait_for_device(dev_name, (long)open_timeout) == -1) {
        _IPATH_DBG("Could not find an InfiniPath Unit on device "
		    "%s (%lds elapsed)", dev_name, (long)open_timeout / 1000);
	return -1;
    }

    if ((fd = open(dev_name, O_RDWR)) == -1) {
        _IPATH_DBG("(host:Can't open %s for reading and writing",
		    dev_name);
	return -1;
    }

    if(fcntl(fd, F_SETFD, FD_CLOEXEC))
        _IPATH_INFO("Failed to set close on exec for device: %s\n",
            strerror(errno));
#endif

    return fd;
}

void
ipath_context_close(int fd)
{
#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_CONTEXT_CLOSE;
    cmd.cmd.mic_info.data1 = fd;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return;

    if (qibp_fd >= 0) {
	close(qibp_fd);
	qibp_fd = -1;
    }
    if (psmd_epd >= 0) {
	scif_close(psmd_epd);
	psmd_epd = -1;
    }
#else
    (void) close(fd);
#endif
}

int
ipath_cmd_writev(int fd, const struct iovec *iov, int iovcnt)
{
#ifdef __MIC__
    return writev(qibp_fd, iov, iovcnt);
#else
    return writev(fd, iov, iovcnt);
#endif
}

int
ipath_cmd_assign_context(int fd, void *buf, size_t count)
{
#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd, *pcmd;

    ret = ipath_scif_send(buf, count);
    if (ret) return ret;

    ret = ipath_scif_send(&fd, sizeof(fd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret < 0) {
	errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    pcmd = (struct ipath_cmd *)buf;
    ret = ipath_scif_recv(
	(void*)(uintptr_t)pcmd->cmd.user_info.spu_base_info,
	(int)pcmd->cmd.user_info.spu_base_info_size);
    return ret;
#else
    return write(fd, buf, count);
#endif
}

int
ipath_cmd_user_init(int fd, void *buf, size_t count)
{
#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd, *pcmd;

    ret = ipath_scif_send(buf, count);
    if (ret) return ret;

    pcmd = (struct ipath_cmd *)buf;
    ret = ipath_scif_send(
	(void*)(uintptr_t)pcmd->cmd.user_info.spu_base_info,
	(int)pcmd->cmd.user_info.spu_base_info_size);
    if (ret) return ret;

    ret = ipath_scif_send(&fd, sizeof(fd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret < 0) {
	errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    ret = ipath_scif_recv(
	(void*)(uintptr_t)pcmd->cmd.user_info.spu_base_info,
	(int)pcmd->cmd.user_info.spu_base_info_size);
    return ret;
#else
    return write(fd, buf, count);
#endif
}

int
ipath_cmd_write(int fd, struct ipath_cmd *cmd, size_t count)
{
#ifdef __MIC__
/*
following cmd are processed by mic driver:
IPATH_CMD_SDMA_COMPLETE
IPATH_CMD_SDMA_INFLIGHT
IPATH_CMD_TID_UPDATE
IPATH_CMD_TID_FREE
IPATH_CMD_MEM_INFO
*/
    int ret;

    if (cmd->type == IPATH_CMD_MIC_MEM_INFO ||
	cmd->type == IPATH_CMD_SDMA_COMPLETE ||
	cmd->type == IPATH_CMD_SDMA_INFLIGHT ||
	cmd->type == IPATH_CMD_TID_UPDATE ||
	cmd->type == IPATH_CMD_TID_FREE) {
	return write(qibp_fd, cmd, count);
    }

    ret = ipath_scif_send(cmd, count);
    if (ret) return ret;

    ret = ipath_scif_send(&fd, sizeof(fd));
    if (ret) return ret;

    ret = ipath_scif_recv(cmd, count);
    if (ret) return ret;

    ret = cmd->cmd.mic_info.data1;
    if (ret) errno = cmd->cmd.mic_info.data2;
    return ret;
#else
    return write(fd, cmd, count);
#endif
}

// we use mmap64() because we compile in both 32 and 64 bit mode,
// and we have to map physical addresses that are > 32 bits long.
// While linux implements mmap64, it doesn't have a man page,
// and isn't declared in any header file, so we declare it here ourselves.

// We'd like to just use -D_LARGEFILE64_SOURCE, to make off_t 64 bits and
// redirects mmap to mmap64 for us, but at least through suse10 and fc4,
// it doesn't work when the address being mapped is > 32 bits.  It chips
// off bits 32 and above.   So we stay with mmap64.
void *
ipath_mmap64(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset)
{
#ifdef __MIC__
    if (qibp_fd == -1) {
	fprintf(stderr, "ipath_mmap64(): qibp not opened, qibp_fd=-1\n");
	return MAP_FAILED;
    }
    fd = qibp_fd;
#endif
    return mmap64(addr, length, prot, flags, fd, offset);
}

// get the number of units supported by the driver.  Does not guarantee
// that a working chip has been found for each possible unit #.
// number of units >=0 (0 means none found).
// formerly used sysfs file "num_units"
int
ipath_get_num_units(void)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_NUM_UNITS;
    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
#else
    char pathname[128];
    struct stat st;
    int i;

    ret = 0;
    for(i=0; i<IPATH_MAX_UNIT; i++) { /* hope no more than supported units */
	    snprintf(pathname, sizeof(pathname), QIB_CLASS_PATH"%d", i);
	    if(stat(pathname, &st) || !S_ISDIR(st.st_mode))
		    continue;
	    ret++;
    }
#endif

    return ret;
}

// get the number of contexts from the unit id.
// Returns 0 if no unit or no match.
int
ipath_get_num_contexts(int unit_id)
{
    int n = 0;

#ifdef __MIC__
    struct ipath_cmd cmd;
    int ret;

    cmd.type = IPATH_CMD_GET_NUM_CTXTS;
    cmd.cmd.mic_info.unit = unit_id;
    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    n = cmd.cmd.mic_info.data1; 
    if (n == -1) errno = cmd.cmd.mic_info.data2;
#else
    int units;

    units = ipath_get_num_units();
    if (units > 0) {
	int64_t val;
	if (unit_id == IPATH_UNIT_ID_ANY) {
	  uint32_t u, p;
	    for (u = 0; u < units; u++) {
	        for (p = 1; p <= IPATH_MAX_PORT; p++)
		    if (ipath_get_port_lid(u, p) != -1)
		        break;
		if (p <= IPATH_MAX_PORT &&
		    !ipath_sysfs_unit_read_s64(u, "nctxts", &val, 0))
		    n += (uint32_t) val;
	    }
	}
	else {
	    uint32_t p;
	    for (p = 1; p <= IPATH_MAX_PORT; p++)
		if (ipath_get_port_lid(unit_id, p) != -1)
	            break;
	    if (p <= IPATH_MAX_PORT &&
		!ipath_sysfs_unit_read_s64(unit_id, "nctxts", &val, 0))
	        n += (uint32_t) val;
	}
    }
#endif

    return n;
}

// Given the unit number, return an error, or the corresponding LID
// For now, it's used only so the MPI code can determine it's own
// LID, and which other LIDs (if any) are also assigned to this node
// Returns an int, so -1 indicates an error.  0 may indicate that
// the unit is valid, but no LID has been assigned.
// No error print because we call this for both potential
// ports without knowing if both ports exist (or are connected)
int
ipath_get_port_lid(int unit, int port)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_PORT_LID;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
#else
    int64_t val;
    char *state;

    ret = ipath_sysfs_port_read(unit, port, "phys_state", &state);
    if (ret == -1) {
	    if(errno == ENODEV)
		    /* this is "normal" for port != 1, on single
		     * port chips */
		    _IPATH_VDBG("Failed to get phys_state for unit %u:%u: %s\n",
			unit, port, strerror(errno));
	    else
		    _IPATH_DBG("Failed to get phys_state for unit %u:%u: %s\n",
			unit, port, strerror(errno));
    } else {
	    if (strncmp(state, "5: LinkUp", 9)) {
		    _IPATH_DBG("!LinkUp for unit %u:%u\n", unit, port);
		    ret = -1;
	    }
	    free(state);
    }
    if (ret == -1) return ret;

    ret = ipath_sysfs_port_read_s64(unit, port, "lid", &val, 0);

    if (ret == -1) {
	    if(errno == ENODEV)
		    /* this is "normal" for port != 1, on single
		     * port chips */
		    _IPATH_VDBG("Failed to get LID for unit %u:%u: %s\n",
			unit, port, strerror(errno));
	    else
		    _IPATH_DBG("Failed to get LID for unit %u:%u: %s\n",
			unit, port, strerror(errno));
    }
    else {
        ret = val;

// disable this feature since we don't have a way to provide
// file descriptor in multiple context case.
#if 0
	if(getenv("IPATH_DIAG_LID_LOOP")) {
		// provides diagnostic ability to run MPI, etc. even
		// on loopback, by claiming a different LID for each context
		struct ipath_ctxt_info info;
		struct ipath_cmd cmd;
		cmd.type = IPATH_CMD_CTXT_INFO;
		cmd.cmd.ctxt_info = (uintptr_t) &info;
		if(__ipath_lastfd == -1)
			_IPATH_INFO("Can't run CONTEXT_INFO for lid_loop, fd not set\n");
		else if(write(__ipath_lastfd, &cmd, sizeof(cmd)) == -1)
			_IPATH_INFO("CONTEXT_INFO command failed: %s\n", strerror(errno));
		else if(!info.context)
			_IPATH_INFO("CONTEXT_INFO returned context 0!\n");
		else {
			_IPATH_PRDBG("Using lid 0x%x, base %x, context %x\n",
				ret + info.context, ret, info.context);
			ret += info.context;
		}
	}
#endif
    }
#endif

    return ret;
}

// Given the unit number, return an error, or the corresponding GID
// For now, it's used only so the MPI code can determine its fabric ID.
// Returns an int, so -1 indicates an error.
// No error print because we call this for both potential
// ports without knowing if both ports exist (or are connected)
int
ipath_get_port_gid(int unit, int port, uint64_t *hi, uint64_t *lo)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_PORT_GID;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
    else {
	*hi = cmd.cmd.mic_info.data3;
	*lo = cmd.cmd.mic_info.data4;
    }
#else
    char *gid_str = NULL;

    ret = ipath_sysfs_port_read(unit, port, "gids/0", &gid_str);

    if (ret == -1) {
	if (errno == ENODEV)
		/* this is "normal" for port != 1, on single
		 * port chips */
	    _IPATH_VDBG("Failed to get GID for unit %u:%u: %s\n",
			unit, port, strerror(errno));
	else
	    _IPATH_DBG("Failed to get GID for unit %u:%u: %s\n",
		       unit, port, strerror(errno));
    }
    else {
        unsigned int gid[8];
        if (sscanf(gid_str, "%4x:%4x:%4x:%4x:%4x:%4x:%4x:%4x", 
		   &gid[0], &gid[1], &gid[2], &gid[3],
		   &gid[4], &gid[5], &gid[6], &gid[7]) != 8) {
	    _IPATH_DBG("Failed to parse GID for unit %u:%u: %s\n",
		       unit, port, gid_str);
	    ret = -1;
	}
	else {
            *hi = (((uint64_t) gid[0]) << 48) | (((uint64_t) gid[1]) << 32) | 
	          (((uint64_t) gid[2]) << 16) | (((uint64_t) gid[3]) << 0);
            *lo = (((uint64_t) gid[4]) << 48) | (((uint64_t) gid[5]) << 32) | 
	          (((uint64_t) gid[6]) << 16) | (((uint64_t) gid[7]) << 0);
	}
        free(gid_str);
    }
#endif

    return ret;
}

// Given the unit number, return an error, or the corresponding LMC value
// for the port
// Returns an int, so -1 indicates an error.  0
int
ipath_get_port_lmc(int unit, int port)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_PORT_LMC;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
#else
    int64_t val;

    ret = ipath_sysfs_port_read_s64(unit, port, "lid_mask_count", &val, 0);

    if (ret == -1) {
      _IPATH_INFO("Failed to get LMC for unit %u:%u: %s\n",
		  unit, port, strerror(errno));	
    }
    else
      ret = val;
#endif
    
    return ret;
}

// Given the unit number, return an error, or the corresponding link rate
// for the port
// Returns an int, so -1 indicates an error. 
int
ipath_get_port_rate(int unit, int port)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_PORT_RATE;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
#else
    double rate;
    char *data_rate = NULL, *newptr;

    ret = ipath_sysfs_port_read(unit, port, "rate", &data_rate);
    if (ret == -1)
      goto get_port_rate_error;
    else {
      rate = strtod(data_rate, &newptr);
      if ((rate == 0) && (data_rate == newptr)) 
	goto get_port_rate_error;
    }
    
    free(data_rate);
    return ((int) (rate * 2) >> 1);
    
 get_port_rate_error:
    _IPATH_INFO("Failed to get link rate for unit %u:%u: %s\n",
		unit, port, strerror(errno));	
#endif

    return ret;
}

// Given a unit, port and SL, return an error, or the corresponding VL for the
// SL as programmed by the SM
// Returns an int, so -1 indicates an error.  0
int
ipath_get_port_sl2vl(int unit, int port, int sl)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_PORT_S2V;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;
    cmd.cmd.mic_info.data1 = sl;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret == -1) errno = cmd.cmd.mic_info.data2;
#else
    int64_t val;
    char sl2vlpath[16];
    
    snprintf(sl2vlpath, sizeof(sl2vlpath), "sl2vl/%d", sl);
    ret = ipath_sysfs_port_read_s64(unit, port, sl2vlpath, &val, 0);

    if (ret == -1) {
      _IPATH_DBG("Failed to get SL2VL mapping for SL %d unit %u:%u: %s\n",
		 sl, unit, port, strerror(errno));	
    }
    else
      ret = val;
#endif
    
    return ret;
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

int infinipath_get_stats_names(char **namep)
{
#ifdef __MIC__
    int ret, size;
    char *name;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_STATS_NAMES;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    size = cmd.cmd.mic_info.data2 + 1;
    name = malloc(size);
    if (!name) return -1;

    ret = ipath_scif_recv(name, size);
    if (ret) {
	free(name);
	return ret;
    }
    
    *namep = name;
    return infinipath_count_names(*namep);
#else
	int i;
	i = ipath_ipathfs_read("driver_stats_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
#endif
}

int infinipath_get_stats(uint64_t *s, int nelem)
{
#ifdef __MIC__
    int ret, n;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_STATS;
    cmd.cmd.mic_info.data1 = nelem;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    n = ret;
    ret = ipath_scif_recv(s, n*sizeof(*s));
    if (ret) {
	return ret;
    }
    return n;
#else
	int i;
	i = ipath_ipathfs_rd("driver_stats", s, nelem * sizeof(*s));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*s);
#endif
}

int infinipath_get_ctrs_unit_names(int unitno, char **namep)
{
#ifdef __MIC__
    int ret, size;
    char *name;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CTRS_UNAMES;
    cmd.cmd.mic_info.unit = unitno;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    size = cmd.cmd.mic_info.data2 + 1;
    name = malloc(size);
    if (!name) return -1;

    ret = ipath_scif_recv(name, size);
    if (ret) {
	free(name);
	return ret;
    }
    
    *namep = name;
    return infinipath_count_names(*namep);
#else
	int i;
	i =  ipath_ipathfs_unit_read(unitno, "counter_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
#endif
}

int infinipath_get_ctrs_unit(int unitno, uint64_t *c, int nelem)
{
#ifdef __MIC__
    int ret, n;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CTRS_UNIT;
    cmd.cmd.mic_info.unit = unitno;
    cmd.cmd.mic_info.data1 = nelem;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    n = ret;
    ret = ipath_scif_recv(c, n*sizeof(*c));
    if (ret) {
	return ret;
    }
    return n;
#else
	int i;
	i =  ipath_ipathfs_unit_rd(unitno, "counters", c,
		nelem * sizeof(*c));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*c);
#endif
}

int infinipath_get_ctrs_port_names(int unitno, char **namep)
{
#ifdef __MIC__
    int ret, size;
    char *name;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CTRS_PNAMES;
    cmd.cmd.mic_info.unit = unitno;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    size = cmd.cmd.mic_info.data2 + 1;
    name = malloc(size);
    if (!name) return -1;

    ret = ipath_scif_recv(name, size);
    if (ret) {
	free(name);
	return ret;
    }
    
    *namep = name;
    return infinipath_count_names(*namep);
#else
	int i;
	i =  ipath_ipathfs_unit_read(unitno, "portcounter_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
#endif
}

int infinipath_get_ctrs_port(int unitno, int port, uint64_t *c, int nelem)
{
#ifdef __MIC__
    int ret, n;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CTRS_PORT;
    cmd.cmd.mic_info.unit = unitno;
    cmd.cmd.mic_info.port = port;
    cmd.cmd.mic_info.data1 = nelem;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret <= 0) {
	if (ret == -1) errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    n = ret;
    ret = ipath_scif_recv(c, n*sizeof(*c));
    if (ret) {
	return ret;
    }
    return n;
#else
	int i;
	char buf[32];
	snprintf(buf, sizeof buf, "port%dcounters", port);
	i =  ipath_ipathfs_unit_rd(unitno, buf, c,
		nelem * sizeof(*c));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*c);
#endif
}

int
ipath_get_cc_settings_bin(int unit, int port, char *ccabuf)
{
#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CC_SETTINGS;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret != 1) return ret;

    ret = ipath_scif_recv(ccabuf, 84);
    if (ret) return ret;
#else
    int fd;

/*
 * Check qib driver CCA setting, and try to use it if available.
 * Fall to self CCA setting if errors.
 */
    sprintf(ccabuf,
	"/sys/class/infiniband/qib%d/ports/%d/CCMgtA/cc_settings_bin",
	unit, port);
    fd = open(ccabuf, O_RDONLY);
    if (fd < 0) {
	return 0;
    }
    /* (16+16+640)/8=84 */
    if (read(fd, ccabuf, 84) != 84) {
	_IPATH_CCADBG("Read cc_settings_bin failed. using static CCA\n");
	close(fd);
	return 0;
    }

    close(fd);
#endif

    return 1;
}

int
ipath_get_cc_table_bin(int unit, int port, uint16_t **cctp)
{
    int i, ccti_limit;
    uint16_t *cct;

#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_GET_CC_TABLE;
    cmd.cmd.mic_info.unit = unit;
    cmd.cmd.mic_info.port = port;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret <= 0) return ret;

    ccti_limit = ret;
    i = (ccti_limit+1)*sizeof(uint16_t);
    cct = malloc(i);
    if (!cct) {
	return -1;
    }

    ret = ipath_scif_recv(cct, i);
    if (ret) {
	free(cct);
	return ret;
    }
#else
    int fd;
    char pathname[256];

    *cctp = NULL;
    sprintf(pathname,
	"/sys/class/infiniband/qib%d/ports/%d/CCMgtA/cc_table_bin",
	unit, port);
    fd = open(pathname, O_RDONLY);
    if (fd < 0) {
	_IPATH_CCADBG("Open cc_table_bin failed. using static CCA\n");
	return 0;
    }
    if (read(fd, &ccti_limit, 2) != 2) {
	_IPATH_CCADBG("Read ccti_limit failed. using static CCA\n");
	close(fd);
	return 0;
    }
    if (ccti_limit < 63 || ccti_limit > 65535) {
	_IPATH_CCADBG("Read ccti_limit %d not in range [63, 65535], "
	    "using static CCA.\n", ccti_limit);
	close(fd);
	return 0;
    }

    i = (ccti_limit+1)*sizeof(uint16_t);
    cct = malloc(i);
    if (!cct) {
	close(fd);
	return -1;
    }
    if (read(fd, cct, i) != i) {
	_IPATH_CCADBG("Read ccti_entry_list, using static CCA\n");
	free(cct);
	close(fd);
	return 0;
    }

    close(fd);
#endif

    *cctp = cct;
    return ccti_limit;
}

/*
 * This is for diag function ipath_wait_for_packet() only
 */
int
ipath_cmd_wait_for_packet(int fd)
{
    int ret;

#ifdef __MIC__
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_WAIT_FOR_PACKET;
    cmd.cmd.mic_info.data1 = fd;
    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1;
    if (ret < 0) errno = cmd.cmd.mic_info.data2;
#else
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = POLLIN;

    ret = poll(&pfd, 1, 500 /* ms */);
#endif

    return ret;
}

/*
 * This is for diag function ipath_hideous_ioctl_emulator() only
 */
int infinipath_get_unit_flash(int unitno, char **datap)
{
#ifdef __MIC__
    int ret, size;
    char *data;
    struct ipath_cmd cmd;

    *datap = NULL;
    cmd.type = IPATH_CMD_GET_UNIT_FLASH;
    cmd.cmd.mic_info.unit = unitno;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret < 0) {
	errno = cmd.cmd.mic_info.data2;
	return ret;
    }

    size = cmd.cmd.mic_info.data2 + 1;
    data = malloc(size);
    if (!data) return -1;

    ret = ipath_scif_recv(data, size);
    if (ret) {
	free(data);
	return ret;
    }
    
    *datap = data;
    return 0;
#else
	int i;
	i =  ipath_ipathfs_unit_read(unitno, "flash", datap);
	if (i < 0)
		return -1;
	else
		return 0;
#endif
}

/*
 * This is for diag function ipath_hideous_ioctl_emulator() only
 */
int infinipath_put_unit_flash(int unitno, char *data, int len)
{
#ifdef __MIC__
    int ret;
    struct ipath_cmd cmd;

    cmd.type = IPATH_CMD_PUT_UNIT_FLASH;
    cmd.cmd.mic_info.unit = unitno;
    cmd.cmd.mic_info.data1 = len;

    ret = ipath_scif_send(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = ipath_scif_send(data, len);
    if (ret) return ret;

    ret = ipath_scif_recv(&cmd, sizeof(cmd));
    if (ret) return ret;

    ret = cmd.cmd.mic_info.data1; 
    if (ret < 0) errno = cmd.cmd.mic_info.data2;
    return ret;
#else
	int i;
	i =  ipath_ipathfs_unit_write(unitno, "flash", data, len);
	if (i < 0)
		return -1;
	else
		return 0;
#endif
}
