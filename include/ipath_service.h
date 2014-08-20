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

#ifndef _IPATH_SERVICE_H
#define _IPATH_SERVICE_H

//  This file contains all the lowest level routines calling into sysfs
//  and qib driver. All other calls are based on these routines.

#include "ipath_intf.h"
#include "ipath_common.h"
#include "ipath_udebug.h"

// any unit id to match.
#define IPATH_UNIT_ID_ANY ((long)-1)

// Given the unit number and port, return an error, or the corresponding LID
// Returns an int, so -1 indicates an error.  0 indicates that
// the unit is valid, but no LID has been assigned.
int ipath_get_port_lid(int, int);

// Given the unit number and port, return an error, or the corresponding GID
// Returns an int, so -1 indicates an error.
int ipath_get_port_gid(int, int, uint64_t *hi, uint64_t *lo);

// Given the unit number, return an error, or the corresponding LMC value
// for the port
// Returns an int, so -1 indicates an error.  0
int ipath_get_port_lmc(int unit, int port);

// Given the unit number, return an error, or the corresponding link rate
// for the port
// Returns an int, so -1 indicates an error. 
int ipath_get_port_rate(int unit, int port);

// Given a unit, port and SL, return an error, or the corresponding VL for the
// SL as programmed by the SM
// Returns an int, so -1 indicates an error.
int ipath_get_port_sl2vl(int unit, int port, int sl);

// get the number of units supported by the driver.  Does not guarantee
// that a working chip has been found for each possible unit #.  Returns
// -1 with errno set, or number of units >=0 (0 means none found).
int ipath_get_num_units(void);

// get the number of contexts from the unit id.
// Returns 0 if no unit or no match.
int ipath_get_num_contexts(int unit);

// Open ipath device file, return -1 on error.
int ipath_context_open(int unit, int port, uint64_t open_timeout);
void ipath_context_close(int fd);
int ipath_cmd_write(int fd, struct ipath_cmd *, size_t count);
int ipath_cmd_writev(int fd, const struct iovec *iov, int iovcnt);
int ipath_cmd_assign_context(int fd, void *buf, size_t count);
int ipath_cmd_user_init(int fd, void *buf, size_t count);

int ipath_get_cc_settings_bin(int unit, int port, char *ccabuf);
int ipath_get_cc_table_bin(int unit, int port, uint16_t **cctp);

// we use mmap64() because we compile in both 32 and 64 bit mode,
// and we have to map physical addresses that are > 32 bits long.
// While linux implements mmap64, it doesn't have a man page,
// and isn't declared in any header file, so we declare it here ourselves.

// We'd like to just use -D_LARGEFILE64_SOURCE, to make off_t 64 bits and
// redirects mmap to mmap64 for us, but at least through suse10 and fc4,
// it doesn't work when the address being mapped is > 32 bits.  It chips
// off bits 32 and above.   So we stay with mmap64.
extern void *mmap64(void *, size_t, int, int, int, __off64_t);
void *ipath_mmap64(void *, size_t, int, int, int, __off64_t);

// Statistics maintained by the driver
int infinipath_get_stats(uint64_t *, int);
int infinipath_get_stats_names(char **namep);
// Counters maintained in the chip, globally, and per-prot
int infinipath_get_ctrs_unit(int unitno, uint64_t *, int);
int infinipath_get_ctrs_unit_names(int unitno, char **namep);
int infinipath_get_ctrs_port(int unitno, int port, uint64_t *, int);
int infinipath_get_ctrs_port_names(int unitno, char **namep);

/* sysfs helper routines (only those currently used are exported;
 * try to avoid using others) */

/* base name of path (without unit #) for qib driver */
#define QIB_CLASS_PATH "/sys/class/infiniband/qib"

/* read a signed 64-bit quantity, in some arbitrary base */
int ipath_sysfs_read_s64(const char *attr, int64_t *valp, int base);

/* read a string value */
int ipath_sysfs_port_read(uint32_t unit, uint32_t port, const char *attr,
			  char **datap);

/* open attribute in unit's sysfs directory via open(2) */
int ipath_sysfs_unit_open(uint32_t unit, const char *attr, int flags);
/* print to attribute in {unit,port} sysfs directory */
int ipath_sysfs_port_printf(uint32_t unit, uint32_t port, const char *attr,
			    const char *fmt, ...)
  __attribute__((format(printf, 4, 5)));
int ipath_sysfs_unit_printf(uint32_t unit, const char *attr,
			    const char *fmt, ...)
  __attribute__((format(printf, 3, 4)));

int ipath_ipathfs_unit_write(uint32_t unit, const char *attr, const void *data,
	size_t len);
/* read up to one page of malloc'ed data (caller must free), returning
   number of bytes read or -1 */
int ipath_ipathfs_read(const char *attr, char **datap);
int ipath_ipathfs_unit_read(uint32_t unit, const char *attr, char **data);
/* read a signed 64-bit quantity, in some arbitrary base */
int ipath_sysfs_unit_read_s64(uint32_t unit, const char *attr,
			      int64_t *valp, int base);
int ipath_sysfs_port_read_s64(uint32_t unit, uint32_t port, const char *attr,
			      int64_t *valp, int base);
/* these read directly into supplied buffer and take a count */
int ipath_ipathfs_rd(const char *, void *, int);
int ipath_ipathfs_unit_rd(uint32_t unit, const char *, void *, int);

int ipath_ipathfs_open(const char *relname, int flags);

/* wait for device special file to show up. timeout is in
 *    milliseconds, 0 is "callee knows best", < 0 is infinite. */
int ipath_wait_for_device(const char *path, long timeout);

int ipath_cmd_wait_for_packet(int fd);
int infinipath_get_unit_flash(int unit, char **datap);
int infinipath_put_unit_flash(int unit, char *data, int len);

#endif				// _IPATH_SERVICE_H
