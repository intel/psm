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

#ifndef __MIC__
// This file contains a simple sysfs interface used by the low level
// infinipath protocol code.  It also implements the interface to ipathfs.

#include <sys/types.h>
#include <sys/stat.h>
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

#include "ipath_service.h"

static char *sysfs_path;
static size_t sysfs_path_len;
static char *ipathfs_path;
static long sysfs_page_size;

static void __attribute__((constructor)) sysfs_init(void)
{
    struct stat s;
    if (sysfs_path == NULL)
        sysfs_path = getenv("IPATH_SYSFS_PATH");
    if (sysfs_path == NULL) {
	static char syspath[64];
	snprintf(syspath, sizeof(syspath),
		"%s%d", QIB_CLASS_PATH, 0);
	sysfs_path = syspath;
    }
    if(stat(sysfs_path, &s) || !S_ISDIR(s.st_mode))
	    _IPATH_DBG("Did not find sysfs directory %s, using anyway\n",
		    sysfs_path);
    sysfs_path_len = strlen(sysfs_path);

    if (ipathfs_path == NULL)
        ipathfs_path = getenv("IPATH_IPATHFS_PATH");
    if (ipathfs_path == NULL)
        ipathfs_path = "/ipathfs";

    if (!sysfs_page_size)
        sysfs_page_size = sysconf(_SC_PAGESIZE);
}

const char *ipath_sysfs_path(void)
{
    return sysfs_path;
}

size_t ipath_sysfs_path_len(void)
{
    return sysfs_path_len;
}

const char *ipath_ipathfs_path(void)
{
    return ipathfs_path;
}

int ipath_sysfs_open(const char *attr, int flags)
{
    char buf[1024];
    int saved_errno;
    int fd;

    snprintf(buf, sizeof(buf), "%s/%s", ipath_sysfs_path(), attr);
    fd = open(buf, flags);
    saved_errno = errno;

    if (fd == -1) {
        _IPATH_DBG("Failed to open driver attribute '%s': %s\n", attr,
                   strerror(errno));
        _IPATH_DBG("Offending file name: %s\n", buf);
    }

    errno = saved_errno;
    return fd;
}

int ipath_ipathfs_open(const char *attr, int flags)
{
    char buf[1024];
    int saved_errno;
    int fd;

    snprintf(buf, sizeof(buf), "%s/%s", ipath_ipathfs_path(), attr);
    fd = open(buf, flags);
    saved_errno = errno;

    if (fd == -1) {
        _IPATH_DBG("Failed to open driver attribute '%s': %s\n", attr,
                   strerror(errno));
        _IPATH_DBG("Offending file name: %s\n", buf);
    }

    errno = saved_errno;
    return fd;
}

static int sysfs_vprintf(int fd, const char *fmt, va_list ap)
{
    char *buf;
    int len, ret;
    int saved_errno;

    buf = alloca(sysfs_page_size);
    len = vsnprintf(buf, sysfs_page_size, fmt, ap);

    if (len > sysfs_page_size) {
        _IPATH_DBG("Attempt to write more (%d) than %ld bytes\n", len,
                   sysfs_page_size);
        saved_errno = EINVAL;
        ret = -1;
        goto bail;
    }

    ret = write(fd, buf, len);
    saved_errno = errno;

    if (ret != -1 && ret < len) {
        _IPATH_DBG("Write ran short (%d < %d)\n", ret, len);
        saved_errno = EAGAIN;
        ret = -1;
    }

bail:
    errno = saved_errno;
    return ret;
}

int ipath_sysfs_printf(const char *attr, const char *fmt, ...)
{
    int fd = -1;
    va_list ap;
    int ret = -1;
    int saved_errno;

    fd = ipath_sysfs_open(attr, O_WRONLY);
    saved_errno = errno;

    if (fd == -1) {
        goto bail;
    }

    va_start(ap, fmt);
    ret = sysfs_vprintf(fd, fmt, ap);
    saved_errno = errno;
    va_end(ap);

    if (ret == -1) {
        _IPATH_DBG("Failed to write to driver attribute '%s': %s\n", attr,
                   strerror(errno));
    }

bail:
    if (fd != -1)
        close(fd);

    errno = saved_errno;
    return ret;
}

int ipath_sysfs_unit_open(uint32_t unit, const char *attr, int flags)
{
    int saved_errno;
    char buf[1024];
    int fd;
    int len, l;

    snprintf(buf, sizeof(buf), "%s", ipath_sysfs_path());
    len = l = strlen(buf) - 1;
    while(l > 0 && isdigit(buf[l]))
	l--;
    if(l)
	buf[++l] = 0;
    else
	l = len; /* assume they know what they are doing */
    snprintf(buf+l, sizeof(buf)-l, "%u/%s", unit, attr);
    fd = open(buf, flags);
    saved_errno = errno;

    if (fd == -1) {
        _IPATH_DBG("Failed to open attribute '%s' of unit %d: %s\n", attr,
                   unit, strerror(errno));
        _IPATH_DBG("Offending file name: %s\n", buf);
    }

    errno = saved_errno;
    return fd;
}

int ipath_sysfs_port_open(uint32_t unit, uint32_t port, const char *attr,
	int flags)
{
    int saved_errno;
    char buf[1024];
    int fd;
    int len, l;

    snprintf(buf, sizeof(buf), "%s", ipath_sysfs_path());
    len = l = strlen(buf) - 1;
    while(l > 0 && isdigit(buf[l]))
	l--;
    if(l)
	buf[++l] = 0;
    else
	l = len; /* assume they know what they are doing */
    snprintf(buf+l, sizeof(buf)-l, "%u/ports/%u/%s", unit, port, attr);
    fd = open(buf, flags);
    saved_errno = errno;

    if (fd == -1) {
        _IPATH_DBG("Failed to open attribute '%s' of unit %d:%d: %s\n", attr,
                   unit, port, strerror(errno));
        _IPATH_DBG("Offending file name: %s\n", buf);
    }

    errno = saved_errno;
    return fd;
}

int ipath_ipathfs_unit_open(uint32_t unit, const char *attr, int flags)
{
    int saved_errno;
    char buf[1024];
    int fd;

    snprintf(buf, sizeof(buf), "%s/%u/%s", ipath_ipathfs_path(), unit, attr);
    fd = open(buf, flags);
    saved_errno = errno;

    if (fd == -1) {
        _IPATH_DBG("Failed to open attribute '%s' of unit %d: %s\n", attr,
                   unit, strerror(errno));
        _IPATH_DBG("Offending file name: %s\n", buf);
    }

    errno = saved_errno;
    return fd;
}

int ipath_sysfs_port_printf(uint32_t unit, uint32_t port, const char *attr,
                            const char *fmt, ...)
{
    va_list ap;
    int ret = -1;
    int saved_errno;
    int fd;

    fd = ipath_sysfs_port_open(unit, port, attr, O_WRONLY);
    saved_errno = errno;

    if (fd == -1) {
        goto bail;
    }

    va_start(ap, fmt);
    ret = sysfs_vprintf(fd, fmt, ap);
    saved_errno = errno;
    va_end(ap);

    if (ret == -1) {
        _IPATH_DBG("Failed to write to attribute '%s' of unit %d: %s\n", attr,
                   unit, strerror(errno));
    }

bail:
    if (fd != -1)
        close(fd);

    errno = saved_errno;
    return ret;
}

int ipath_sysfs_unit_printf(uint32_t unit, const char *attr,
                            const char *fmt, ...)
{
    va_list ap;
    int ret = -1;
    int saved_errno;
    int fd;

    fd = ipath_sysfs_unit_open(unit, attr, O_WRONLY);
    saved_errno = errno;

    if (fd == -1) {
        goto bail;
    }

    va_start(ap, fmt);
    ret = sysfs_vprintf(fd, fmt, ap);
    saved_errno = errno;
    va_end(ap);

    if (ret == -1) {
        _IPATH_DBG("Failed to write to attribute '%s' of unit %d: %s\n", attr,
                   unit, strerror(errno));
    }

bail:
    if (fd != -1)
        close(fd);

    errno = saved_errno;
    return ret;
}

static int read_page(int fd, char **datap)
{
    char *data = NULL;
    int saved_errno;
    int ret = -1;

    data = malloc(sysfs_page_size);
    saved_errno = errno;

    if (!data) {
        _IPATH_DBG("Could not allocate memory: %s\n", strerror(errno));
        goto bail;
    }

    ret = read(fd, data, sysfs_page_size);
    saved_errno = errno;

    if (ret == -1) {
        _IPATH_DBG("Read of attribute failed: %s\n", strerror(errno));
        goto bail;
    }

bail:
    if (ret == -1) {
        free(data);
    } else {
        *datap = data;
    }

    errno = saved_errno;
    return ret;
}

/*
 * On return, caller must free *datap.
 */
int ipath_sysfs_read(const char *attr, char **datap)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_sysfs_open(attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read_page(fd, datap);
    saved_errno = errno;

bail:
    if (ret == -1)
        *datap = NULL;

    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

/*
 * On return, caller must free *datap.
 */
int ipath_sysfs_unit_read(uint32_t unit, const char *attr, char **datap)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_sysfs_unit_open(unit, attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read_page(fd, datap);
    saved_errno = errno;

bail:
    if (ret == -1)
        *datap = NULL;

    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

/*
 * On return, caller must free *datap.
 */
int ipath_sysfs_port_read(uint32_t unit, uint32_t port, const char *attr,
	char **datap)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_sysfs_port_open(unit, port, attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read_page(fd, datap);
    saved_errno = errno;

bail:
    if (ret == -1)
        *datap = NULL;

    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

int ipath_sysfs_unit_write(uint32_t unit, const char *attr, const void *data,
                           size_t len)
{
    int fd = -1, ret = -1;
    int saved_errno;

    if (len > sysfs_page_size) {
        _IPATH_DBG("Attempt to write more (%ld) than %ld bytes\n", (long) len,
                   sysfs_page_size);
        saved_errno = EINVAL;
        goto bail;
    }

    fd = ipath_sysfs_unit_open(unit, attr, O_WRONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = write(fd, data, len);
    saved_errno = errno;

    if (ret == -1) {
        _IPATH_DBG("Attempt to write %ld bytes failed: %s\n",
                   (long) len, strerror(errno));
        goto bail;
    }

    if (ret < len) { // sysfs routines can routine count including null byte
        // so don't return an error if it's > len
        _IPATH_DBG("Attempt to write %ld bytes came up short (%ld bytes)\n",
                   (long) len, (long) ret);
        saved_errno = EAGAIN;
        ret = -1;
    }

bail:
    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

/*
 * On return, caller must free *datap.
 */
int ipath_ipathfs_read(const char *attr, char **datap)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_ipathfs_open(attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read_page(fd, datap);
    saved_errno = errno;

bail:
    if (ret == -1)
        *datap = NULL;

    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

/*
 * On return, caller must free *datap.
 */
int ipath_ipathfs_unit_read(uint32_t unit, const char *attr, char **datap)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_ipathfs_unit_open(unit, attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read_page(fd, datap);
    saved_errno = errno;

bail:
    if (ret == -1)
        *datap = NULL;

    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

/*
 * The _rd routines jread directly into a supplied buffer,
 * unlike  the _read routines.
 */
int ipath_ipathfs_rd(const char *attr, void *buf, int n)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_ipathfs_open(attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read(fd, buf, n);
    saved_errno = errno;

bail:
    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

int ipath_ipathfs_unit_rd(uint32_t unit, const char *attr, void *buf, int n)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_ipathfs_unit_open(unit, attr, O_RDONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = read(fd, buf, n);
    saved_errno = errno;

bail:
    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

int ipath_ipathfs_unit_write(uint32_t unit, const char *attr, const void *data,
                             size_t len)
{
    int fd = -1, ret = -1;
    int saved_errno;

    fd = ipath_ipathfs_unit_open(unit, attr, O_WRONLY);
    saved_errno = errno;

    if (fd == -1)
        goto bail;

    ret = write(fd, data, len);
    saved_errno = errno;

    if (ret == -1) {
        _IPATH_DBG("Attempt to write %ld bytes failed: %s\n",
                   (long) len, strerror(errno));
        goto bail;
    }

    if (ret != len) {
        _IPATH_DBG("Attempt to write %ld bytes came up short (%ld bytes)\n",
                   (long) len, (long) ret);
        saved_errno = EAGAIN;
        ret = -1;
    }

bail:
    if (fd != -1) {
        close(fd);
    }

    errno = saved_errno;
    return ret;
}

int ipath_sysfs_read_s64(const char *attr, int64_t *valp, int base)
{
    char *data, *end;
    int ret;
    int saved_errno;
    long long val;

    ret = ipath_sysfs_read(attr, &data);
    saved_errno = errno;

    if (ret == -1) {
        goto bail;
    }

    val = strtoll(data, &end, base);
    saved_errno = errno;

    if (!*data || !(*end == '\0' || isspace(*end))) {
        ret = -1;
        goto bail;
    }

    *valp = val;
    ret = 0;

bail:
    free(data);
    errno = saved_errno;
    return ret;
}

int ipath_sysfs_unit_read_s64(uint32_t unit, const char *attr,
                              int64_t *valp, int base)
{
    char *data, *end;
    int saved_errno;
    long long val;
    int ret;

    ret = ipath_sysfs_unit_read(unit, attr, &data);
    saved_errno = errno;

    if (ret == -1) {
        goto bail;
    }

    val = strtoll(data, &end, base);
    saved_errno = errno;

    if (!*data || !(*end == '\0' || isspace(*end))) {
        ret = -1;
        goto bail;
    }

    *valp = val;
    ret = 0;

bail:
    free(data);
    errno = saved_errno;
    return ret;
}

int ipath_sysfs_port_read_s64(uint32_t unit, uint32_t port, const char *attr,
                              int64_t *valp, int base)
{
    char *data, *end;
    int saved_errno;
    long long val;
    int ret;

    ret = ipath_sysfs_port_read(unit, port, attr, &data);
    saved_errno = errno;

    if (ret == -1) {
        goto bail;
    }

    val = strtoll(data, &end, base);
    saved_errno = errno;

    if (!*data || !(*end == '\0' || isspace(*end))) {
        ret = -1;
        goto bail;
    }

    *valp = val;
    ret = 0;

bail:
    free(data);
    errno = saved_errno;
    return ret;
}

#endif		//__MIC__
