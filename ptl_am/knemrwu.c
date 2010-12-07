/*
 * Copyright (c) 2010. QLogic Corporation. All rights reserved.
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

#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>

#include "psm_user.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"
#include "knemrw.h"

int knem_open_device()
{
  /* Process wide knem handle */
  static int fd = -1;
  
#if defined(PSM_USE_KNEM)
  if (fd >= 0)
    return fd;
  
  fd = open(KNEM_DEVICE_FILENAME, O_RDWR);
#endif
  return fd;
}

int64_t knem_get(int fd, int64_t cookie, const void *src, int64_t n)
{
  
#if defined(PSM_USE_KNEM)
  struct knem_cmd_inline_copy c;
  struct knem_cmd_param_iovec iov;
  int err;

  iov.base = (uint64_t) (uintptr_t) src;
  iov.len = n;
  
  c.local_iovec_array = (uintptr_t) &iov;
  c.local_iovec_nr = 1;
  c.remote_cookie = cookie;
  c.remote_offset = 0;
  c.write = 0;   /* Do a Read/Get from remote memory region */
  c.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &c);

  if (c.current_status != KNEM_STATUS_SUCCESS) {
    _IPATH_INFO("KNEM: Get request of size 0x%"PRIx64" failed with error %d.\n",
		n, c.current_status);
    err = c.current_status;
  }
  
  return err;
#else
  psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR, 
		    "Attempt to use KNEM kassist (get), support for which has "
		    "not been compiled in.");
  
  return PSM_INTERNAL_ERR;
#endif
}

int64_t knem_put(int fd, const void *src, int64_t n, int64_t cookie)
{

#if defined(PSM_USE_KNEM)
  struct knem_cmd_inline_copy c;
  struct knem_cmd_param_iovec iov;
  int err;
  
  iov.base = (uint64_t) (uintptr_t) src;
  iov.len = n;
  
  c.local_iovec_array = (uintptr_t) &iov;
  c.local_iovec_nr = 1;
  c.remote_cookie = cookie;
  c.remote_offset = 0;
  c.write = 1;   /* Do a Write/Put to remote memory region */
  c.flags = 0;
  err = ioctl(fd, KNEM_CMD_INLINE_COPY, &c);

  if (c.current_status != KNEM_STATUS_SUCCESS) {
    _IPATH_INFO("KNEM: Put request of size 0x%"PRIx64" failed with error %d.\n",
		n, c.current_status);
    err = c.current_status;
  }
  
  return err;
#else
  
  psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR, 
		    "Attempt to use KNEM kassist (put), support for which has "
		    "not been compiled in.");
  
  return PSM_INTERNAL_ERR;
#endif

}

int64_t knem_register_region(void *buffer, size_t len, int write)
{

#if defined(PSM_USE_KNEM)
  struct knem_cmd_create_region create;
  struct knem_cmd_param_iovec iov;
 
  iov.base = (uint64_t) (uintptr_t) buffer;
  iov.len = len;
  create.iovec_array = (uintptr_t) &iov;
  create.iovec_nr = 1;
  create.flags = KNEM_FLAG_SINGLEUSE; /* Automatically destroy after put */
  create.protection = write ? PROT_WRITE : PROT_READ;
  
  /* AV: Handle failure in memory registration */
  ioctl(psmi_kassist_fd, KNEM_CMD_CREATE_REGION, &create);
  return create.cookie;    /* Cookie for registered memory region */
#else
  
  psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR, 
		    "Attempt to use KNEM kassist (reg), support for which has "
		    "not been compiled in.");
  return 0;
#endif

}
