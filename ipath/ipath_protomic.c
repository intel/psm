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

#ifdef __MIC__
// This file contains the initialization functions used by the low
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

#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>

#include "ipserror.h"
#include "ipath_user.h"

#include <sched.h>

#include <scif.h>

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

/*
 * unit		: bit 1-3
 * context	: bit 4-8
 * subcontext	: bit 9-11
 * type		: bit 12-16
 */
#define MAKE_KEY(unit, context, subcontext, type, subctxtcnt)	\
	(((unit)&0x7) | (((context)&0x1F)<<3) |		\
	(((subcontext)&0x7)<<8) | (((type)&0x1F)<<11) |	\
	(((subctxtcnt)&0x7)<<16))

#define GET_UNIT_FROM_KEY(key)				\
	((key)&0x7)

#define GET_CONTEXT_FROM_KEY(key)			\
	(((key)>>3)&0x1F)

/*
flags in above structure has the following bits:
0x1: map remote host buffer, offset is the SCIF offset
0x2: allocate knx memory in kernel.
0x4: allocate physically contiguous knx memory in kernel.
0x8: SCIF register knx memory, and copy offset to first 8 bytes.
*/
#define MIC_HOSTMEM_MAP			0x1
#define MIC_KNXMEM_ALLOC		0x2
#define MIC_KNXMEM_ALLOC_CONTG		0x4
#define MIC_KNXMEM_REGISTER		0x8

/*
 * Memory name to map into PSM process.
 */
#define SPI_SENDBUF_STATUS		1
#define SPI_RCVHDR_BASE			2
#define SPI_RCVHDR_TAILADDR		3
#define SPI_RCV_EGRBUFS			4
#define SPI_UREGBASE			5
#define SPI_PIOBUFBASE			6
#define SPI_PIOAVAILADDR		7
#define SPI_STATUS			8
#define SPI_SUBCTXT_UREGBASE		9
#define SPI_SUBCTXT_RCVHDR_BASE		10
#define SPI_SUBCTXT_RCVEGRBUF		11

static void ipath_setaffinity(int fd) 
{
    cpu_set_t cpuset;
    char *env;

    if(getenv("IPATH_NO_CPUAFFINITY")) {
        _IPATH_PRDBG("Skipping processor affinity, $IPATH_NO_CPUAFFINITY set\n");
        return;
    }

    env = getenv("IPATH_SET_CPUAFFINITY");
    if (!env) return;

    CPU_ZERO(&cpuset);
    CPU_SET(atoi(env), &cpuset);
    if(sched_setaffinity(0,sizeof cpuset, &cpuset)) {
	_IPATH_INFO("sched_setaffinity() failed, cpu %d\n", atoi(env));
    }

    return;
}

// It is allowed to have multiple devices (and of different types)
// simultaneously opened and initialized, although this (still! Oct 07)
// implemented.  This routine is used by the low level
// infinipath protocol code (and any other code that has similar low level
// functionality).
// This is the only routine that takes a file descriptor, rather than an
// struct _ipath_ctrl *.  The struct _ipath_ctrl * used for everything
// else is returned as part of ipath_base_info.
struct _ipath_ctrl *ipath_userinit(int fd, struct ipath_user_info *u,
                                   struct ipath_base_info *b)
{
    struct _ipath_ctrl *spctrl = NULL;
    void *tmp;
    uint64_t *tmp64;
    struct stat st;
    struct ipath_cmd c;
    size_t usize;
    uintptr_t pg_mask;
    __u64 pioavailaddr;
    __u64 sendbuf_status, rcvhdr_base, rcv_egrbufs;
    int __ipath_pg_sz;
    
    /* First get the page size */
    __ipath_pg_sz = sysconf(_SC_PAGESIZE);
    pg_mask = ~ (intptr_t) (__ipath_pg_sz - 1);

    u->spu_base_info_size = sizeof(*b);
    u->spu_base_info = (uint64_t)(uintptr_t) b;

    memset(&c, 0, sizeof(struct ipath_cmd));
    c.type = IPATH_CMD_ASSIGN_CONTEXT;
    memcpy(&c.cmd.user_info, u, sizeof(*u));

    if(ipath_cmd_assign_context(fd, &c, sizeof(c)) == -1) {
        _IPATH_INFO("assign_context command failed: %s\n", strerror(errno));
        goto err;
    }

    ipath_setaffinity(fd); // prior to memory allocation in driver, etc.

    /*
     * Allocate b->spi_sendbuf_status, one page size.
     */
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_SENDBUF_STATUS, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC|MIC_KNXMEM_REGISTER;
    c.cmd.mem_info.length = __ipath_pg_sz;
    c.cmd.mem_info.offset = 0;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
	goto err;
    }
    if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
        (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
   	    _IPATH_INFO("mmap of send buffer status page at %llx failed: %s\n",
         (long long unsigned)b->spi_sendbuf_status,
         strerror(errno));
	goto err;
    }
    else {
	_IPATH_MMDBG("mmap send buffer status page from kernel %llx to %p\n",
	    (long long unsigned)b->spi_sendbuf_status, tmp);
	// we don't try to fault these in; no need
	sendbuf_status = (uint64_t)(uintptr_t)tmp;
	if (b->spi_subcontext == 0) {
	    b->spi_sendbuf_status = (uint64_t)(*((off_t*)tmp));
	    //*((off_t*)tmp) = 0;
	}
    }

    /*
     * Allocate b->spi_rcvhdr_base.
     */
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_RCVHDR_BASE, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC_CONTG|MIC_KNXMEM_REGISTER;
    c.cmd.mem_info.length = b->spi_rcvhdrent_size*b->spi_rcvhdr_cnt*sizeof(uint32_t);
    c.cmd.mem_info.offset = 0;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
	goto err;
    }
    if((tmp=ipath_mmap64(0, b->spi_rcvhdrent_size*b->spi_rcvhdr_cnt*sizeof(uint32_t),
		   u->spu_subcontext_cnt ? PROT_READ | PROT_WRITE : PROT_READ,
		   MAP_SHARED | MAP_LOCKED,
		   fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
      _IPATH_INFO("mmap of rcvhdrq failed: %s\n", strerror(errno));
      goto err;
    }
    else {
	// for use in protocol code
	_IPATH_MMDBG("mmap rcvhdrq from kernel %llx, %lx bytes to %p\n",
	    (unsigned long long)b->spi_rcvhdr_base,
	    (unsigned long)(b->spi_rcvhdrent_size *
			    b->spi_rcvhdr_cnt*sizeof(uint32_t)), tmp);
	ipath_touch_mmap(tmp, b->spi_rcvhdrent_size*b->spi_rcvhdr_cnt*sizeof(uint32_t));
	rcvhdr_base = (uintptr_t)tmp; // set to mapped address
	if (b->spi_subcontext == 0) {
	    b->spi_rcvhdr_base = (uint64_t)(*((off_t*)tmp));
	    //*((off_t*)tmp) = 0;
	}
    }

    /*
     * Skip b->spi_rcvhdr_tailaddr.
     */
    if (b->spi_runtime_flags & IPATH_RUNTIME_NODMA_RTAIL)
      ; /* Don't mmap tail pointer if not using it. */
    else {
	_IPATH_INFO("mmap of rcvhdrq tail failed: %s\n", strerror(errno));
	goto err;
    }

    /*
     * Allocate b->spi_rcv_egrbufs.
     */
    if(!b->spi_rcv_egrbuftotlen) {
	_IPATH_ERROR("new protocol against older driver, fall back to old\n");
	goto err;
    }
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_RCV_EGRBUFS, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC|MIC_KNXMEM_REGISTER;
    c.cmd.mem_info.length = b->spi_rcv_egrbuftotlen;
    c.cmd.mem_info.offset = 0;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
	goto err;
    }
    if((tmp=ipath_mmap64(0, b->spi_rcv_egrbuftotlen,
	    PROT_READ, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	_IPATH_INFO("mmap of egr bufs from %llx failed: %s\n",
	    (long long)b->spi_rcv_egrbufs, strerror(errno));
	goto err;
    }
    else {
	_IPATH_MMDBG("mmap egr bufs of 0x%x bytes (0x%x) from kernel %llx to %p\n",
	     b->spi_rcv_egrbufsize, b->spi_rcv_egrbuftotlen,
	     (long long)b->spi_rcv_egrbufs, tmp);
	ipath_touch_mmap(tmp, b->spi_rcv_egrbuftotlen);
	rcv_egrbufs = (uint64_t)(uintptr_t)tmp;
	if (b->spi_subcontext == 0) {
	    b->spi_rcv_egrbufs = (uint64_t)(*((off_t*)tmp));
	    //*((off_t*)tmp) = 0;
	}
    }

    memset(&c, 0, sizeof(struct ipath_cmd));
    c.type = IPATH_CMD_USER_INIT;
    memcpy(&c.cmd.user_info, u, sizeof(*u));

    if(ipath_cmd_user_init(fd, &c, sizeof(c)) == -1) {
        _IPATH_INFO("userinit command failed: %s\n", strerror(errno));
        goto err;
    }
    /*
     * If header redirection is enabled, there will be a shared subcontext
     * with the kernel that we have to examine.
     */
    if (b->spi_runtime_flags & IPATH_RUNTIME_CTXT_REDIRECT)
        u->spu_subcontext_cnt = 1;

    _IPATH_PRDBG("Driver is %sQLogic-built\n",
	((1<<31)&b->spi_sw_version) ? "" : "not ");
    if((0x7fff&(b->spi_sw_version >> 16)) != IPATH_USER_SWMAJOR) {
	_IPATH_INFO
	    ("User major version 0x%x not same as driver major 0x%x\n",
	     IPATH_USER_SWMAJOR, b->spi_sw_version >> 16);
	if((b->spi_sw_version >> 16) < IPATH_USER_SWMAJOR)
	    goto err; // else assume driver knows how to be compatible
    }
    else if ((b->spi_sw_version & 0xffff) != IPATH_USER_SWMINOR) {
	_IPATH_PRDBG("User minor version 0x%x not same as driver minor 0x%x\n",
	     IPATH_USER_SWMINOR, b->spi_sw_version & 0xffff);
	if ((b->spi_sw_version & 0xffff) < IPATH_USER_SWMINOR)
	  b->spi_sendbuf_status = 0;
    }

    if (u->spu_subcontext_cnt &&
        (b->spi_sw_version & 0xffff) != IPATH_USER_SWMINOR) {
        _IPATH_INFO("Mismatched user minor version (%d) and driver "
                         "minor version (%d) while context sharing. Ensure "
                         "that driver and library are from the same "
                         "release.\n", 
	            IPATH_USER_SWMINOR,
                    (int) (b->spi_sw_version & 0xffff));
    }

    if(!(spctrl = calloc(1, sizeof(struct _ipath_ctrl)))) {
	_IPATH_INFO("can't allocate memory for ipath_ctrl: %s\n",
		strerror(errno));
	goto err;
    }

    /*  
     * Setup KNC buffers mapped to host.
     */
    b->spi_sendbuf_status = sendbuf_status;
    b->spi_rcvhdr_base = rcvhdr_base;
    b->spi_rcv_egrbufs = rcv_egrbufs;

    /* Check if we need to turn off header suppression in hardware and 
     * emulate it in software. Since the driver disables all TID flow 
     * entries we don't need to do anything just fake it that this
     * looks like Linda. 
     * Note: This will break the hardware detection heuristics where we
     * determine that a card is QLE73XX by looking at the capability to 
     * support header suppression! Need the driver to provide the requisite
     * information so we can move away from heuristics based on flags.
     */
    {
      const char *env;
      
      if ((env = getenv("IPATH_HW_HEADER_SUPPRESSION")) && (*env != '\0')) {
	int hwsupp = (int) strtol(env, NULL, 0);
	
	if (!hwsupp && (b->spi_runtime_flags & IPATH_RUNTIME_HDRSUPP)) {
	    _IPATH_INFO("Disabling hardware suppresion!\n");
	  b->spi_runtime_flags &= ~IPATH_RUNTIME_HDRSUPP;
	}
      } /* Env */
      
    }
    
      
    usize = b->spi_runtime_flags & IPATH_RUNTIME_HDRSUPP ?
      2 * __ipath_pg_sz : __ipath_pg_sz;
    _IPATH_DBG("uregbase=%llx usize=%u context=%d\n",
	       (unsigned long long) b->spi_uregbase,
	       (unsigned) usize, (int) b->spi_context);
    
    // now mmap in the rcvhdrq, egr bufs, PIO buffers and user regs
    // _ipath_uregbase is the user regs; not offset as it is in the kernel
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_UREGBASE, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_HOSTMEM_MAP;
    c.cmd.mem_info.length = usize;
    c.cmd.mem_info.offset = b->spi_uregbase;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
        goto err;
    }

    if((tmp=ipath_mmap64(0, usize, PROT_WRITE | PROT_READ,
	    MAP_SHARED | MAP_LOCKED, fd,
	    (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	_IPATH_INFO("mmap of user registers at %llx failed: %s\n",
	     (long long unsigned)b->spi_uregbase,
	     strerror(errno));
	goto err;
    }

    _IPATH_MMDBG("mmap user regs from kernel %llx to %p (0x%lx bytes)\n",
		 (long long unsigned) b->spi_uregbase, tmp, 
		 (unsigned long)usize);
    
    // we don't try to fault these in, no need
    tmp64 = (uint64_t *)tmp;
    b->spi_uregbase = (uint64_t)(uintptr_t)tmp;
    spctrl->spc_dev.spd_uregbase = (volatile uint64_t*) tmp;
    
    /*
     * Set up addresses for optimized register writeback routines.
     * This is for the real onchip registers, shared context or not
     */
    spctrl->__ipath_rcvhdrhead = (uint32_t*)&tmp64[ur_rcvhdrhead];
    spctrl->__ipath_rcvegrhead = (uint32_t*)&tmp64[ur_rcvegrindexhead];
    spctrl->__ipath_rcvegrtail = (uint32_t*)&tmp64[ur_rcvegrindextail];
    
    if (b->spi_runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
      spctrl->__ipath_rcvtail = (volatile uint32_t*)
		&spctrl->spc_dev.spd_uregbase[ur_rcvhdrtail * 8];
      b->spi_rcvhdr_tailaddr = (uint64_t) (uintptr_t)spctrl->__ipath_rcvtail;
    } else {
	_IPATH_INFO("mmap of rcvhdrq tail failed: %s\n", strerror(errno));
	goto err;
    }

    if (!(b->spi_runtime_flags & IPATH_RUNTIME_HDRSUPP)) {
      static __le32 regs[INFINIPATH_TF_NFLOWS << 1];
      static __le32 tidflow_wmb_location;
      _IPATH_DBG("HdrSupp not available. Using virt tidflow table.\n");
      spctrl->__ipath_rcvtidflow = regs;
      spctrl->__ipath_tidflow_wmb = &spctrl->tidflow_wmb_location;
    }
    else {
      spctrl->__ipath_rcvtidflow = (uint32_t*)&tmp64[ur_rcvtidflow];
      spctrl->__ipath_tidflow_wmb = (__le32*)spctrl->__ipath_rcvegrtail;
    }
    
    /* map the receive tidflow table in QLE73XX */    
    _IPATH_DBG("rcvtidfflow=%p offset=0x%lx\n", 
	       spctrl->__ipath_rcvtidflow,
	       (long) ((uintptr_t) spctrl->__ipath_rcvtidflow - (uintptr_t) tmp64));
    	
    {   char *maxpio; uint32_t numpio;
	maxpio = getenv("IPATH_MAXPIO");
	if(maxpio && (numpio=strtoul(maxpio, NULL, 0))>0 &&
	    numpio < b->spi_piocnt) {
	    _IPATH_INFO("$IPATH_MAXPIO is %u, reducing PIO buffer count from %u\n",
		numpio, b->spi_piocnt);
		b->spi_piocnt = numpio;
	}
    }

    // map in the PIO buffers, much like ureg, since it's
    // in the chip address space
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, b->spi_subcontext, SPI_PIOBUFBASE, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_HOSTMEM_MAP;
    c.cmd.mem_info.length = b->spi_pioalign*b->spi_piocnt;
    c.cmd.mem_info.offset = b->spi_piobufbase;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
        goto err;
    }

    if((tmp=ipath_mmap64(0, b->spi_pioalign*b->spi_piocnt,
	    PROT_WRITE, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	_IPATH_INFO("mmap of pio buffers at %llx failed: %s\n",
	     (long long unsigned)b->spi_piobufbase,
	     strerror(errno));
	goto err;
    }
    else {
	_IPATH_MMDBG("mmap PIO buffers from kernel %llx, %u pages to %p\n",
	    (unsigned long long)b->spi_piobufbase, b->spi_piocnt, tmp);
	// Do not try to read the PIO buffers; they are mapped write
	// only.  We'll fault them in as we write to them.
	b->spi_piobufbase = (uintptr_t)tmp;
    }

    pioavailaddr = b->spi_pioavailaddr;
    c.type = IPATH_CMD_MIC_MEM_INFO;
    c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_PIOAVAILADDR, u->spu_subcontext_cnt);
    c.cmd.mem_info.flags = MIC_HOSTMEM_MAP;
    c.cmd.mem_info.length = __ipath_pg_sz;
    c.cmd.mem_info.offset = b->spi_pioavailaddr;
    if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	_IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
        goto err;
    }

    if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	_IPATH_INFO("mmap of pioavail registers (%llx) failed: %s\n",
	    (long long)b->spi_pioavailaddr, strerror(errno));
	goto err;
    }
    else {
	volatile __le64 *pio;
	_IPATH_MMDBG("mmap pioavail from kernel 0x%llx to %p\n",
	    (long long)b->spi_pioavailaddr, tmp);
	b->spi_pioavailaddr = (uintptr_t)tmp;
	pio = (volatile __le64 *)(uintptr_t)b->spi_pioavailaddr;
	_IPATH_DBG("pioindex=0x%x, piocnt=0x%x "
	    "pioavailregs 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
	    b->spi_pioindex, b->spi_piocnt,
	    (unsigned long long)__le64_to_cpu(pio[0]),
	    (unsigned long long)__le64_to_cpu(pio[1]),
	    (unsigned long long)__le64_to_cpu(pio[2]),
	    (unsigned long long)__le64_to_cpu(pio[3]));
    }

    if ((b->spi_status & pg_mask) == (pioavailaddr & pg_mask)) {
        /* spi_status and spi_pioavailaddr are in the same page */
	uintptr_t s;
	s = b->spi_status - pioavailaddr;
	b->spi_status = (uintptr_t)tmp + s;
	spctrl->__ipath_spi_status = (__u64 volatile*)(uintptr_t)b->spi_status;
    }
    else {
	_IPATH_INFO("mmap of spi_status (%llx) failed: %s\n",
	    (long long)b->spi_status, strerror(errno));
	goto err;
    }
    _IPATH_DBG("chipstatus=0x%llx\n",
	       (unsigned long long)*spctrl->__ipath_spi_status);

    if(u->spu_subcontext_cnt) {
	unsigned num_subcontexts = u->spu_subcontext_cnt;
	size_t size;
	int i;

	size = __ipath_pg_sz * num_subcontexts;
        c.type = IPATH_CMD_MIC_MEM_INFO;
        c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_SUBCTXT_UREGBASE, u->spu_subcontext_cnt);
        c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC;
        c.cmd.mem_info.length = size;
        c.cmd.mem_info.offset = 0;
        if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	    _IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
            goto err;
        }

	if((tmp=ipath_mmap64(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	    _IPATH_INFO("mmap of subcontext uregbase array (%llx) failed: %s\n",
		(long long)b->spi_subctxt_uregbase, strerror(errno));
	    goto err;
	}
	else {
	    _IPATH_MMDBG(
		"mmap subcontext uregbase array (0x%zx) from kernel %llx to %p\n",
		size, (long long)b->spi_subctxt_uregbase, tmp);
	    ipath_touch_mmap(tmp, size);
	    
	    b->spi_subctxt_uregbase = (uint64_t)(uintptr_t)tmp;

	    for (i = 0; i < num_subcontexts; i++) {
		volatile uint64_t *uregp = (volatile uint64_t *)tmp;
		if (i == u->spu_subcontext_id) {
		    * (volatile uint32_t *) &uregp[ur_rcvhdrtail * 8] = 0;
		    * (volatile uint32_t *) &uregp[ur_rcvhdrhead * 8] = 0;
		    * (volatile uint32_t *) &uregp[ur_rcvegrindexhead * 8] = 0;
		    * (volatile uint32_t *) &uregp[ur_rcvegrindextail * 8] = 0;
		}
		tmp = (void *)((char *)tmp + __ipath_pg_sz);
	    }
	}
	size = ALIGN(b->spi_rcvhdr_cnt * b->spi_rcvhdrent_size *
		sizeof(uint32_t), __ipath_pg_sz) * num_subcontexts;
        c.type = IPATH_CMD_MIC_MEM_INFO;
        c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_SUBCTXT_RCVHDR_BASE, u->spu_subcontext_cnt);
        c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC;
        c.cmd.mem_info.length = size;
        c.cmd.mem_info.offset = 0;
        if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	    _IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
            goto err;
        }

	if((tmp=ipath_mmap64(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	    _IPATH_INFO("mmap of subcontext rcvhdr_base array (%llx) failed: %s\n",
		(long long)b->spi_subctxt_rcvhdr_base, strerror(errno));
	    goto err;
	}
	else {
	    _IPATH_MMDBG(
		"mmap subcontext rcvhdr_base array (0x%zx) from kernel %llx to %p\n",
		size, (long long)b->spi_subctxt_rcvhdr_base, tmp);
	    ipath_touch_mmap(tmp, size);
	    b->spi_subctxt_rcvhdr_base = (uint64_t)(uintptr_t)tmp;
	}

	size = b->spi_rcv_egrbuftotlen * num_subcontexts;
        c.type = IPATH_CMD_MIC_MEM_INFO;
        c.cmd.mem_info.key = MAKE_KEY(b->spi_unit, b->spi_context, 0, SPI_SUBCTXT_RCVEGRBUF, u->spu_subcontext_cnt);
        c.cmd.mem_info.flags = MIC_KNXMEM_ALLOC;
        c.cmd.mem_info.length = size;
        c.cmd.mem_info.offset = 0;
        if (ipath_cmd_write(fd, &c, sizeof(c)) == -1) {
	    _IPATH_INFO("ipath_cmd_write() call failed: %s\n", strerror(errno));
            goto err;
        }

	if((tmp=ipath_mmap64(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)c.cmd.mem_info.key<<12)) == MAP_FAILED) {
	    _IPATH_INFO("mmap of subcontext rcvegrbuf array (%llx) failed: %s\n",
		(long long)b->spi_subctxt_rcvegrbuf, strerror(errno));
	    goto err;
	}
	else {
	    _IPATH_MMDBG(
		"mmap subcontext rcvegrbuf array (0x%x) from kernel %llx to %p\n",
		b->spi_rcv_egrbuftotlen, (long long)b->spi_subctxt_rcvegrbuf,
		tmp);
	    ipath_touch_mmap(tmp, b->spi_rcv_egrbuftotlen * num_subcontexts);
	    b->spi_subctxt_rcvegrbuf = (uint64_t)(uintptr_t)tmp;
	}
    }

    spctrl->spc_dev.spd_fd = fd;
    return spctrl;
err:
    if(spctrl)
        free(spctrl);
    return NULL;
}

#endif		//__MIC__
