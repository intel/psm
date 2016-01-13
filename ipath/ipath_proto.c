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

#ifndef __MIC__
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

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))

// don't inline these; it's all init code, and not inlining makes the
// overall code shorter and easier to debug.
static void ipath_setaffinity(int) __attribute__ ((noinline));

// set the processor affinity based upon the assigned context.
// We want to do this early, before much memory is allocated
// (by user or kernel code) so that we get memory allocated on
// the node upon which we will be running.  This was done in the
// MPI init code, but that's way too late...
//
// We need to know both the context, and the unit (chip) that we are
// using.  If we have more than 2 cpus, and we have more than one
// chip, we use the unit number as part of the algorithm, so that
// we try to stay on a cpu close to the chip that we are using.
//
// This will need more work; it isn't really right yet for dual core,
// dual cpu.  We may change the command to just return the cpu that
// should be used for affinity, eventually.
// Since user contextss start at 1, we subtract one.
// The "same" code is done as part of MPI_Init, if the job is only
// using shared memory, no infinipath
static void ipath_setaffinity(int fd) 
{
    struct ipath_ctxt_info info;
    struct ipath_cmd cmd;
    cpu_set_t cpuset;

    if(getenv("IPATH_NO_CPUAFFINITY")) {
        _IPATH_PRDBG("Skipping processor affinity, $IPATH_NO_CPUAFFINITY set\n");
        return;
    }

    memset(&cmd, 0, sizeof(struct ipath_cmd));
    memset(&info, 0, sizeof(struct ipath_ctxt_info));
    cmd.type = IPATH_CMD_CTXT_INFO;
    cmd.cmd.ctxt_info = (uintptr_t) &info;
    if(ipath_cmd_write(fd, &cmd, sizeof(cmd)) == -1) {
        _IPATH_INFO("CTXT_INFO command failed: %s\n", strerror(errno));
        return;
    }
    if(!info.num_active || !info.context) {
        _IPATH_INFO("CTXT_INFO: %u active contexts unit %u:%u %u/%u, skip cpu affinity\n",
            info.num_active, info.unit, info.port, info.context, info.subcontext);
        return;
    }

    if(info.rec_cpu == (__u16)-1) {
        _IPATH_PRDBG("Skipping processor affinity, set already or no "
		     "unallocated cpu\n");
	return;
    }

    CPU_ZERO(&cpuset);
    CPU_SET(info.rec_cpu, &cpuset);
    if(sched_setaffinity(0,sizeof cpuset, &cpuset))
        _IPATH_INFO("Couldn't set runon processor %u (unit:context %u:%u) (%u active chips): %s\n",
            info.rec_cpu, info.unit, info.context, info.num_active, strerror(errno));
     else
         _IPATH_PRDBG("Set CPU affinity to %u, context %u:%u:%u (%u active chips)\n",
             info.rec_cpu, info.unit, info.context, info.subcontext, info.num_active);
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
    uint64_t uregbase;
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

#ifdef PSM_DEBUG
    _IPATH_PRDBG("spi_subcontext = %d\n", (int) b->spi_subcontext);
    _IPATH_PRDBG("spi_subctxt_uregbase = 0x%llx\n", (unsigned long long) b->spi_subctxt_uregbase);
    _IPATH_PRDBG("spi_subctxt_rcvegrbuf = 0x%llx\n", (unsigned long long) b->spi_subctxt_rcvegrbuf);
    _IPATH_PRDBG("spi_subctxt_rcvhdr_base = 0x%llx\n", (unsigned long long) b->spi_subctxt_rcvhdr_base);
    _IPATH_PRDBG("spu_subcontext_cnt = %d\n", (int) u->spu_subcontext_cnt);
    _IPATH_PRDBG("spu_subcontext_id = %d\n", (int) u->spu_subcontext_id);
#endif

    if(!(spctrl = calloc(1, sizeof(struct _ipath_ctrl)))) {
	_IPATH_INFO("can't allocate memory for ipath_ctrl: %s\n",
		strerror(errno));
	goto err;
    }

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
    uregbase = b->spi_uregbase;
    if((tmp=ipath_mmap64(0, usize, PROT_WRITE | PROT_READ,
	    MAP_SHARED | MAP_LOCKED, fd,
	    (__off64_t)b->spi_uregbase)) == MAP_FAILED) {
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
    
    if (!(b->spi_runtime_flags & IPATH_RUNTIME_HDRSUPP)) {
      _IPATH_DBG("HdrSupp not available. Using virt tidflow table.\n");
      spctrl->__ipath_rcvtidflow = spctrl->regs;
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
    if((tmp=ipath_mmap64(0, b->spi_pioalign*b->spi_piocnt,
	    PROT_WRITE, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)b->spi_piobufbase)) == MAP_FAILED) {
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

    if (b->spi_sendbuf_status) {
        if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
	        (__off64_t)b->spi_sendbuf_status)) == MAP_FAILED) {
    	    _IPATH_INFO("mmap of send buffer status page at %llx failed: %s\n",
	         (long long unsigned)b->spi_sendbuf_status,
	         strerror(errno));
	    goto err;
        }
        else {
	   _IPATH_MMDBG("mmap send buffer status page from kernel %llx to %p\n",
	        (long long unsigned)b->spi_sendbuf_status, tmp);
	    // we don't try to fault these in; no need
	    b->spi_sendbuf_status = (uint64_t)(uintptr_t)tmp;
	}
    }
    else{
      b->spi_sendbuf_status = (uint64_t)(uintptr_t) &spctrl->sendbuf_status;
    }

    /*
     * Removed reference to waldo.
     * Also needs to be read/write when context sharing so process can update the TID.
     */
    if((tmp=ipath_mmap64(0, b->spi_rcvhdrent_size*b->spi_rcvhdr_cnt*sizeof(uint32_t),
		   u->spu_subcontext_cnt ? PROT_READ | PROT_WRITE : PROT_READ,
		   MAP_SHARED | MAP_LOCKED,
		   fd, (__off64_t)b->spi_rcvhdr_base)) == MAP_FAILED) {
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
	b->spi_rcvhdr_base = (uintptr_t)tmp; // set to mapped address
    }

    if (b->spi_runtime_flags & IPATH_RUNTIME_NODMA_RTAIL) {
        /* Don't mmap tail pointer if not using it. */
	/* make tail address for false-eager-full recovery, CQ, Jul 15, 2013 */
	spctrl->__ipath_rcvtail = (volatile uint32_t*)
	    &spctrl->spc_dev.spd_uregbase[ur_rcvhdrtail * 8];
	_IPATH_MMDBG("mmap rcvhdrq tail %p\n", spctrl->__ipath_rcvtail);
	b->spi_rcvhdr_tailaddr = (uint64_t) (uintptr_t)spctrl->__ipath_rcvtail;
    }
    else if ((b->spi_rcvhdr_tailaddr & pg_mask) == (uregbase & pg_mask)) {
	uintptr_t s;
	s = b->spi_rcvhdr_tailaddr - (b->spi_rcvhdr_tailaddr & pg_mask);
	b->spi_rcvhdr_tailaddr = b->spi_uregbase + s;
	spctrl->__ipath_rcvtail = (volatile uint32_t*)(uintptr_t)b->spi_rcvhdr_tailaddr;
    }
    else if (!b->spi_rcvhdr_tailaddr) {
	/* If tailaddr is NULL, use the ureg page (for context sharing) */
	spctrl->__ipath_rcvtail = (volatile uint32_t*)
	    &spctrl->spc_dev.spd_uregbase[ur_rcvhdrtail * 8];
	_IPATH_MMDBG("mmap rcvhdrq tail %p\n", spctrl->__ipath_rcvtail);
    }
    else if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)b->spi_rcvhdr_tailaddr)) == MAP_FAILED) {
	_IPATH_INFO("mmap of rcvhdrq tail failed: %s\n", strerror(errno));
	goto err;
    }
    else {
	ipath_touch_mmap(tmp, __ipath_pg_sz);
	spctrl->__ipath_rcvtail = (volatile uint32_t*)tmp; // for use in protocol code
	_IPATH_MMDBG("mmap rcvhdrq tail from kernel %llx to %p\n",
	    (unsigned long long)b->spi_rcvhdr_tailaddr, tmp);
	/* Update baseinfo with new value of tail address */
	b->spi_rcvhdr_tailaddr = (uint64_t) (uintptr_t) tmp;
    }

    spctrl->__ipath_tidegrcnt = b->spi_tidegrcnt;
    if(!b->spi_rcv_egrbuftotlen) {
	_IPATH_ERROR("new protocol against older driver, fall back to old\n");
	b->spi_rcv_egrbuftotlen = b->spi_rcv_egrbufsize*b->spi_tidegrcnt;
    }

    if((tmp=ipath_mmap64(0, b->spi_rcv_egrbuftotlen,
	    PROT_READ, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)b->spi_rcv_egrbufs)) == MAP_FAILED) {
	_IPATH_INFO("mmap of egr bufs from %llx failed: %s\n",
	    (long long)b->spi_rcv_egrbufs, strerror(errno));
	goto err;
    }
    else {
	_IPATH_MMDBG("mmap egr bufs of 0x%x bytes (0x%x) from kernel %llx to %p\n",
	     b->spi_rcv_egrbufsize, b->spi_rcv_egrbuftotlen,
	     (long long)b->spi_rcv_egrbufs, tmp);
	ipath_touch_mmap(tmp, b->spi_rcv_egrbuftotlen);
	b->spi_rcv_egrbufs = (uint64_t)(uintptr_t)tmp;
    }

    pioavailaddr = b->spi_pioavailaddr;
    if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
	    fd, (__off64_t)b->spi_pioavailaddr)) == MAP_FAILED) {
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
    else if((tmp=ipath_mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
		 fd, (__off64_t)(b->spi_status & pg_mask))) == MAP_FAILED) {
	_IPATH_INFO("mmap of spi_status (%llx) failed: %s\n",
	    (long long)b->spi_status, strerror(errno));
	goto err;
    }
    else {
        /* spi_status and spi_pioavailaddr are in different pages */
	uintptr_t s;
	_IPATH_MMDBG("mmap spi_status from kernel 0x%llx to %p\n",
	    (long long)b->spi_status, tmp);
	s = b->spi_status - (b->spi_status & pg_mask);
	b->spi_status = (uintptr_t)tmp + s;
	spctrl->__ipath_spi_status = (__u64 volatile*)(uintptr_t)b->spi_status;
    }
    _IPATH_DBG("chipstatus=0x%llx\n",
	       (unsigned long long)*spctrl->__ipath_spi_status);

    if(u->spu_subcontext_cnt > 0) {
	unsigned num_subcontexts = u->spu_subcontext_cnt;
	size_t size;
	int i;

	size = __ipath_pg_sz * num_subcontexts;
	if((tmp=ipath_mmap64(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)b->spi_subctxt_uregbase)) == MAP_FAILED) {
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
		tmp = (void *)((char*)tmp + __ipath_pg_sz);
	    }
	}
	size = ALIGN(b->spi_rcvhdr_cnt * b->spi_rcvhdrent_size *
		sizeof(uint32_t), __ipath_pg_sz) * num_subcontexts;
	if((tmp=ipath_mmap64(0, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)b->spi_subctxt_rcvhdr_base)) == MAP_FAILED) {
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
	if((tmp=ipath_mmap64(0, b->spi_rcv_egrbuftotlen * num_subcontexts,
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
		fd, (__off64_t)b->spi_subctxt_rcvegrbuf)) == MAP_FAILED) {
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
    if(fstat(fd, &st)) {
	_IPATH_INFO("can't stat infinipath device to determine type: %s\n",
	    strerror(errno));
	goto err;
    }
    else if(!S_ISCHR(st.st_mode)) {
	// shouldn't ever happen, since the commands worked, but...
	_IPATH_INFO("file descriptor is not for a real device, failing\n");
	goto err;
    }
    spctrl->spc_dev.spd_type = minor(st.st_rdev);
    return spctrl;
err:
    if(spctrl)
        free(spctrl);
    return NULL;
}

#endif		//__MIC__
