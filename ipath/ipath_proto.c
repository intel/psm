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

// we use mmap64() because we compile in both 32 and 64 bit mode,
// and we have to map physical addresses that are > 32 bits long.
// While linux implements mmap64, it doesn't have a man page,
// and isn't declared in any header file, so we declare it here ourselves.

// We'd like to just use -D_LARGEFILE64_SOURCE, to make off_t 64 bits and
// redirects mmap to mmap64 for us, but at least through suse10 and fc4,
// it doesn't work when the address being mapped is > 32 bits.  It chips
// off bits 32 and above.   So we stay with mmap64.
extern void *mmap64(void *, size_t, int, int, int, __off64_t);

// don't inline these; it's all init code, and not inlining makes the
// overall code shorter and easier to debug.
static void ipath_setaffinity(int) __attribute__ ((noinline));
static void ipath_touch_mmap(void *, size_t) __attribute__ ((noinline));

int __ipath_malloc_no_mmap = 0; // keep track whether we disabled mmap in malloc

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
    if(write(fd, &cmd, sizeof(cmd)) == -1) {
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

    if(write(fd, &c, sizeof(c)) == -1) {
        _IPATH_INFO("assign_context command failed: %s\n", strerror(errno));
        goto err;
    }

    ipath_setaffinity(fd); // prior to memory allocation in driver, etc.

    c.type = IPATH_CMD_USER_INIT;
    memcpy(&c.cmd.user_info, u, sizeof(*u));

    if(write(fd, &c, sizeof(c)) == -1) {
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

    _IPATH_PRDBG("Runtime flags are 0x%x, explicit mallopt mmap disable "
		"in malloc is %s\n", b->spi_runtime_flags, 
		__ipath_malloc_no_mmap ? "on" : "off");

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
    if((tmp=mmap64(0, usize, PROT_WRITE | PROT_READ,
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
    if((tmp=mmap64(0, b->spi_pioalign*b->spi_piocnt,
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
        if((tmp=mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED, fd,
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
    if((tmp=mmap64(0, b->spi_rcvhdrent_size*b->spi_rcvhdr_cnt*sizeof(uint32_t),
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
    else if((tmp=mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
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

    if((tmp=mmap64(0, b->spi_rcv_egrbuftotlen,
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
    if((tmp=mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
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
	b->spi_status = (uintptr_t)(tmp + s);
	spctrl->__ipath_spi_status = (__u64 volatile*)(uintptr_t)b->spi_status;
    }
    else if((tmp=mmap64(0, __ipath_pg_sz, PROT_READ, MAP_SHARED | MAP_LOCKED,
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
	b->spi_status = (uintptr_t)(tmp + s);
	spctrl->__ipath_spi_status = (__u64 volatile*)(uintptr_t)b->spi_status;
    }
    _IPATH_DBG("chipstatus=0x%llx\n",
	       (unsigned long long)*spctrl->__ipath_spi_status);

    if(u->spu_subcontext_cnt) {
	unsigned num_subcontexts = u->spu_subcontext_cnt;
	size_t size;
	int i;

	size = __ipath_pg_sz * num_subcontexts;
	if((tmp=mmap64(0, size, PROT_READ | PROT_WRITE,
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
		tmp += __ipath_pg_sz;
	    }
	}
	size = ALIGN(b->spi_rcvhdr_cnt * b->spi_rcvhdrent_size *
		sizeof(uint32_t), __ipath_pg_sz) * num_subcontexts;
	if((tmp=mmap64(0, size, PROT_READ | PROT_WRITE,
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
	if((tmp=mmap64(0, b->spi_rcv_egrbuftotlen * num_subcontexts,
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

// get the number of units supported by the driver.  Does not guarantee
// that a working chip has been found for each possible unit #.
// number of units >=0 (0 means none found).
// formerly used sysfs file "num_units"
int ipath_get_num_units(void)
{
    int ret;
    char pathname[128];
    struct stat st;

    for(ret=0; ; ret++) {
	    snprintf(pathname, sizeof(pathname), QIB_CLASS_PATH"%d", ret);
	    if(stat(pathname, &st) || !S_ISDIR(st.st_mode))
		    break;
    }

    return ret;
}

// Given the unit number, return an error, or the corresponding LID
// For now, it's used only so the MPI code can determine it's own
// LID, and which other LIDs (if any) are also assigned to this node
// Returns an int, so -1 indicates an error.  0 may indicate that
// the unit is valid, but no LID has been assigned.
// No error print because we call this for both potential
// ports without knowing if both ports exist (or are connected)
int ipath_get_port_lid(uint16_t unit, uint16_t port)
{
    int64_t val;
    char *state;
    int ret;

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
    } else if (strncmp(state, "5: LinkUp", 9)) {
	    _IPATH_DBG("!LinkUp for unit %u:%u\n", unit, port);
	    ret = -1;
    }
    free(state);
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

    return ret;
}

// Given the unit number, return an error, or the corresponding GID
// For now, it's used only so the MPI code can determine its fabric ID.
// Returns an int, so -1 indicates an error.
// No error print because we call this for both potential
// ports without knowing if both ports exist (or are connected)
int ipath_get_port_gid(uint16_t unit, uint16_t port,
                       uint64_t *hi, uint64_t *lo)
{
    char *gid_str = NULL;
    int ret;

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
        int gid[8];
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

    return ret;
}

// Given the unit number, return an error, or the corresponding LMC value
// for the port
// Returns an int, so -1 indicates an error.  0
int ipath_get_port_lmc(uint16_t unit, uint16_t port)
{
    int64_t val;
    int ret;

    ret = ipath_sysfs_port_read_s64(unit, port, "lid_mask_count", &val, 0);

    if (ret == -1) {
      _IPATH_INFO("Failed to get LMC for unit %u:%u: %s\n",
		  unit, port, strerror(errno));	
    }
    else
      ret = val;
    
    return ret;
}

// Given the unit number, return an error, or the corresponding link rate
// for the port
// Returns an int, so -1 indicates an error. 
int ipath_get_port_rate(uint16_t unit, uint16_t port)
{
    double rate;
    char *data_rate = NULL, *newptr;
    int ret;

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
    return ret;
}

// Given a unit, port and SL, return an error, or the corresponding VL for the
// SL as programmed by the SM
// Returns an int, so -1 indicates an error.  0
int ipath_get_port_sl2vl(uint16_t unit, uint16_t port, uint8_t sl)
{
    int64_t val;
    int ret;
    char sl2vlpath[16];
    
    snprintf(sl2vlpath, sizeof(sl2vlpath), "sl2vl/%d", sl);
    ret = ipath_sysfs_port_read_s64(unit, port, sl2vlpath, &val, 0);

    if (ret == -1) {
      _IPATH_DBG("Failed to get SL2VL mapping for SL %d unit %u:%u: %s\n",
		 sl, unit, port, strerror(errno));	
    }
    else
      ret = val;
    
    return ret;
}

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
static void ipath_touch_mmap(void *m, size_t bytes)
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

    if(write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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

    if(write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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

    if(write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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

    if(write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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

    if (write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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

    if (write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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
    if ((ret = write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd))) == -1) {
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
    if ((ret = write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd))) == -1) {
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

    if(write(ctrl->spc_dev.spd_fd, &cmd, sizeof(cmd)) == -1) {
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
    struct pollfd pfd;
    int ret;

    pfd.fd = ctrl->spc_dev.spd_fd;
    pfd.events = POLLIN;

    ret = poll(&pfd, 1, 500 /* ms */);

    return ret;
}

int ipath_hideous_ioctl_emulator(int unit, int reqtype, struct ipath_eeprom_req *req)
{
    switch (reqtype) {
    case IPATH_READ_EEPROM:
    {
        // Emulate a read of a byte range by doing a full read, then
        // getting the bits we want.
        char *data;

        if (ipath_ipathfs_unit_read(unit, "flash", &data) == -1)
            return -1;

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

        len = ipath_ipathfs_unit_read(unit, "flash", &data);

        if (len == -1)
            return -1;

        memcpy(data + req->offset, (char *) (unsigned long) req->addr,
               req->len);

        if (ipath_ipathfs_unit_write(unit, "flash", data, len) == -1) {
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

int infinipath_get_stats_names(char **namep)
{
	int i;
	i = ipath_ipathfs_read("driver_stats_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
}

int infinipath_get_stats_names_count()
{
	char *namep;
	int c;

	c = infinipath_get_stats_names(&namep);
	free(namep);
	return c;
}

int infinipath_get_stats(uint64_t *s, int nelem)
{
	int i;
	i = ipath_ipathfs_rd("driver_stats", s, nelem * sizeof(*s));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*s);
}

int infinipath_get_ctrs_unit_names(int unitno, char **namep)
{
	int i;
	i =  ipath_ipathfs_unit_read(unitno, "counter_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
}

int infinipath_get_ctrs_unit_names_count(int unitno)
{
	char *namep;
	int c;

	c = infinipath_get_ctrs_unit_names(unitno, &namep);
	free(namep);
	return c;
}

int infinipath_get_ctrs_unit(int unitno, uint64_t *c, int nelem)
{
	int i;
	i =  ipath_ipathfs_unit_rd(unitno, "counters", c,
		nelem * sizeof(*c));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*c);
}

int infinipath_get_ctrs_port_names(int unitno, char **namep)
{
	int i;
	i =  ipath_ipathfs_unit_read(unitno, "portcounter_names", namep);
	if (i < 0)
		return -1;
	else
		return infinipath_count_names(*namep);
}

int infinipath_get_ctrs_port_names_count(int unitno)
{
	char *namep;
	int c;

	c = infinipath_get_ctrs_port_names(unitno, &namep);
	free(namep);
	return c;
}

int infinipath_get_ctrs_port(int unitno, int port, uint64_t *c, int nelem)
{
	int i;
	char buf[32];
	snprintf(buf, sizeof buf, "port%dcounters", port);
	i =  ipath_ipathfs_unit_rd(unitno, buf, c,
		nelem * sizeof(*c));
	if(i < 0)
		return -1;
	else
		return i / sizeof(*c);
}

int infinipath_lookup_stat(const char *attr, char *namep, uint64_t *stats,
			   uint64_t *s)
{
	const char *p;
	int i, ret = -1, len = strlen(attr);
	int nelem = infinipath_count_names(namep);

	for (i = 0; i < nelem; i++) {
		p = infinipath_get_next_name(&namep);
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
