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

#include <sys/types.h>	/* shm_open and signal handling */
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>

#include "psm_user.h"
#include "psm_mq_internal.h"
#include "psm_am_internal.h"
#include "kcopyrw.h"
#include "knemrw.h"

struct psm_am_max_sizes {
    uint32_t   nargs;
    uint32_t   request_short;
    uint32_t   reply_short;
    uint32_t   request_long;
    uint32_t   reply_long;
};

int psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_NO_KASSIST;

/* If we push bulk packets, we place them in the target's bulk packet region,
 * if we don't push bulk packets, we place them in *our* bulk packet region and
 * have the target pull the data from our region when it needs it. */
#define AMSH_BULK_PUSH  1   

/* When do we start using the "huge" buffers -- at 1MB */
#define AMSH_HUGE_BYTES 1024*1024

#define AMMED_SZ    2048
#define AMLONG_SZ   8192
#define AMHUGE_SZ   (524288+sizeof(am_pkt_bulk_t)) /* 512k + E */

static const amsh_qinfo_t amsh_qcounts =
        { 1024, 256, 16, 1, 1024, 256, 16, 8 };

static const amsh_qinfo_t amsh_qelemsz =
        { sizeof(am_pkt_short_t), AMMED_SZ+64, AMLONG_SZ, AMHUGE_SZ, 
          sizeof(am_pkt_short_t), AMMED_SZ+64, AMLONG_SZ, AMHUGE_SZ };

/* we use this internally to break up packets into MTUs */
static const amsh_qinfo_t amsh_qpkt_max =
        { NSHORT_ARGS*8, AMMED_SZ, AMLONG_SZ-sizeof(am_pkt_bulk_t),
                                   AMHUGE_SZ-sizeof(am_pkt_bulk_t),
          NSHORT_ARGS*8, AMMED_SZ, AMLONG_SZ-sizeof(am_pkt_bulk_t),
                                   AMHUGE_SZ-sizeof(am_pkt_bulk_t),
        };

/* We expose max sizes for the AM ptl.  */
static const struct psm_am_max_sizes psmi_am_max_sizes = 
        { 6, AMMED_SZ, (uint32_t) -1,
             AMMED_SZ, (uint32_t) -1 };

/*
 * Macro expansion trickery to handle 6 different fifo types:
 *
 * _fifo is one of 'reqFifoShort', 'reqFifoMed', 'reqFifoLong',
 * 'repFifoShort', 'repFifoMed', 'repFifoLong'
 *
 * _fifotyp is one of 'short' or 'bulk'
 */
#define QGETPTR(ptl, _shmidx_, _fifo, _fifotyp, _idx)	    \
	(am_pkt_ ## _fifotyp ## _t *)			    \
	(((uintptr_t)ptl->ep->amsh_qdir[(_shmidx_)].q ## _fifo) +    \
		    (_idx) *amsh_qelemsz.q ## _fifo)
        
static psm_error_t am_remap_segment(ptl_t *ptl, int max_idx);
static psm_error_t amsh_poll(ptl_t *ptl, int replyonly);
static void process_packet(ptl_t *ptl, am_pkt_short_t *pkt, int isreq);
static void amsh_conn_handler(void *toki, psm_amarg_t *args, int narg, 
                              void *buf, size_t len);

/* Kassist helper functions */
static const char * psmi_kassist_getmode(int mode);
static int psmi_get_kassist_mode();

/* Kcopy functionality */
int psmi_epaddr_kcopy_pid(psm_epaddr_t epaddr);
static int psmi_kcopy_find_minor(int *minor);
static int psmi_kcopy_open_minor(int minor);

static inline void
am_ctl_qhdr_init(volatile am_ctl_qhdr_t *q, int elem_cnt, int elem_sz)
{
    pthread_spin_init(&q->lock, PTHREAD_PROCESS_SHARED);
    q->head = 0;
    q->tail = 0;
    q->elem_cnt = elem_cnt;
    q->elem_sz  = elem_sz;
}

static void
am_ctl_bulkpkt_init(am_pkt_bulk_t *base_ptr, size_t elemsz, int nelems)
{
    int i;
    am_pkt_bulk_t *bulkpkt;
    uintptr_t bulkptr = (uintptr_t) base_ptr;

    for (i = 0; i < nelems; i++, bulkptr += elemsz) {
        bulkpkt = (am_pkt_bulk_t *) bulkptr;
        bulkpkt->idx = i;
    }
}

#define _PA(type) PSMI_ALIGNUP(amsh_qcounts.q ## type * amsh_qelemsz.q ## type, \
                               PSMI_PAGESIZE)
static inline uintptr_t 
am_ctl_sizeof_block()
{
    return 
      PSMI_ALIGNUP(
        PSMI_ALIGNUP(AMSH_BLOCK_HEADER_SIZE, PSMI_PAGESIZE) + 
	PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE) + /* reqctrl block */
        _PA(reqFifoShort) + _PA(reqFifoMed) + _PA(reqFifoLong) + 
        _PA(reqFifoHuge) + 
        PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE) + /*reqctrl block*/
        _PA(repFifoShort) + _PA(repFifoMed) + _PA(repFifoLong) + 
        _PA(repFifoHuge),
      PSMI_PAGESIZE); /* align to page size */
}
#undef _PA

static void am_update_directory(ptl_t *ptl, int shmidx);

/**
 * Given a number of PEs, determine the amount of memory required.
 */
static
size_t
psmi_amsh_segsize(int num_pe)
{
    size_t segsz;
    segsz  = PSMI_ALIGNUP(sizeof(struct am_ctl_dirpage), PSMI_PAGESIZE);
    segsz += am_ctl_sizeof_block() * num_pe;
    return segsz;
}

static
void
amsh_atexit()
{
    static pthread_mutex_t mutex_once = PTHREAD_MUTEX_INITIALIZER;
    static int atexit_once = 0;
    psm_ep_t ep;
    extern psm_ep_t psmi_opened_endpoint;

    pthread_mutex_lock(&mutex_once); 
    if (atexit_once) {
        pthread_mutex_unlock(&mutex_once);
        return;
    }
    else
        atexit_once = 1;
    pthread_mutex_unlock(&mutex_once); 

    ep = psmi_opened_endpoint;
    while (ep) {
	if (ep->amsh_keyname != NULL) {
	    _IPATH_VDBG("unlinking shm file %s\n", ep->amsh_keyname);
	    shm_unlink(ep->amsh_keyname);
	}

	if (ep->psmi_kassist_fd != -1) {
	    close(ep->psmi_kassist_fd);
	    ep->psmi_kassist_fd = -1;
	}
	ep = ep->user_ep_next;
    }

    return;
}

static
void
amsh_mmap_fault(int sig)
{
    static char shm_errmsg[256];

    snprintf(shm_errmsg, sizeof shm_errmsg,
        "%s: Unable to allocate shared memory for intra-node messaging.\n"
        "%s: Delete stale shared memory files in /dev/shm.\n",
        psmi_gethostname(), psmi_gethostname());
    amsh_atexit();
    if (write(2, shm_errmsg, strlen(shm_errmsg)+1) == -1)
      exit(2);
    else
      exit(1); /* XXX revisit this... there's probably a better way to exit */
}

/**
 * Attach endpoint shared-memory.
 *
 * We only try to obtain an shmidx at this point.
 */
psm_error_t
psmi_shm_attach(psm_ep_t ep, int *shmidx_o)
{
    int ismaster = 1;
    int i;
    int use_kcopy, use_kassist;
    int shmidx;
    int kcopy_minor = -1;
    char shmbuf[256];
    void *mapptr;
    size_t segsz;
    psm_error_t err = PSM_OK;

    if (ep->amsh_shmidx != -1) {
        *shmidx_o = ep->amsh_shmidx;
        return PSM_OK;
    }

    *shmidx_o = -1;
    if (ep->amsh_keyname != NULL) {
        if (psmi_uuid_compare(ep->amsh_keyno, ep->key) != 0) {
	    psmi_uuid_unparse(ep->amsh_keyno, shmbuf);
	    err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
		"Shared memory segment already initialized with key=%s",
		shmbuf);
	    goto fail;
	}
    }
    else {
        char *p;
        memcpy(&ep->amsh_keyno, ep->key, sizeof(psm_uuid_t));
        strncpy(shmbuf, "/psm_shm.", sizeof shmbuf);
        p = shmbuf + strlen(shmbuf);
        psmi_uuid_unparse(ep->amsh_keyno, p);
	ep->amsh_keyname = psmi_strdup(NULL, shmbuf); 
        if (ep->amsh_keyname == NULL) {
            err = PSM_NO_MEMORY;
            goto fail;
        }
	memset(&ep->amsh_qdir, 0, sizeof(ep->amsh_qdir));
    }

    ep->amsh_qdir = psmi_calloc(NULL, PER_PEER_ENDPOINT, 
			    PTL_AMSH_MAX_LOCAL_PROCS,
			    sizeof(struct amsh_qdirectory));
    if (ep->amsh_qdir == NULL) {
	err = PSM_NO_MEMORY;
	goto fail;
    }
    
    /* Get which kassist mode to use. */
    ep->psmi_kassist_mode = psmi_get_kassist_mode();
    use_kassist = (ep->psmi_kassist_mode != PSMI_KASSIST_OFF);
    use_kcopy = (ep->psmi_kassist_mode & PSMI_KASSIST_KCOPY);

    segsz = psmi_amsh_segsize(0); /* segsize with no procs attached yet */ 
    ep->amsh_shmfd = shm_open(ep->amsh_keyname, 
                          O_RDWR | O_CREAT | O_EXCL | O_TRUNC, S_IRWXU);
    if (ep->amsh_shmfd < 0) {
	ismaster = 0;
        if (errno != EEXIST) {
            err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR, 
                "Error creating shared memory object in shm_open%s%s",
                 errno != EACCES ? ": " :
                "(/dev/shm may have stale shm files that need to be removed): ",
                strerror(errno));
	    goto fail;
        }

        /* Try to open again, knowing we won't be the shared memory master */
        ep->amsh_shmfd = shm_open(ep->amsh_keyname, O_RDWR, S_IRWXU);
        if (ep->amsh_shmfd < 0) {
            err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR, 
                "Error attaching to shared memory object in shm_open: %s", 
                strerror(errno));
            goto fail;
        }
    }
    /* Now register the atexit handler for cleanup, whether master or slave */
    atexit(amsh_atexit);

    _IPATH_PRDBG("Registered as %s to key %s\n", ismaster ? "master" : "slave",
           ep->amsh_keyname);

    if (ismaster) {
	if (ftruncate(ep->amsh_shmfd, segsz) != 0) {
            err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                "Error setting size of shared memory object to %u bytes in "
		"ftruncate: %s\n", (uint32_t) segsz, strerror(errno));
            goto fail;
	}
    }
    else {
        /* Before we do the mmap, make sure that the master has had time to
         * apply the ftruncate, or else we will get a successful mmap on a
         * 0-sized object */
        struct stat fdstat;
        off_t cursize = 0;
        while (cursize == 0) {
            if (fstat(ep->amsh_shmfd, &fdstat)) {
                err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                         "Error querying size of shared memory object: %s",
                        strerror(errno));
                goto fail;
            }
            cursize = fdstat.st_size;
            if (cursize == 0)
                usleep(1); /* be gentle in tight fstat loop */
        }
    }
    
    /* We only map the first portion of the shared memory area.  This portion
     * is a single page used for control information.  The "master" creates it
     * and initializes it but every process must lock appropriate data
     * structures before it reads or writes it.
     */
    mapptr = mmap(NULL, segsz,
	PROT_READ|PROT_WRITE, MAP_SHARED, ep->amsh_shmfd, 0);
    if (mapptr == MAP_FAILED) {
	err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
	        "Error mmapping shared memory: %s", strerror(errno));
	goto fail;
    }

    ep->amsh_shmbase = (uintptr_t) mapptr;
    ep->amsh_dirpage = (struct am_ctl_dirpage *) ep->amsh_shmbase;

    /* We core dump right after here if we don't check the mmap */
    void (*old_handler_segv)(int) = signal (SIGSEGV, amsh_mmap_fault);
    void (*old_handler_bus)(int)  = signal (SIGBUS, amsh_mmap_fault);

    _IPATH_PRDBG("Mapped shm control object at %p\n", mapptr);
    if (ismaster) {
        pthread_mutexattr_t attr;
	pthread_mutexattr_init(&attr);
	pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&(ep->amsh_dirpage->lock), &attr);
	pthread_mutexattr_destroy(&attr);
	ep->amsh_dirpage->num_attached = 0;
	ep->amsh_dirpage->max_idx = -1;
	for (i = 0; i < PTL_AMSH_MAX_LOCAL_PROCS; i++) {
	    ep->amsh_dirpage->shmidx_map_epid[i] = 0;
	    ep->amsh_dirpage->kassist_pids[i] = 0;
	}
	if (use_kassist) {
	  if (use_kcopy) {
	    ep->psmi_kassist_fd = psmi_kcopy_find_minor(&kcopy_minor);
	    if (ep->psmi_kassist_fd >= 0) 
	      ep->amsh_dirpage->kcopy_minor = kcopy_minor;
	    else
	      ep->amsh_dirpage->kcopy_minor = -1;
	  }
	  else {  /* Setup knem */
	    psmi_assert_always(ep->psmi_kassist_mode & PSMI_KASSIST_KNEM);
	    
	    ep->psmi_kassist_fd = knem_open_device();
	  }
	  
	}
	else
	  ep->psmi_kassist_fd = -1;
	ips_mb();
	ep->amsh_dirpage->is_init = 1;
	_IPATH_PRDBG("Mapped and initalized shm object control page at %p,"
                    "size=%d, kcopy minor is %d (mode=%s)\n", mapptr, 
		    (int) segsz, kcopy_minor, 
		    psmi_kassist_getmode(ep->psmi_kassist_mode));
    }
    else {
	volatile int *is_init = &ep->amsh_dirpage->is_init;
	while (*is_init == 0) 
	    usleep(1);
	_IPATH_PRDBG("Slave synchronized object control page at "
		     "%p, size=%d, kcopy minor is %d (mode=%s)\n", 
		     mapptr, (int) segsz, kcopy_minor,
		    psmi_kassist_getmode(ep->psmi_kassist_mode));
    }

    /* 
     * First safe point where we can try to attach to the segment.
     *
     * Here we reserve the shmidx slot by marking the epid to '1'.  We only
     * update our epid in the init phase once we actually know what our epid
     * is.
     */
    pthread_mutex_lock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));
    shmidx = -1;
    for (i = 0; i < PTL_AMSH_MAX_LOCAL_PROCS; i++) {
	if (ep->amsh_dirpage->shmidx_map_epid[i] == 0) {
	    ep->amsh_dirpage->shmidx_map_epid[i] = 1;
            ep->amsh_dirpage->psm_verno[i] = PSMI_VERNO;
	    ep->amsh_dirpage->kassist_pids[i] = (int) getpid();
	    if (use_kassist) {
	      if (!use_kcopy) {
		if (!ismaster)
		  ep->psmi_kassist_fd = knem_open_device();
		
		/* If we are able to use KNEM assume everyone else on the
		 * node can also use it. Advertise that KNEM is active via
		 * the feature flag.
		 */
		if (ep->psmi_kassist_fd >= 0) {
		  ep->amsh_dirpage->amsh_features[i] |= AMSH_HAVE_KNEM;
		  psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_KNEM;
		}
		else {
		  ep->psmi_kassist_mode = PSMI_KASSIST_OFF;
		  use_kassist = 0;
		  psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_NO_KASSIST;
		}
	      }
	      else {
		psmi_assert_always(use_kcopy);
		kcopy_minor = ep->amsh_dirpage->kcopy_minor;
		if (!ismaster && kcopy_minor >= 0) 
		  ep->psmi_kassist_fd = psmi_kcopy_open_minor(kcopy_minor);
		
		/* If we are able to use KCOPY assume everyone else on the
		 * node can also use it. Advertise that KCOPY is active via
		 * the feature flag.
		 */
		if (ep->psmi_kassist_fd >= 0) {
		  ep->amsh_dirpage->amsh_features[i] |= AMSH_HAVE_KCOPY;
		  psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_KCOPY;
		}
		else {
		  ep->psmi_kassist_mode = PSMI_KASSIST_OFF;
		  use_kassist = 0; use_kcopy = 0;
		  psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_NO_KASSIST;
		}
	      }
	    }
	    else
	      psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_NO_KASSIST;
	    _IPATH_PRDBG("KASSIST MODE: %s\n", psmi_kassist_getmode(ep->psmi_kassist_mode));
	    
            ep->amsh_shmidx = shmidx = *shmidx_o = i;
            _IPATH_PRDBG("Grabbed shmidx %d\n", shmidx);
            ep->amsh_dirpage->num_attached++;
	    break;
	}
    }
    pthread_mutex_unlock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));

    /* install the old sighandler back */
    signal(SIGSEGV, old_handler_segv);
    signal(SIGBUS, old_handler_bus);
    
    if (shmidx == -1) 
	err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
	        "Exceeded maximum of %d support local endpoints: %s", 
		PTL_AMSH_MAX_LOCAL_PROCS, strerror(errno));
fail:
    return err;
}

/**
 * Initialize endpoint shared-memory AM.
 *
 * This function ensures that the given endpoint initializes enough shared
 * memory storage to communicate with up to PSMI_AMSH_MAX_LOCAL_PROCS local
 * peers.  In reality, the implementation need not grow any shared structures
 * if a single endpoint needs to communicate to 2 or 20 local peers (A local
 * peer is a peer having a context on any locally-attached LID). 
 *
 * [pre] Endpoint address epaddr has already been allocated.
 */

#define AMSH_QSIZE(type)                                                \
        PSMI_ALIGNUP(amsh_qelemsz.q ## type * amsh_qcounts.q ## type,   \
                     PSMI_PAGESIZE)

static
psm_error_t
amsh_init_segment(ptl_t *ptl)
{
    int shmidx;
    psm_error_t err = PSM_OK;

    /* Preconditions */
    psmi_assert_always(ptl != NULL);
    psmi_assert_always(ptl->ep != NULL);
    psmi_assert_always(ptl->epaddr != NULL);
    psmi_assert_always(ptl->ep->epid != 0);

    /* If we haven't attached to the segment yet, do it now */
    if (ptl->ep->amsh_shmidx == -1) {
        if ((err = psmi_shm_attach(ptl->ep, &shmidx)))
            goto fail;
    }
    else
        shmidx = ptl->ep->amsh_shmidx;

    ptl->amsh_qsizes.qreqFifoShort = AMSH_QSIZE(reqFifoShort);
    ptl->amsh_qsizes.qreqFifoMed   = AMSH_QSIZE(reqFifoMed);
    ptl->amsh_qsizes.qreqFifoLong  = AMSH_QSIZE(reqFifoLong);
    ptl->amsh_qsizes.qreqFifoHuge  = AMSH_QSIZE(reqFifoHuge);
    ptl->amsh_qsizes.qrepFifoShort = AMSH_QSIZE(repFifoShort);
    ptl->amsh_qsizes.qrepFifoMed   = AMSH_QSIZE(repFifoMed);
    ptl->amsh_qsizes.qrepFifoLong  = AMSH_QSIZE(repFifoLong);
    ptl->amsh_qsizes.qrepFifoHuge  = AMSH_QSIZE(repFifoHuge);

    /* We core dump right after here if we don't check the mmap */
    void (*old_handler_segv)(int) = signal (SIGSEGV, amsh_mmap_fault);
    void (*old_handler_bus)(int)  = signal (SIGBUS, amsh_mmap_fault);

    pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));

    /*
     * Now that we know our epid, update it in the shmidx array
     */
    ptl->ep->amsh_dirpage->shmidx_map_epid[shmidx] = ptl->ep->epid;

    if (shmidx > ptl->ep->amsh_dirpage->max_idx) {
	/* Have to truncate for more space */
	ptl->ep->amsh_dirpage->max_idx = shmidx;
	size_t newsize = psmi_amsh_segsize(shmidx+1);
	if (ftruncate(ptl->ep->amsh_shmfd, newsize) != 0) {
	    err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
		    "Error growing shared memory segment: %s",
		    strerror(errno));
	    goto fail_with_lock;
	}
	_IPATH_PRDBG("Grew shared segment for %d procs, size=%.2f MB\n",
		     shmidx+1, newsize / 1048576.0);
    }

    ptl->shmidx = shmidx;
    ptl->shmidx_map_epaddr[shmidx] = ptl->ep->epaddr;
    ptl->reqH.base = ptl->reqH.head = ptl->reqH.end = NULL;
    ptl->repH.base = ptl->repH.head = ptl->repH.end = NULL;
    if ((err = am_remap_segment(ptl, shmidx)) != PSM_OK) 
	goto fail_with_lock;

    memset((void *)(ptl->ep->amsh_blockbase + am_ctl_sizeof_block() * shmidx),
	   0, am_ctl_sizeof_block()); /* touch all of my pages */

    am_update_directory(ptl, shmidx);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qreqH->shortq, 
                     amsh_qcounts.qreqFifoShort, amsh_qelemsz.qreqFifoShort);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qreqH->medbulkq, 
                     amsh_qcounts.qreqFifoMed, amsh_qelemsz.qreqFifoMed);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qreqH->longbulkq, 
                     amsh_qcounts.qreqFifoLong, amsh_qelemsz.qreqFifoLong);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qreqH->hugebulkq, 
                     amsh_qcounts.qreqFifoHuge, amsh_qelemsz.qreqFifoHuge);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qrepH->shortq, 
                     amsh_qcounts.qrepFifoShort, amsh_qelemsz.qrepFifoShort);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qrepH->medbulkq, 
                     amsh_qcounts.qrepFifoMed, amsh_qelemsz.qrepFifoMed);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qrepH->longbulkq, 
                     amsh_qcounts.qrepFifoLong, amsh_qelemsz.qrepFifoLong);
    am_ctl_qhdr_init(&ptl->ep->amsh_qdir[shmidx].qrepH->hugebulkq, 
                     amsh_qcounts.qrepFifoHuge, amsh_qelemsz.qrepFifoHuge);

    /* Set bulkidx in every bulk packet */
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qreqFifoMed,
			amsh_qelemsz.qreqFifoMed,
                        amsh_qcounts.qreqFifoMed);
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qreqFifoLong,
			amsh_qelemsz.qreqFifoLong,
                        amsh_qcounts.qreqFifoLong);
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qreqFifoHuge,
			amsh_qelemsz.qreqFifoHuge,
                        amsh_qcounts.qreqFifoHuge);
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qrepFifoMed,
			amsh_qelemsz.qrepFifoMed,
                        amsh_qcounts.qrepFifoMed);
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qrepFifoLong,
			amsh_qelemsz.qrepFifoLong,
                        amsh_qcounts.qrepFifoLong);
    am_ctl_bulkpkt_init(ptl->ep->amsh_qdir[shmidx].qrepFifoHuge,
			amsh_qelemsz.qrepFifoHuge,
                        amsh_qcounts.qrepFifoHuge);

    /* install the old sighandler back */
    signal(SIGSEGV, old_handler_segv);
    signal(SIGBUS, old_handler_bus);

fail_with_lock:
    pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));

fail:
    return err;
}

psm_error_t
psmi_shm_detach(psm_ep_t ep)
{
    psm_error_t err = PSM_OK;
    int do_unlock = 1;

    if (ep->amsh_shmidx == -1 || ep->amsh_keyname == NULL)
        return err;

    _IPATH_VDBG("unlinking shm file %s\n", ep->amsh_keyname+1);
    shm_unlink(ep->amsh_keyname);
    psmi_free(ep->amsh_keyname);
    ep->amsh_keyname = NULL;

    if (ep->psmi_kassist_fd != -1) {
	close(ep->psmi_kassist_fd);
	ep->psmi_kassist_fd = -1;
    }

    /* go mark my shmidx as free */
    pthread_mutex_lock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));

    ep->amsh_dirpage->num_attached--;
    ep->amsh_dirpage->shmidx_map_epid[ep->amsh_shmidx] = 0;
    ep->amsh_shmidx = -1;

    if (ep->amsh_dirpage->num_attached == 0) { /* truncate to nothing */
        do_unlock = 0;
        if (ftruncate(ep->amsh_shmfd, 0) != 0) {
	    err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                "Error shrinking shared memory segment to 0: %s",
	        strerror(errno));
            goto fail_with_lock;
        }
	_IPATH_PRDBG("Shrinking shared segment to 0\n");
    }
    else {
        int i, new_max_idx = ep->amsh_dirpage->max_idx;
        for (i = ep->amsh_dirpage->max_idx; i >= 0; i--) {
            if (ep->amsh_dirpage->shmidx_map_epid[i] == 0) 
                new_max_idx = i;
            else
                break;
        }
        if (new_max_idx != ep->amsh_dirpage->max_idx) { /* we can truncate */
            size_t newsize = psmi_amsh_segsize(new_max_idx+1);
	    _IPATH_PRDBG("Shrinking shared segment down to %d procs, "
                "size=%.2f MB\n", new_max_idx+1, newsize / 1048576.0);
            if (ftruncate(ep->amsh_shmfd, newsize) != 0) {
	        err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                    "Error shrinking shared memory segment: %s", 
                    strerror(errno));
                goto fail_with_lock;
            }
            ep->amsh_dirpage->max_idx = new_max_idx;
        }
    }

    /* If we truncated down to zero, don't unlock since the storage is gone */
    if (do_unlock)
        pthread_mutex_unlock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));

    if (munmap((void *) ep->amsh_shmbase, psmi_amsh_segsize(ep->amsh_max_idx+1))) {
        err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                "Error with munamp of shared segment: %s", 
                strerror(errno));
        goto fail;
    }
    ep->amsh_max_idx = -1;
    ep->amsh_shmfd = -1;

    ep->amsh_shmbase = ep->amsh_blockbase = 0;
    ep->amsh_dirpage = NULL;
    memset(ep->amsh_keyno, 0, sizeof(ep->amsh_keyno));

    return PSM_OK;

fail_with_lock:
    if (do_unlock)
        pthread_mutex_unlock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));
fail:
    return err;
}

/**
 * Update pointers to our req/rep receive queues
 *
 * Only called from am_update_directory()
 */
static
void
am_hdrcache_update_short(ptl_t *ptl, int shmidx,
                   am_ctl_qshort_cache_t *reqH,
                   am_ctl_qshort_cache_t *repH)
{
    int head_shmidx;
    head_shmidx= reqH->head - reqH->base;
    reqH->base = QGETPTR(ptl, shmidx, reqFifoShort, short, 0);
    reqH->head = QGETPTR(ptl, shmidx, reqFifoShort, short, head_shmidx);
    reqH->end  = QGETPTR(ptl, shmidx, reqFifoShort, short, amsh_qcounts.qreqFifoShort);
    head_shmidx= repH->head - repH->base;
    repH->base = QGETPTR(ptl, shmidx, repFifoShort, short, 0);
    repH->head = QGETPTR(ptl, shmidx, repFifoShort, short, head_shmidx);
    repH->end  = QGETPTR(ptl, shmidx, repFifoShort, short, amsh_qcounts.qrepFifoShort);
    return;
}

/**
 * Update locally cached shared-pointer directory.  The directory must be
 * updated when a new epaddr is connected to or on every epaddr already 
 * connected to whenever the shared memory segment is relocated via mremap.
 *
 * @param epaddr Endpoint address for which to update local directory.
 */
	
static
void
am_update_directory(ptl_t *ptl, int shmidx)
{
    uintptr_t base_this;

    psmi_assert_always(shmidx != -1);
    base_this = ptl->ep->amsh_blockbase + am_ctl_sizeof_block() * shmidx + 
                AMSH_BLOCK_HEADER_SIZE;

    if (ptl->ep->amsh_dirpage->amsh_features[shmidx] & AMSH_HAVE_KASSIST) 
	ptl->ep->amsh_qdir[shmidx].kassist_pid = ptl->ep->amsh_dirpage->kassist_pids[shmidx];
    else
	ptl->ep->amsh_qdir[shmidx].kassist_pid = 0;

    /* Request queues */
    ptl->ep->amsh_qdir[shmidx].qreqH = (am_ctl_blockhdr_t *) base_this;
    ptl->ep->amsh_qdir[shmidx].qreqFifoShort = (am_pkt_short_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qreqH + 
            PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE));

    ptl->ep->amsh_qdir[shmidx].qreqFifoMed = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qreqFifoShort + ptl->amsh_qsizes.qreqFifoShort);
    ptl->ep->amsh_qdir[shmidx].qreqFifoLong = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qreqFifoMed + ptl->amsh_qsizes.qreqFifoMed);
    ptl->ep->amsh_qdir[shmidx].qreqFifoHuge = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qreqFifoLong + ptl->amsh_qsizes.qreqFifoLong);

    /* Reply queues */
    ptl->ep->amsh_qdir[shmidx].qrepH = (am_ctl_blockhdr_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qreqFifoHuge + ptl->amsh_qsizes.qreqFifoHuge);

    ptl->ep->amsh_qdir[shmidx].qrepFifoShort = (am_pkt_short_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qrepH + 
            PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE));
    ptl->ep->amsh_qdir[shmidx].qrepFifoMed = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qrepFifoShort + ptl->amsh_qsizes.qrepFifoShort);
    ptl->ep->amsh_qdir[shmidx].qrepFifoLong = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qrepFifoMed + ptl->amsh_qsizes.qrepFifoMed);
    ptl->ep->amsh_qdir[shmidx].qrepFifoHuge = (am_pkt_bulk_t *)
	((uintptr_t) ptl->ep->amsh_qdir[shmidx].qrepFifoLong + ptl->amsh_qsizes.qrepFifoLong);
    
    _IPATH_VDBG("shmidx=%d Request Hdr=%p,Pkt=%p,Med=%p,Long=%p,Huge=%p\n", 
                shmidx,
		ptl->ep->amsh_qdir[shmidx].qreqH, ptl->ep->amsh_qdir[shmidx].qreqFifoShort,
		ptl->ep->amsh_qdir[shmidx].qreqFifoMed, ptl->ep->amsh_qdir[shmidx].qreqFifoLong,
                ptl->ep->amsh_qdir[shmidx].qreqFifoHuge);
    _IPATH_VDBG("shmidx=%d Reply   Hdr=%p,Pkt=%p,Med=%p,Long=%p,Huge=%p\n", 
                shmidx,
		ptl->ep->amsh_qdir[shmidx].qrepH, ptl->ep->amsh_qdir[shmidx].qrepFifoShort,
		ptl->ep->amsh_qdir[shmidx].qrepFifoMed, ptl->ep->amsh_qdir[shmidx].qrepFifoLong,
                ptl->ep->amsh_qdir[shmidx].qrepFifoHuge);

    /* If we're updating our shmidx, we update our cached pointers */
    if (ptl->shmidx == shmidx)
	am_hdrcache_update_short(ptl, shmidx, 
                                 (am_ctl_qshort_cache_t *) &ptl->reqH, 
                                 (am_ctl_qshort_cache_t *) &ptl->repH); 

    /* Sanity check */
    uintptr_t base_next = 
	(uintptr_t) ptl->ep->amsh_qdir[shmidx].qrepFifoHuge + ptl->amsh_qsizes.qrepFifoHuge;

    psmi_assert_always(base_next - base_this <= am_ctl_sizeof_block());
}

/**
 * Remap shared memory segment.
 *
 * This function internally handles cases where the segment has to be moved
 * in the address space to accomodate more shared memory peers.
 *
 * @param max_idx Maximum shared-memory index for which a remap is needed.
 */
static
psm_error_t
am_remap_segment(ptl_t *ptl, int max_idx)
{
    void *prev_mmap;
    void *mapptr;
    int	i, err;

    if (max_idx <= ptl->ep->amsh_max_idx) {
	_IPATH_VDBG("shm segment with max_idx=%d needs no remap (top=%d)\n", 
		    max_idx, ptl->ep->amsh_max_idx); 
	return PSM_OK;
    }

    prev_mmap = (void *) ptl->ep->amsh_shmbase;

    mapptr = mremap(prev_mmap,
		    psmi_amsh_segsize(ptl->ep->amsh_max_idx+1),
		    psmi_amsh_segsize(max_idx+1),
		    MREMAP_MAYMOVE);
    if (mapptr == MAP_FAILED) {
	err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
		"Error re-mmapping shared memory: %s", strerror(errno));
	goto fail;
    }
    ptl->ep->amsh_shmbase = (uintptr_t) mapptr;
    ptl->ep->amsh_dirpage = (struct am_ctl_dirpage *) ptl->ep->amsh_shmbase;
    ptl->ep->amsh_blockbase = ptl->ep->amsh_shmbase + psmi_amsh_segsize(0);
    if (prev_mmap != mapptr) { /* newly relocated map, recreate directory */
	for (i = 0; i <= max_idx; i++)
	    am_update_directory(ptl, i);
    }
    _IPATH_PRDBG("shm segment remap from %p..%d to %p..%d (relocated=%s)\n",
		prev_mmap, (int) psmi_amsh_segsize(ptl->ep->amsh_max_idx+1),
		mapptr, (int) psmi_amsh_segsize(max_idx+1),
		prev_mmap == mapptr ? "NO" : "YES");
    ptl->ep->amsh_max_idx = max_idx;
    return PSM_OK;

fail:
    return err;
}

/* ep_epid_share_memory wrapper */
static
int
amsh_epid_reachable(ptl_t *ptl, psm_epid_t epid)
{
    int result;
    psm_error_t err;
    err = psm_ep_epid_share_memory(ptl->ep, epid, &result);
    psmi_assert_always(err == PSM_OK);
    return result;
}

static
psm_error_t
amsh_epaddr_add(ptl_t *ptl, psm_epid_t epid, int shmidx, psm_epaddr_t *epaddr_o)
{
    psm_epaddr_t epaddr;
    psm_error_t err = PSM_OK;

    psmi_assert(psmi_epid_lookup(ptl->ep, epid) == NULL);

    if (epid == ptl->epid) {
        epaddr = ptl->epaddr;
    } else {
        epaddr = (psm_epaddr_t) psmi_calloc(ptl->ep, PER_PEER_ENDPOINT, 
					    1, sizeof(struct psm_epaddr));
        if (epaddr == NULL) {
            err = PSM_NO_MEMORY;
            goto fail;
        }
        psmi_assert_always(ptl->shmidx_map_epaddr[shmidx] == NULL);
    }
    epaddr->ptl = ptl;
    epaddr->ptlctl = ptl->ctl;
    STAILQ_INIT(&epaddr->egrlong);
    epaddr->mctxt_prev = epaddr;
    epaddr->mctxt_next = epaddr;
    epaddr->mctxt_master = epaddr;
    epaddr->epid = epid;
    epaddr->ep = ptl->ep;
    epaddr->_shmidx = shmidx;
    AMSH_CSTATE_TO_SET(epaddr, NONE);
    AMSH_CSTATE_FROM_SET(epaddr, NONE);
    if ((err = psmi_epid_set_hostname(psm_epid_nid(epid), 
                                      psmi_gethostname(), 0)))
        goto fail;
    ptl->shmidx_map_epaddr[shmidx] = epaddr;
    if ((err = am_remap_segment(ptl, shmidx)))
        goto fail;
    am_update_directory(ptl, shmidx);
    /* Finally, add to table */
    if ((err = psmi_epid_add(ptl->ep, epid, epaddr)))
        goto fail;
    _IPATH_VDBG("epaddr=%s added to ptl=%p\n",
                psmi_epaddr_get_name(epid), ptl);
    *epaddr_o = epaddr;
fail:
    return err;
}

struct ptl_connection_req 
{
    int         isdone;
    int         op;         /* connect or disconnect */
    int         numep;
    int         numep_left;
    int         phase;

    int               *epid_mask;
    const psm_epid_t  *epids;     /* input epid list */
    psm_epaddr_t      *epaddr;
    psm_error_t       *errors;    /* inout errors */

    /* Used for connect/disconnect */
    psm_amarg_t args[4];
};

#define PTL_OP_CONNECT      0
#define PTL_OP_DISCONNECT   1
#define PTL_OP_ABORT        2

static
psm_error_t 
amsh_ep_connreq_init(ptl_t *ptl, 
             int op, /* connect, disconnect or abort */
             int numep,
	     const psm_epid_t *array_of_epid, /* non-NULL on connect */
	     const int array_of_epid_mask[],
             psm_error_t *array_of_errors,
	     psm_epaddr_t *array_of_epaddr,
             struct ptl_connection_req **req_o)
{
    int i, cstate;
    psm_epaddr_t epaddr;
    psm_epid_t epid;
    struct ptl_connection_req *req = NULL;

    req = (struct ptl_connection_req *)
          psmi_calloc(ptl->ep, PER_PEER_ENDPOINT, 1,
                      sizeof(struct ptl_connection_req));
    if (req == NULL) 
        return PSM_NO_MEMORY;
    req->isdone = 0;
    req->op = op;
    req->numep = numep;
    req->numep_left = 0;
    req->phase = ptl->connect_phase;
    req->epid_mask = (int *) 
        psmi_calloc(ptl->ep, PER_PEER_ENDPOINT, numep, sizeof(int));
    req->epaddr = array_of_epaddr;
    req->epids = array_of_epid;
    req->errors = array_of_errors;

    /* First check if there's really something to connect/disconnect 
     * for this PTL */
    for (i = 0; i < numep; i++) {
        req->epid_mask[i] = AMSH_CMASK_NONE; /* no connect by default */
        if (!array_of_epid_mask[i]) 
            continue;
        if (op == PTL_OP_CONNECT) {
            epid = array_of_epid[i];
            if (!amsh_epid_reachable(ptl, epid)) {
                array_of_errors[i] = PSM_EPID_UNREACHABLE;
                array_of_epaddr[i] = NULL;
                continue;
            }
            _IPATH_VDBG("looking at epid %llx\n", (unsigned long long) epid);
            epaddr = psmi_epid_lookup(ptl->ep, epid);
            if (epaddr != NULL) {
                if (epaddr->ptl != ptl) {
                    array_of_errors[i] = PSM_EPID_UNREACHABLE;
                    array_of_epaddr[i] = NULL;
                    continue;
                }
                cstate = AMSH_CSTATE_TO_GET(epaddr);
                if (cstate == AMSH_CSTATE_TO_ESTABLISHED) {
                    array_of_epaddr[i] = epaddr;
                    array_of_errors[i] = PSM_OK;
                }
                else {
                    psmi_assert(cstate == AMSH_CSTATE_TO_NONE);
                    array_of_errors[i] = PSM_TIMEOUT;
                    array_of_epaddr[i] = epaddr;
                    req->epid_mask[i] = AMSH_CMASK_PREREQ;
                }
            }
            else {
                req->epid_mask[i] = AMSH_CMASK_PREREQ;
                array_of_epaddr[i] = NULL;
            }
        }
        else { /* disc or abort */
            epaddr = array_of_epaddr[i];
            psmi_assert(epaddr != NULL);
            cstate = AMSH_CSTATE_TO_GET(epaddr);
            if (cstate == AMSH_CSTATE_TO_ESTABLISHED) {
                req->epid_mask[i] = AMSH_CMASK_PREREQ;
                _IPATH_VDBG("Just set index %d to AMSH_CMASK_PREREQ\n", i);
            }
            /* XXX undef ? */
        }
        if (req->epid_mask[i] != AMSH_CMASK_NONE)
            req->numep_left++;
    }

    if (req->numep_left == 0) { /* nothing to do */
        psmi_free(req->epid_mask);
        psmi_free(req);
        _IPATH_VDBG("Nothing to connect, bump up phase\n");
        ptl->connect_phase++;
        *req_o = NULL;
        return PSM_OK;
    }
    else {
        *req_o = req;
        return PSM_OK_NO_PROGRESS;
    }
}

static
psm_error_t
amsh_ep_connreq_poll(ptl_t *ptl, struct ptl_connection_req *req)
{
    int i, j, cstate, shmidx;
    psm_error_t err = PSM_OK;
    int this_max;
    psm_epid_t epid;
    psm_epaddr_t epaddr;

    if (req == NULL || req->isdone)
        return PSM_OK;

    psmi_assert_always(ptl->ep->amsh_dirpage != NULL); 
    psmi_assert_always(ptl->connect_phase == req->phase);

    if (req->op == PTL_OP_DISCONNECT || req->op == PTL_OP_ABORT) {
        for (i = 0; i < req->numep; i++)  {
            if (req->epid_mask[i] == AMSH_CMASK_NONE ||
                req->epid_mask[i] == AMSH_CMASK_DONE)
                continue;

            epaddr = req->epaddr[i];
            psmi_assert(epaddr != NULL);
            if (req->epid_mask[i] == AMSH_CMASK_PREREQ) {
                int shmidx = epaddr->_shmidx;
                /* Make sure the target of the disconnect is still there */
                pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
                if (ptl->ep->amsh_dirpage->shmidx_map_epid[shmidx] != epaddr->epid) {
                    req->numep_left--;
                    req->epid_mask[i] = AMSH_CMASK_DONE;
                    AMSH_CSTATE_TO_SET(epaddr, NONE);
                }
                pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
            }

            if (req->epid_mask[i] == AMSH_CMASK_PREREQ) {
                req->args[0].u32w0 = PSMI_AM_DISC_REQ;
                req->args[0].u32w1 = ptl->connect_phase;
                req->args[1].u64w0 = (uint64_t) ptl->epid;
                req->args[2].u32w0 = PSMI_VERNO;
                req->args[2].u32w1 = PSM_OK;
                req->args[3].u64w0 = (uint64_t)(uintptr_t)&req->errors[i];
                psmi_amsh_short_request(ptl, epaddr,
                                amsh_conn_handler_hidx,
                                req->args, 4, NULL, 0, 0);
                req->epid_mask[i] = AMSH_CMASK_POSTREQ;
            }
            else if (req->epid_mask[i] == AMSH_CMASK_POSTREQ) {
                cstate = AMSH_CSTATE_TO_GET(epaddr);
                if (cstate == AMSH_CSTATE_TO_DISC_REPLIED) {
                    req->numep_left--;
                    req->epid_mask[i] = AMSH_CMASK_DONE;
                    AMSH_CSTATE_TO_SET(epaddr, NONE);
                }
            }
        }
    }
    else {
        /* First see if we've made progress on any postreqs */
        int n_prereq = 0;
        for (i = 0; i < req->numep; i++) {
            int cstate;
            if (req->epid_mask[i] != AMSH_CMASK_POSTREQ) {
                if (req->epid_mask[i] == AMSH_CMASK_PREREQ)
                    n_prereq++;
                continue;
            }
            epaddr = req->epaddr[i];
            psmi_assert(epaddr != NULL);
            cstate = AMSH_CSTATE_TO_GET(epaddr);
            if (cstate == AMSH_CSTATE_TO_REPLIED) {
                req->numep_left--;
                AMSH_CSTATE_TO_SET(epaddr, ESTABLISHED);
                req->epid_mask[i] = AMSH_CMASK_DONE;
                continue;
            }
        }
        if (n_prereq > 0) { 
            psmi_assert(req->numep_left > 0);
            this_max = ptl->ep->amsh_max_idx;
            /* Go through the list of peers we need to connect to and find out
             * if they each shared ep is mapped into shm */
            pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
            for (i = 0; i < req->numep; i++) {
                if (req->epid_mask[i] != AMSH_CMASK_PREREQ)
                    continue;
                epid = req->epids[i];
                epaddr = req->epaddr[i];

                /* Go through mapped epids and find the epid we're looking for */
                for (shmidx = -1, j = 0; j <= ptl->ep->amsh_dirpage->max_idx; j++) {
                    /* epid is connected and ready to go */
	            if (ptl->ep->amsh_dirpage->shmidx_map_epid[j] == epid) {
                        shmidx = j;
	                this_max = max(j, this_max);
	                break;
                    }
                }
                if (shmidx == -1)  /* couldn't find epid, go to next */
                    continue;

                /* Before we even send the request out, check to see if
                 * versions are interoperable */
                if (!psmi_verno_isinteroperable(ptl->ep->amsh_dirpage->psm_verno[shmidx])) {
                    char buf[32];
                    uint16_t their_verno = ptl->ep->amsh_dirpage->psm_verno[shmidx];
                    snprintf(buf,sizeof buf, "%d.%d",
                            PSMI_VERNO_GET_MAJOR(their_verno),
                            PSMI_VERNO_GET_MINOR(their_verno));

                    _IPATH_INFO(
                            "Local endpoint id %" PRIx64 " has version %s "
                            "which is not supported by library version %d.%d", 
                            epid, buf, PSM_VERNO_MAJOR, PSM_VERNO_MINOR);
                    req->errors[i] = PSM_EPID_INVALID_VERSION;
                    req->numep_left--;
                    req->epid_mask[i] = AMSH_CMASK_DONE;
                    continue;
                }
                if (epaddr != NULL) {
                    psmi_assert(epaddr->_shmidx == shmidx);
                }
                else if ((epaddr = psmi_epid_lookup(ptl->ep, epid)) == NULL)  {
                    if ((err = amsh_epaddr_add(ptl, epid, shmidx, &epaddr))) {
                        pthread_mutex_unlock(
                            (pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
                        return err;
                    }
                } 
                req->epaddr[i] = epaddr;
                req->args[0].u32w0 = PSMI_AM_CONN_REQ;
                req->args[0].u32w1 = ptl->connect_phase;
                req->args[1].u64w0 = (uint64_t) ptl->epid;
                req->args[2].u32w0 = PSMI_VERNO;
                req->args[2].u32w1 = PSM_OK;
                req->args[3].u64w0 = (uint64_t)(uintptr_t)&req->errors[i];
                req->epid_mask[i] = AMSH_CMASK_POSTREQ;
                psmi_amsh_short_request(ptl, epaddr, amsh_conn_handler_hidx,
                                    req->args, 4, NULL, 0, 0);
	        _IPATH_PRDBG("epaddr=%p, epid=%" PRIx64 " at shmidx=%d\n", 
                    epaddr, epid, shmidx);
            }
            pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
        }
    }

    if (req->numep_left == 0) { /* we're all done */
        req->isdone = 1;
        return PSM_OK;
    }
    else {
        sched_yield();
        return PSM_OK_NO_PROGRESS;
    }
}

static
psm_error_t
amsh_ep_connreq_fini(ptl_t *ptl, struct ptl_connection_req *req)
{
    psm_error_t err = PSM_OK;
    int i;

    /* Whereever we are at in our connect process, we've been instructed to
     * finish the connection process */
    if (req == NULL)
        return PSM_OK;

    /* This prevents future connect replies from referencing data structures
     * that disappeared */
    ptl->connect_phase++;

    /* First process any leftovers in postreq or prereq */
    for (i = 0; i < req->numep; i++) {
        if (req->epid_mask[i] == AMSH_CMASK_NONE)
            continue;
        else if (req->epid_mask[i] == AMSH_CMASK_POSTREQ) {
            int cstate;
            req->epid_mask[i] = AMSH_CMASK_DONE;
            cstate = AMSH_CSTATE_TO_GET(req->epaddr[i]);
            if (cstate == AMSH_CSTATE_TO_REPLIED) {
                req->numep_left--;
                AMSH_CSTATE_TO_SET(req->epaddr[i], ESTABLISHED);
            }
            else { /* never actually got reply */
                req->errors[i] = PSM_TIMEOUT;
            }
        }
        /* If we couldn't go from prereq to postreq, that means we couldn't
         * find the shmidx for an epid in time.  This can only be a case of
         * time out */
        else if (req->epid_mask[i] == AMSH_CMASK_PREREQ) {
            req->errors[i] = PSM_TIMEOUT;
            req->numep_left--;
            req->epaddr[i] = NULL;
            req->epid_mask[i] = AMSH_CMASK_DONE;
        }
    }
    
    /* Whatever is left can only be in DONE or NONE state */
    for (i = 0; i < req->numep; i++) {
        if (req->epid_mask[i] == AMSH_CMASK_NONE)
            continue;
        psmi_assert(req->epid_mask[i] == AMSH_CMASK_DONE);

        err = psmi_error_cmp(err, req->errors[i]);
        /* Report errors in connection. */
        /* XXX de-alloc epaddr */
    }

    psmi_free(req->epid_mask);
    psmi_free(req);

    return err;
}

/* Wrapper for 2.0's use of connect/disconect.  The plan is to move the
 * init/poll/fini interface up to the PTL level for 2.2 */
#define CONNREQ_ZERO_POLLS_BEFORE_YIELD  20
static
psm_error_t
amsh_ep_connreq_wrap(ptl_t *ptl, int op,
             int numep,
	     const psm_epid_t *array_of_epid, 
	     const int array_of_epid_mask[],
             psm_error_t *array_of_errors,
	     psm_epaddr_t *array_of_epaddr,
             uint64_t timeout_ns)
{
    psm_error_t err;
    uint64_t t_start;
    struct ptl_connection_req *req;
    int num_polls_noprogress = 0;
    static int shm_polite_attach = -1;

    if (shm_polite_attach == -1) {
        char *p = getenv("PSM_SHM_POLITE_ATTACH");
        if (p && *p && atoi(p) != 0) {
            fprintf(stderr, "%s: Using Polite SHM segment attach\n",
                psmi_gethostname());
            shm_polite_attach = 1;
        }
        shm_polite_attach = 0;
    }

    /* Initialize */
    err = amsh_ep_connreq_init(ptl, op, numep,
            array_of_epid, array_of_epid_mask, array_of_errors,
            array_of_epaddr, &req);
    if (err != PSM_OK_NO_PROGRESS) /* Either we're all done with connect or 
                                    * there was an error */
        return err;

    /* Poll until either
     * 1. We time out
     * 2. We are done with connecting 
     */ 
    t_start = get_cycles();
    do {
        psmi_poll_internal(ptl->ep, 1);
        err = amsh_ep_connreq_poll(ptl, req);
        if (err == PSM_OK)
            break; /* Finished before timeout */
        else if (err != PSM_OK_NO_PROGRESS)
	    goto fail;
        else if (shm_polite_attach && 
            ++num_polls_noprogress == CONNREQ_ZERO_POLLS_BEFORE_YIELD) {
            num_polls_noprogress = 0;
	    PSMI_PYIELD();
        }
    }
    while (psmi_cycles_left(t_start, timeout_ns));

    err = amsh_ep_connreq_fini(ptl, req);

fail:
    return err;
}

static
psm_error_t 
amsh_ep_connect(ptl_t *ptl,
             int numep,
	     const psm_epid_t *array_of_epid, 
	     const int array_of_epid_mask[],
             psm_error_t *array_of_errors,
	     psm_epaddr_t *array_of_epaddr,
             uint64_t timeout_ns)
{
    return amsh_ep_connreq_wrap(ptl, PTL_OP_CONNECT, numep, array_of_epid,
                                array_of_epid_mask, array_of_errors,
                                array_of_epaddr, timeout_ns);
}

static
psm_error_t
amsh_ep_disconnect(ptl_t *ptl, int force, int numep, 
	     const psm_epaddr_t array_of_epaddr[], 
	     const int array_of_epaddr_mask[], 
	     psm_error_t array_of_errors[],
	     uint64_t timeout_ns)
{
    return amsh_ep_connreq_wrap(ptl, force ? PTL_OP_ABORT : PTL_OP_DISCONNECT, 
                numep, NULL, array_of_epaddr_mask, array_of_errors,
                (psm_epaddr_t *) array_of_epaddr, timeout_ns);
}

#undef CSWAP
PSMI_ALWAYS_INLINE(
int32_t 
cswap(volatile int32_t *p, int32_t old_value, int32_t new_value))
{
  asm volatile ("lock cmpxchg %2, %0" :
                "+m" (*p), "+a" (old_value) :
                "r" (new_value) :
                "memory");
  return old_value;
}

PSMI_ALWAYS_INLINE(
am_pkt_short_t *
am_ctl_getslot_pkt_inner(volatile am_ctl_qhdr_t *shq, am_pkt_short_t *pkt0)
)
{
    am_pkt_short_t *pkt;
    uint32_t idx;
#ifndef CSWAP
    pthread_spin_lock(&shq->lock);
    idx = shq->tail;
    pkt = (am_pkt_short_t *)((uintptr_t) pkt0 + idx * shq->elem_sz);
    if (pkt->flag == QFREE) {
        ips_sync_reads();
        pkt->flag = QUSED;
        shq->tail += 1;
        if (shq->tail == shq->elem_cnt)
            shq->tail = 0;
    } else {
        pkt = 0;
    }
    pthread_spin_unlock(&shq->lock);
#else
    uint32_t idx_next;
    do {
        idx = shq->tail;
        idx_next = (idx+1 == shq->elem_cnt) ? 0 : idx+1;
    } while (cswap(&shq->tail, idx, idx_next) != idx);

    pkt = (am_pkt_short_t *)((uintptr_t) pkt0 + idx * shq->elem_sz);
    while (cswap(&pkt->flag, QFREE, QUSED) !=  QFREE)
        ;
#endif
    return pkt;
}

/* This is safe because 'flag' is at the same offset on both pkt and bulkpkt */
#define am_ctl_getslot_bulkpkt_inner(shq,pkt0) ((am_pkt_bulk_t *) \
            am_ctl_getslot_pkt_inner(shq,(am_pkt_short_t *)(pkt0)))

PSMI_ALWAYS_INLINE(
am_pkt_short_t *
am_ctl_getslot_pkt(ptl_t *ptl, int shmidx, int is_reply)
)
{
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_short_t  *pkt0;
    if (!is_reply) {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->shortq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoShort; 
    }
    else {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->shortq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoShort; 
    }
    return am_ctl_getslot_pkt_inner(shq, pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_med(ptl_t *ptl, int shmidx, int is_reply)
)
{
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;
    if (!is_reply) {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->medbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoMed; 
    }
    else {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->medbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoMed; 
    }
    return am_ctl_getslot_bulkpkt_inner(shq, pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_long(ptl_t *ptl, int shmidx, int is_reply)
)
{
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;
    if (!is_reply) {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->longbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoLong; 
    }
    else {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->longbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoLong; 
    }
    return am_ctl_getslot_bulkpkt_inner(shq, pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_huge(ptl_t *ptl, int shmidx, int is_reply)
)
{
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;
    if (!is_reply) {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->hugebulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoHuge; 
    }
    else {
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->hugebulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoHuge; 
    }
    return am_ctl_getslot_bulkpkt_inner(shq, pkt0);
}

psmi_handlertab_t psmi_allhandlers[] = { 
    { 0 },
    { amsh_conn_handler },
    { psmi_am_mq_handler },
    { psmi_am_mq_handler_data },
    { psmi_am_mq_handler_rtsmatch },
    { psmi_am_mq_handler_rtsdone },
    { psmi_am_handler }
};

PSMI_ALWAYS_INLINE(
void 
advance_head(volatile am_ctl_qshort_cache_t *hdr))
{
    QMARKFREE(hdr->head);
    hdr->head++;
    if (hdr->head == hdr->end)
        hdr->head = hdr->base;
}

#define AMSH_ZERO_POLLS_BEFORE_YIELD    64
#define AMSH_POLLS_BEFORE_PSM_POLL      16

/* XXX this can be made faster.  Instead of checking the flag of the head, keep
 * a cached copy of the integer value of the tail and compare it against the
 * previous one we saw.
 */
PSMI_ALWAYS_INLINE(
psm_error_t
amsh_poll_internal_inner(ptl_t *ptl, int replyonly, int is_internal))
{
    psm_error_t err = PSM_OK_NO_PROGRESS;
    /* poll replies */
    if (!QISEMPTY(ptl->repH.head->flag)) {
        do {
            ips_sync_reads();
            process_packet(ptl, (am_pkt_short_t *) ptl->repH.head, 0);
	    advance_head(&ptl->repH);
            err = PSM_OK;
        } while (!QISEMPTY(ptl->repH.head->flag));
    }

    if (!replyonly) {
    /* Request queue not enable for 2.0, will be re-enabled to support long
     * replies */
        if (!is_internal && ptl->psmi_am_reqq_fifo.first != NULL) {
            psmi_am_reqq_drain(ptl);
            err = PSM_OK;
        }
        if (!QISEMPTY(ptl->reqH.head->flag)) {
            do {
                ips_sync_reads();
                process_packet(ptl, (am_pkt_short_t *) ptl->reqH.head, 1);
	        advance_head(&ptl->reqH);
                err = PSM_OK;
            } while (!QISEMPTY(ptl->reqH.head->flag));
        }
    }

    if (is_internal) {
        if (err == PSM_OK) /* some progress, no yields */
            ptl->zero_polls = 0;
        else if (++ptl->zero_polls == AMSH_ZERO_POLLS_BEFORE_YIELD) {
            /* no progress for AMSH_ZERO_POLLS_BEFORE_YIELD */
            sched_yield();
            ptl->zero_polls = 0;
        }

        if (++ptl->amsh_only_polls == AMSH_POLLS_BEFORE_PSM_POLL) {
            psmi_poll_internal(ptl->ep, 0);
            ptl->amsh_only_polls = 0;
        }
    }
    return err; /* if we actually did something */
}

/* non-inlined version */
static
psm_error_t
amsh_poll_internal(ptl_t *ptl, int replyonly)
{
    return amsh_poll_internal_inner(ptl, replyonly, 1);
}

#ifdef PSM_PROFILE
  #define AMSH_POLL_UNTIL(ptl,isreply,cond)   do {      \
            PSMI_PROFILE_BLOCK();                       \
            while (!(cond)) {                           \
                PSMI_PROFILE_REBLOCK(                   \
                  amsh_poll_internal(ptl,isreply) ==    \
                  PSM_OK_NO_PROGRESS);                  \
            }                                           \
            PSMI_PROFILE_UNBLOCK();                     \
        } while (0)
#else
  #define AMSH_POLL_UNTIL(ptl,isreply,cond)   do {  \
            while (!(cond)) {                       \
                amsh_poll_internal(ptl,isreply);    \
            }                                       \
        } while (0)
#endif

static
psm_error_t
amsh_poll(ptl_t *ptl, int replyonly)
{
    return amsh_poll_internal_inner(ptl, replyonly, 0);
}

PSMI_ALWAYS_INLINE(
void
am_send_pkt_short(ptl_t *ptl, uint32_t destidx, uint32_t bulkidx, 
                  uint16_t fmt, uint16_t nargs, uint16_t handleridx, 
                  psm_amarg_t *args, const void *src, uint32_t len, int isreply))
{
    int i;
    volatile am_pkt_short_t *pkt;

    AMSH_POLL_UNTIL(ptl, isreply,
        (pkt = am_ctl_getslot_pkt(ptl, destidx, isreply)) != NULL);

    /* got a free pkt... fill it in */
    pkt->bulkidx = bulkidx;
    pkt->shmidx = ptl->shmidx; 
    pkt->type  = fmt;
    pkt->nargs = nargs;
    pkt->handleridx = handleridx;
    for (i = 0; i < nargs; i++)
        pkt->args[i] = args[i];
    if (fmt == AMFMT_SHORT_INLINE) 
        mq_copy_tiny((uint32_t *) &pkt->args[nargs], (uint32_t *) src, len);
    _IPATH_VDBG("pkt=%p fmt=%d bulkidx=%d,flag=%d,nargs=%d,"
                "buf=%p,len=%d,hidx=%d,value=%d\n", pkt, (int) fmt, bulkidx, 
                pkt->flag, pkt->nargs, src, (int) len, (int) handleridx,
                src != NULL ?  *((uint32_t *)src): 0); 
    QMARKREADY(pkt);
}

/* It's probably unlikely that the alloca below is problematic, but
 * in case we think it is, define the next to 1
 */
#define ALLOCA_AS_SCRATCH 0

#if ALLOCA_AS_SCRATCH
static char amsh_medscratch[AMMED_SZ];
#endif

#define amsh_shm_copy_short psmi_mq_mtucpy
#define amsh_shm_copy_long  psmi_mq_mtucpy
#define amsh_shm_copy_huge  psmi_memcpyo

PSMI_ALWAYS_INLINE(
int
psmi_amsh_generic_inner(uint32_t amtype, ptl_t *ptl, psm_epaddr_t epaddr,
                  psm_handler_t handler, psm_amarg_t *args, int nargs,
		  const void *src, size_t len, void *dst, int flags))
{
    uint16_t type;
    uint32_t bulkidx;
    uint16_t hidx = (uint16_t) handler;
    int destidx = epaddr->_shmidx;
    int is_reply = AM_IS_REPLY(amtype);
    volatile am_pkt_bulk_t *bulkpkt;

    _IPATH_VDBG("%s epaddr=%s, shmidx=%d, type=%d LOOPBACK=%s\n", 
            is_reply ? "reply" : "request",
            psmi_epaddr_get_name(epaddr->epid), epaddr->_shmidx, amtype,
            ptl->epaddr == epaddr ? "YES" : "NO");
    if (ptl->epaddr == epaddr) { /* loopback */
        amsh_am_token_t tok;
        void *bufa;

	tok.tok.epaddr_from = epaddr;
        tok.ptl = ptl;
        tok.mq = ptl->ep->mq;
        tok.shmidx = ptl->shmidx;
        if (len > 0) {
            if (AM_IS_LONG(amtype))
                bufa = dst;
            else {
                psmi_assert_always(len <= AMMED_SZ);
#if ALLOCA_AS_SCRATCH
                bufa = (void *) amsh_medscratch;
#else
                bufa = alloca(len);
#endif
            }
            psmi_assert(bufa != NULL);
            amsh_shm_copy_short((void *) bufa, src, len);
        }
        else
            bufa = NULL;
        psmi_handler_fn_t fn = 
            (psmi_handler_fn_t) psmi_allhandlers[hidx].fn;
        fn(&tok, args, nargs, bufa, len);

        return 1;
    }

    switch (amtype) {
        case AMREQUEST_SHORT:
        case AMREPLY_SHORT:
            if (len + (nargs<<3) <= (NSHORT_ARGS<<3)) {
                /* Payload fits in args packet */
                type = AMFMT_SHORT_INLINE;
                bulkidx = len;
            }
            else {
                psmi_assert(len < amsh_qelemsz.qreqFifoMed);
                psmi_assert(src != NULL);
                type = AMFMT_SHORT;
#if 1
                AMSH_POLL_UNTIL(ptl, is_reply,
                    (bulkpkt = am_ctl_getslot_med(ptl, destidx, is_reply)) != NULL);
#else
                /* This version exposes a compiler bug */
                while (1) {
                    bulkpkt = am_ctl_getslot_med(ptl, destidx, is_reply);
                    if (bulkpkt == NULL)
                        break;
                    amsh_poll_internal(ptl, is_reply);
                }
#endif
                bulkidx = bulkpkt->idx;
                bulkpkt->len = len;
                _IPATH_VDBG("bulkpkt %p flag is %d from idx %d\n", 
                    bulkpkt, bulkpkt->flag, destidx);
                amsh_shm_copy_short((void*) bulkpkt->payload, src, (uint32_t) len);
                QMARKREADY(bulkpkt);
            }
            am_send_pkt_short(ptl, destidx, bulkidx, type, nargs, hidx,
                              args, src, len, is_reply);
            break;

        case AMREQUEST_LONG:
        case AMREPLY_LONG:
        {
            uint32_t bytes_left = len;
            uint8_t *src_this = (uint8_t *) src;
            uint8_t *dst_this = (uint8_t *) dst;
            uint32_t bytes_this;
            uint32_t mtu_this;
            type = (bytes_left >= AMSH_HUGE_BYTES ? AMFMT_HUGE : AMFMT_LONG);
            /* XXX put in my shm block */
            int destidx_l = AMSH_BULK_PUSH ? destidx : ptl->shmidx;

            if (type == AMFMT_HUGE)
                mtu_this = is_reply ? amsh_qpkt_max.qrepFifoHuge :
                                      amsh_qpkt_max.qreqFifoHuge;
            else
                mtu_this = is_reply ? amsh_qpkt_max.qrepFifoLong :
                                       amsh_qpkt_max.qreqFifoLong;
            _IPATH_VDBG("[long][%s] src=%p,dest=%p,len=%d,hidx=%d\n",
                    is_reply ? "rep" : "req", src, dst, (uint32_t)len, hidx);
            while (bytes_left) {
                if (type == AMFMT_HUGE) {
                    bytes_this = min(bytes_left, mtu_this);
                    AMSH_POLL_UNTIL(ptl, is_reply,
                      (bulkpkt = am_ctl_getslot_huge(ptl, destidx_l, is_reply)) != NULL);
                    bytes_left -= bytes_this;
                    if (bytes_left == 0)
                        type = AMFMT_HUGE_END;
                    bulkidx = bulkpkt->idx;
                    amsh_shm_copy_huge((void *) bulkpkt->payload, 
                                       src_this, bytes_this);
                }
                else {
                    bytes_this = min(bytes_left, mtu_this);
                    AMSH_POLL_UNTIL(ptl, is_reply,
                      (bulkpkt = am_ctl_getslot_long(ptl, destidx_l, is_reply)) != NULL);
                    bytes_left -= bytes_this;
                    if (bytes_left == 0)
                        type = AMFMT_LONG_END;
                    bulkidx = bulkpkt->idx;
                    amsh_shm_copy_long((void *) bulkpkt->payload, src_this, 
                                       bytes_this);
                }

                bulkpkt->dest = (uintptr_t) dst;
                bulkpkt->dest_off = 
                    (uint32_t)((uintptr_t)dst_this - (uintptr_t)dst);
                bulkpkt->len = bytes_this;
                QMARKREADY(bulkpkt);
                am_send_pkt_short(ptl, destidx, bulkidx, type, nargs, 
                                  hidx, args, NULL, 0, is_reply);
                src_this += bytes_this;
                dst_this += bytes_this;
            }
            break;
        }
        default:
            break;
    }
    return 1;
}

/* A generic version that's not inlined */
int
psmi_amsh_generic(uint32_t amtype, ptl_t *ptl, psm_epaddr_t epaddr,
                  psm_handler_t handler, psm_amarg_t *args, int nargs,
		  const void *src, size_t len, void *dst, int flags)
{
    return psmi_amsh_generic_inner(amtype,ptl,epaddr,handler,args,nargs,src,len,
            dst,flags);
}

int
psmi_amsh_short_request(ptl_t *ptl, psm_epaddr_t epaddr,
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
		        const void *src, size_t len, int flags)
{
    return psmi_amsh_generic_inner(AMREQUEST_SHORT, ptl, epaddr, handler, args, nargs,
                             src, len, NULL, flags);
}
                
int
psmi_amsh_long_request(ptl_t *ptl, psm_epaddr_t epaddr,
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
		        const void *src, size_t len, void *dest, int flags)
{
    return psmi_amsh_generic_inner(AMREQUEST_LONG, ptl, epaddr, handler, args, nargs,
                             src, len, dest, flags);
}

void
psmi_amsh_short_reply(amsh_am_token_t *tok,
                      psm_handler_t handler, psm_amarg_t *args, int nargs,
		      const void *src, size_t len, int flags)
{
  psmi_amsh_generic_inner(AMREPLY_SHORT, tok->ptl, tok->tok.epaddr_from, 
			  handler, args, nargs, src, len, NULL, flags);
  return;
}

void
psmi_amsh_long_reply(amsh_am_token_t *tok,
                     psm_handler_t handler, psm_amarg_t *args, int nargs,
		     const void *src, size_t len, void *dest, int flags)
{
   psmi_amsh_generic_inner(AMREPLY_LONG, tok->ptl, tok->tok.epaddr_from, 
			   handler, args, nargs, src, len, dest, flags);
   return;
}

void
psmi_am_reqq_init(ptl_t *ptl)
{
    ptl->psmi_am_reqq_fifo.first = NULL;
    ptl->psmi_am_reqq_fifo.lastp = &ptl->psmi_am_reqq_fifo.first;
}

psm_error_t
psmi_am_reqq_drain(ptl_t *ptl)
{
    am_reqq_t *reqn = ptl->psmi_am_reqq_fifo.first;
    am_reqq_t *req;
    psm_error_t err = PSM_OK_NO_PROGRESS;

    /* We're going to process the entire list, and running the generic handler
     * below can cause other requests to be enqueued in the queue that we're
     * processing. */
    ptl->psmi_am_reqq_fifo.first = NULL;
    ptl->psmi_am_reqq_fifo.lastp = &ptl->psmi_am_reqq_fifo.first;

    while ((req = reqn) != NULL) {
        err = PSM_OK;
        reqn = req->next;
        _IPATH_VDBG("push of reqq=%p epaddr=%s localreq=%p remotereq=%p\n", req,
                psmi_epaddr_get_hostname(req->epaddr->epid),
                (void *) (uintptr_t) req->args[1].u64w0,
                (void *) (uintptr_t) req->args[0].u64w0);
        psmi_amsh_generic(req->amtype, req->ptl, req->epaddr,
                          req->handler, req->args, req->nargs, req->src,
                          req->len, req->dest, req->amflags);
        if (req->flags & AM_FLAG_SRC_TEMP) 
                psmi_free(req->src);
        psmi_free(req);
    }
    return err;
}

void
psmi_am_reqq_add(int amtype, ptl_t *ptl, psm_epaddr_t epaddr,
                 psm_handler_t handler, psm_amarg_t *args, int nargs,
		 void *src, size_t len, void *dest, int amflags)
{
    int i;
    int flags = 0;
    am_reqq_t *nreq = 
        (am_reqq_t *) psmi_malloc(ptl->ep, UNDEFINED, sizeof(am_reqq_t));
    psmi_assert_always(nreq != NULL);
    _IPATH_VDBG("alloc of reqq=%p, to epaddr=%s, ptr=%p, len=%d, "
        "localreq=%p, remotereq=%p\n", nreq, 
        psmi_epaddr_get_hostname(epaddr->epid), dest,  
        (int)len, (void *) (uintptr_t) args[1].u64w0, 
        (void *) (uintptr_t) args[0].u64w0);

    psmi_assert(nargs <= 8);
    nreq->next = NULL;
    nreq->amtype = amtype;
    nreq->ptl = ptl;
    nreq->epaddr = epaddr;
    nreq->handler = handler;
    for (i = 0; i < nargs; i++)
        nreq->args[i] = args[i];
    nreq->nargs = nargs;
    if (AM_IS_LONG(amtype) && src != NULL && 
         len > 0 && !(amflags & AM_FLAG_SRC_ASYNC)) 
    {
        abort();
        flags |= AM_FLAG_SRC_TEMP;
	nreq->src = psmi_malloc(ptl->ep, UNDEFINED, len);
	psmi_assert_always(nreq->src != NULL); /* XXX mem */
	amsh_shm_copy_short(nreq->src, src, len);
    }
    else
	nreq->src = src;
    nreq->len =  len;
    nreq->dest = dest;
    nreq->amflags = amflags;
    nreq->flags = flags;

    nreq->next = NULL;
    *(ptl->psmi_am_reqq_fifo.lastp) = nreq;
    ptl->psmi_am_reqq_fifo.lastp = &nreq->next;
}

static 
void
process_packet(ptl_t *ptl, am_pkt_short_t *pkt, int isreq)
{
    amsh_am_token_t    tok;
    psmi_handler_fn_t  fn;
    int shmidx = pkt->shmidx;
    
    tok.tok.epaddr_from = ptl->shmidx_map_epaddr[shmidx];
    tok.ptl = ptl;
    tok.mq = ptl->ep->mq;
    tok.shmidx = shmidx;

    uint16_t hidx = (uint16_t) pkt->handleridx;
    int myshmidx = ptl->shmidx;
    int shmidx_l = AMSH_BULK_PUSH ? myshmidx : shmidx;
    uint32_t bulkidx = pkt->bulkidx;
    uintptr_t bulkptr;
    am_pkt_bulk_t *bulkpkt;

    fn = (psmi_handler_fn_t) psmi_allhandlers[hidx].fn;
    psmi_assert(fn != NULL);
    psmi_assert((uintptr_t) pkt > ptl->ep->amsh_blockbase);

    if (pkt->type == AMFMT_SHORT_INLINE) {
        _IPATH_VDBG("%s inline flag=%d nargs=%d from_idx=%d pkt=%p hidx=%d\n",
                isreq ? "request" : "reply",
                pkt->flag, pkt->nargs, shmidx, pkt, hidx);

        fn(&tok, pkt->args, pkt->nargs, pkt->length > 0 ? 
           (void *) &pkt->args[pkt->nargs] : NULL, pkt->length);
    }
    else {
        int isend = 0;
        switch (pkt->type) {
            case AMFMT_SHORT:
                if (isreq) {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[myshmidx].qreqFifoMed;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoMed;
                }
                else {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[myshmidx].qrepFifoMed;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoMed;
                }
                break;

            case AMFMT_LONG_END:
                isend = 1;
            case AMFMT_LONG:
                if (isreq) {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qreqFifoLong;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoLong;
                }
                else {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qrepFifoLong;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoLong;
                }
                break;

            case AMFMT_HUGE_END:
                isend = 1;
            case AMFMT_HUGE:
                if (isreq) {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qreqFifoHuge;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoHuge;
                }
                else {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qrepFifoHuge;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoHuge;
                }
                break;
            default:
                bulkptr = 0;
                psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
                    "Unknown/unhandled packet type 0x%x", pkt->type);
        }

        bulkpkt = (am_pkt_bulk_t *) bulkptr;
        _IPATH_VDBG("ep=%p mq=%p type=%d bulkidx=%d flag=%d/%d nargs=%d "
                    "from_idx=%d pkt=%p/%p hidx=%d\n",
                    ptl->ep, ptl->ep->mq, pkt->type, bulkidx, pkt->flag, 
                    bulkpkt->flag, pkt->nargs, shmidx, pkt, bulkpkt, hidx);
        psmi_assert(bulkpkt->flag == QREADY);
        if (pkt->type == AMFMT_SHORT) {
                fn(&tok, pkt->args, pkt->nargs, 
                    (void *) bulkpkt->payload, bulkpkt->len);
            QMARKFREE(bulkpkt);
        }
        else {
            if (pkt->type == AMFMT_HUGE || pkt->type == AMFMT_HUGE_END)
                amsh_shm_copy_huge((void *) (bulkpkt->dest + bulkpkt->dest_off), 
                                   bulkpkt->payload, bulkpkt->len);
            else
                amsh_shm_copy_long((void *) (bulkpkt->dest + bulkpkt->dest_off), 
                                   bulkpkt->payload, bulkpkt->len);

            /* If this is the last packet, copy args before running the
             * handler */
            if (isend) {
                psm_amarg_t args[8];
                int nargs = pkt->nargs;
                int i;
                void *dest = (void *) bulkpkt->dest;
                size_t len = (size_t) (bulkpkt->dest_off + bulkpkt->len);
                for (i = 0; i < nargs; i++)
                    args[i] = pkt->args[i];
                QMARKFREE(bulkpkt);
                fn(&tok, args, nargs, dest, len);
            }
            else 
                QMARKFREE(bulkpkt);
        }
    }
    return;
}

static
psm_error_t
amsh_mq_rndv(ptl_t *ptl, psm_mq_t mq, psm_mq_req_t req,
             psm_epaddr_t epaddr, uint64_t tag, const void *buf, uint32_t len)
{
    psm_amarg_t args[5];
    psm_error_t err = PSM_OK;

    args[0].u32w0 = MQ_MSG_RTS;
    args[0].u32w1 = len;
    args[1].u64w0 = tag;
    args[2].u64w0 = (uint64_t)(uintptr_t) req;
    args[3].u64w0 = (uint64_t)(uintptr_t) buf;
    /* If KNEM Get is active register region for peer to get from */
    if (ptl->ep->psmi_kassist_mode == PSMI_KASSIST_KNEM_GET) 
      args[4].u64w0 = knem_register_region((void*) buf, len, PSMI_FALSE);
    else
      args[4].u64w0 = 0; 
    
    psmi_assert(req != NULL);
    req->type = MQE_TYPE_SEND;
    req->buf  = (void *) buf;
    req->buf_len = len;
    req->send_msglen = len;
    req->send_msgoff = 0;

    psmi_amsh_short_request(ptl, epaddr, mq_handler_hidx, args, 5, NULL, 0, 0);

    return err;
}

/*
 * All shared am mq sends, req can be NULL
 */
PSMI_ALWAYS_INLINE(
psm_error_t
amsh_mq_send_inner(psm_mq_t mq, psm_mq_req_t req, psm_epaddr_t epaddr, 
                   uint32_t flags, uint64_t tag, const void *ubuf, uint32_t len))
{
    psm_amarg_t args[3];
    psm_error_t err = PSM_OK;
    int is_blocking = (req == NULL);

    if (!flags && len <= psmi_am_max_sizes.request_short) {
	if (len <= 32) 
	    args[0].u32w0 = MQ_MSG_TINY;
	else 
	    args[0].u32w0 = MQ_MSG_SHORT;
	args[1].u64 = tag;

	psmi_amsh_short_request(epaddr->ptl, epaddr, mq_handler_hidx, args, 2, 
				ubuf, len, 0);
    }
    else if (flags & PSM_MQ_FLAG_SENDSYNC)
        goto do_rendezvous;
    else if (len <= mq->shm_thresh_rv) {
	uint32_t bytes_left = len;
	uint32_t bytes_this = min(bytes_left, psmi_am_max_sizes.request_short);
	uint8_t *buf = (uint8_t *)ubuf;
	args[0].u32w0 = MQ_MSG_LONG;
        args[0].u32w1 = len;
	args[1].u64 = tag;
	psmi_amsh_short_request(epaddr->ptl, epaddr, mq_handler_hidx, args, 2, 
				buf, bytes_this, 0);
	bytes_left -= bytes_this;
	buf += bytes_this;
	args[2].u32w0 = 0;
	while (bytes_left) {
	    args[2].u32w0 += bytes_this;
	    bytes_this = min(bytes_left, psmi_am_max_sizes.request_short);
	    /* Here we kind of bend the rules, and assume that shared-memory
	     * active messages are delivered in order */
	    psmi_amsh_short_request(epaddr->ptl, epaddr,
				mq_handler_data_hidx, args, 
				    3, buf, bytes_this, 0);
	    buf += bytes_this;
	    bytes_left -= bytes_this;
	}
    }
    else {
do_rendezvous:
        if (is_blocking) {
            req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
            if_pf (req == NULL)
                return PSM_NO_MEMORY;
            req->send_msglen = len;
            req->tag = tag;
        }
        err = amsh_mq_rndv(epaddr->ptl,mq,req,epaddr,tag,ubuf,len);

        if (err == PSM_OK && is_blocking) { /* wait... */
	    err = psmi_mq_wait_internal(&req);
	}
        return err; /* skip eager accounting below */
    }

    /* All eager async sends are always "all done" */
    if (req != NULL) {
        req->state = MQ_STATE_COMPLETE;
        mq_qq_append(&mq->completed_q, req);
    }

    mq->stats.tx_num++;
    mq->stats.tx_shm_num++;
    mq->stats.tx_eager_num++;
    mq->stats.tx_eager_bytes += len;

    return err;
}

static
psm_error_t
amsh_mq_isend(psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	      uint64_t tag, const void *ubuf, uint32_t len, void *context,
              psm_mq_req_t *req_o)
{
    psm_mq_req_t req = psmi_mq_req_alloc(mq, MQE_TYPE_SEND);
    if_pf (req == NULL)
        return PSM_NO_MEMORY;

    req->send_msglen = len;
    req->tag = tag;
    req->context = context;

    _IPATH_VDBG("[ishrt][%s->%s][n=0][b=%p][l=%d][t=%"PRIx64"]\n", 
        psmi_epaddr_get_name(epaddr->ep->epid),
        psmi_epaddr_get_name(epaddr->epid), ubuf, len, tag);

    amsh_mq_send_inner(mq, req, epaddr, flags, tag, ubuf, len);

    *req_o = req;
    return PSM_OK;
}

static
psm_error_t
amsh_mq_send(psm_mq_t mq, psm_epaddr_t epaddr, uint32_t flags, 
	      uint64_t tag, const void *ubuf, uint32_t len)
{
    amsh_mq_send_inner(mq, NULL, epaddr, flags, tag, ubuf, len);

    _IPATH_VDBG("[shrt][%s->%s][n=0][b=%p][l=%d][t=%"PRIx64"]\n", 
        psmi_epaddr_get_name(epaddr->ep->epid),
        psmi_epaddr_get_name(epaddr->epid), ubuf, len, tag);

    return PSM_OK;
}

/* Kcopy-related handling */
int
psmi_epaddr_kcopy_pid(psm_epaddr_t epaddr)
{
    int shmidx = epaddr->_shmidx;
    return epaddr->ep->amsh_qdir[shmidx].kassist_pid;
}

static
int
psmi_kcopy_find_minor(int *minor)
{
    int i;
    char path[128];

    /* process-wide kcopy filedescriptor */
    static int fd = -1;
    static int kcopy_minor = -1;

    if (fd >= 0) {
	*minor = kcopy_minor;
	return fd;
    }

    for (i = 0; i < 256; i++) {
	snprintf(path, sizeof(path), "/dev/kcopy/%02d", i);
	fd = open(path, O_WRONLY | O_EXCL);
	if (fd >= 0) {
	    *minor = kcopy_minor = i;
	    break;
	}
    }

    return fd;
}

static
int
psmi_kcopy_open_minor(int minor)
{
    char path[128];

    /* process-wide kcopy filedescriptor */
    static int fd = -1;
    if (fd >= 0)
	return fd;

    if (minor >= 0 && minor < 256) {
	snprintf(path, sizeof(path), "/dev/kcopy/%02d", minor);
	fd = open(path, O_WRONLY);
    }
    return fd;
}

static
const char *
psmi_kassist_getmode(int mode)
{
    switch (mode) {
        case PSMI_KASSIST_OFF:
	    return "kassist off";
	case PSMI_KASSIST_KCOPY_PUT:
	    return "kcopy put";
	case PSMI_KASSIST_KCOPY_GET:
	    return "kcopy get";
        case PSMI_KASSIST_KNEM_GET:
	    return "knem get";
        case PSMI_KASSIST_KNEM_PUT:
	    return "knem put";
	default:
	    return "unknown";
    }
}

static
int
psmi_get_kassist_mode()
{
  int mode = PSMI_KASSIST_MODE_DEFAULT;
  union psmi_envvar_val env_kassist;

  /* Preserve backward compatibility */
  if (!psmi_getenv("PSM_SHM_KCOPY", 
		   "PSM Shared Memory use kcopy (put,get,none)",
		   PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
		   (union psmi_envvar_val) "put",
		   &env_kassist))
    {
      char *s = env_kassist.e_str;
      if (strcasecmp(s, "put") == 0)
	mode = PSMI_KASSIST_KCOPY_PUT;
      else if (strcasecmp(s, "get") == 0)
	mode = PSMI_KASSIST_KCOPY_PUT;
      else
	mode = PSMI_KASSIST_OFF;
    }
  else if(!psmi_getenv("PSM_KASSIST_MODE",
		       "PSM Shared memory kernel assist mode "
		       "(knem-put, knem-get, kcopy-put, kcopy-get, none)",
		       PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
		       (union psmi_envvar_val) PSMI_KASSIST_MODE_DEFAULT_STRING,
		       &env_kassist)) 
    {
      char *s = env_kassist.e_str;
      if (strcasecmp(s, "kcopy-put") == 0)
	mode = PSMI_KASSIST_KCOPY_PUT;
      else if (strcasecmp(s, "kcopy-get") == 0)
	mode = PSMI_KASSIST_KCOPY_GET;
      else if (strcasecmp(s, "knem-put") == 0)
	mode = PSMI_KASSIST_KNEM_PUT;
      else if (strcasecmp(s, "knem-get") == 0)
	mode = PSMI_KASSIST_KNEM_GET;
      else
	mode = PSMI_KASSIST_OFF;

#if !defined(PSM_USE_KNEM)
      if (mode & PSMI_KASSIST_KNEM) {
      	_IPATH_ERROR("KNEM kassist mode requested which has not been compiled "
		     "into this version of PSM. Switching kassist mode off.\n");
      	mode = PSMI_KASSIST_OFF;
      }
#endif
    }
  else {
    
#if defined(PSM_USE_KNEM)   
    int res;
    
    /* KNEM is the preferred access mechanism if available. Else default to
     * using KCOPY.
     */
    res = access(KNEM_DEVICE_FILENAME, R_OK | W_OK);
    if (res == 0)
      mode = PSMI_KASSIST_KNEM_PUT;
    else 
      mode = PSMI_KASSIST_KCOPY_PUT;
#else
    mode = PSMI_KASSIST_KCOPY_PUT;
#endif
  }

  return mode;
}

/* Connection handling for shared memory AM.
 *
 * arg0 => conn_op, result (PSM error type)
 * arg1 => epid (always)
 * arg2 => version.
 * arg3 => pointer to error for replies.
 */
static
void
amsh_conn_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len)
{
    int op          = args[0].u32w0;
    int phase       = args[0].u32w1;
    psm_epid_t epid = args[1].u64w0;
    psm_error_t err = (psm_error_t) args[2].u32w1;
    psm_error_t *perr = (psm_error_t *) (uintptr_t) args[3].u64w0;

    psm_epaddr_t epaddr;
    amsh_am_token_t *tok = (amsh_am_token_t *) toki;
    int shmidx = tok->shmidx;
    int is_valid;
    ptl_t *ptl = tok->ptl;

    /* We do this because it's an assumption below */
    psmi_assert_always(buf == NULL && len == 0);

    _IPATH_VDBG("Conn op=%d, phase=%d, epid=%llx, err=%d\n",
            op, phase, (unsigned long long) epid, err);
    switch (op) {
        case PSMI_AM_CONN_REQ: 
            _IPATH_VDBG("Connect from %d:%d\n",
		    (int) psm_epid_nid(epid),
		    (int) psm_epid_context(epid));

            epaddr = psmi_epid_lookup(ptl->ep, epid);
            if (epaddr == NULL) {
                uintptr_t args_segoff =
                    (uintptr_t) args - ptl->ep->amsh_blockbase;
                /* This can be nasty.  If the segment moves as a result of
                 * adding a new peer, we have to fix the input pointer 'args'
                 * since it comes from a shared memory location */
                if ((err = amsh_epaddr_add(ptl, epid, shmidx, &epaddr)))
                    /* Unfortunately, no way out of here yet */
                    psmi_handle_error(PSMI_EP_NORETURN, err, "Fatal error "
		     "in connecting to shm segment"); 
                args = (psm_amarg_t *) (ptl->ep->amsh_blockbase + args_segoff);
            }
            /* Do some version comparison, error checking if required. */
            /* Rewrite args */
            ptl->connect_from++;
            args[0].u32w0 = PSMI_AM_CONN_REP;
            args[1].u64w0 = (psm_epid_t) ptl->epid;
            args[2].u32w1 = PSM_OK;
            AMSH_CSTATE_FROM_SET(epaddr, ESTABLISHED);
            tok->tok.epaddr_from = epaddr; /* adjust token */
            psmi_amsh_short_reply(tok, amsh_conn_handler_hidx, 
                                  args, narg, NULL, 0, 0);
            break;

        case PSMI_AM_CONN_REP: 
            if (ptl->connect_phase != phase) {
                _IPATH_VDBG("Out of phase connect reply\n");
                return;
            }
            epaddr = ptl->shmidx_map_epaddr[shmidx];
            *perr = err;
            AMSH_CSTATE_TO_SET(epaddr, REPLIED);
            ptl->connect_to++;
            _IPATH_VDBG("CCC epaddr=%s connected to ptl=%p\n",
                    psmi_epaddr_get_name(epaddr->epid), ptl);
            break;

        case PSMI_AM_DISC_REQ: 
            epaddr = tok->tok.epaddr_from;
            args[0].u32w0 = PSMI_AM_DISC_REP;
            args[2].u32w1 = PSM_OK;
            AMSH_CSTATE_FROM_SET(epaddr, DISC_REQ);
            ptl->connect_from--;
            /* Before sending the reply, make sure the process
             * is still connected */

            pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
            if (ptl->ep->amsh_dirpage->shmidx_map_epid[shmidx] != epaddr->epid) 
                is_valid = 0;
            else
                is_valid = 1;
            pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
            
            if (is_valid)
                psmi_amsh_short_reply(tok, amsh_conn_handler_hidx, 
                                  args, narg, NULL, 0, 0);
            break;

        case PSMI_AM_DISC_REP: 
            if (ptl->connect_phase != phase) {
                _IPATH_VDBG("Out of phase disconnect reply\n");
                return;
            }
            *perr = err;
            epaddr = tok->tok.epaddr_from;
            AMSH_CSTATE_TO_SET(epaddr, DISC_REPLIED);
            ptl->connect_to--;
            break;

        default:
            psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
                    "Unknown/unhandled connect handler op=%d", op);
            break;
    }
    return;
}

static
size_t
amsh_sizeof(void)
{
    return sizeof(ptl_t);
}

/**
 * @param ep PSM Endpoint, guaranteed to have initialized epaddr and epid.
 * @param ptl Pointer to caller-allocated space for PTL (fill in)
 * @param ctl Pointer to caller-allocated space for PTL-control 
 *            structure (fill in)
 */
static
psm_error_t 
amsh_init(psm_ep_t ep, ptl_t *ptl, ptl_ctl_t *ctl)
{
    psm_error_t err = PSM_OK;

    /* Preconditions */
    psmi_assert_always(ep != NULL);
    psmi_assert_always(ep->epaddr != NULL);
    psmi_assert_always(ep->epid != 0);

    ptl->ep     = ep; /* back pointer */
    ptl->epid   = ep->epid; /* cache epid */
    ptl->epaddr = ep->epaddr; /* cache a copy */
    ptl->ctl    = ctl;
    ptl->zero_polls = 0;

    pthread_mutex_init(&ptl->connect_lock, NULL);
    ptl->connect_phase = 0;
    ptl->connect_from = 0;
    ptl->connect_to = 0;

    memset(&ptl->amsh_empty_shortpkt, 0, sizeof ptl->amsh_empty_shortpkt);
    memset(&ptl->psmi_am_reqq_fifo, 0, sizeof ptl->psmi_am_reqq_fifo);

    if ((err = amsh_init_segment(ptl)))
        goto fail;

    psmi_am_reqq_init(ptl);
    memset(ctl, 0, sizeof(*ctl));

    /* Fill in the control structure */
    ctl->ptl = ptl;
    ctl->ep_poll = amsh_poll;
    ctl->ep_connect = amsh_ep_connect;
    ctl->ep_disconnect = amsh_ep_disconnect;

    ctl->mq_send  = amsh_mq_send;
    ctl->mq_isend = amsh_mq_isend;
    
    ctl->am_short_request = psmi_amsh_am_short_request;
    ctl->am_short_reply   = psmi_amsh_am_short_reply;

    /* No stats in shm (for now...) */
    ctl->epaddr_stats_num  = NULL;
    ctl->epaddr_stats_init = NULL;
    ctl->epaddr_stats_get  = NULL;
fail:
    return err;
}

static
psm_error_t 
amsh_fini(ptl_t *ptl, int force, uint64_t timeout_ns)
{
    struct psmi_eptab_iterator itor;
    psm_epaddr_t epaddr;
    psm_error_t err = PSM_OK;
    psm_error_t err_seg;
    uint64_t t_start = get_cycles();
    int i = 0;

    /* Close whatever has been left open -- this will be factored out for 2.1 */
    if (ptl->connect_to > 0) {
        int num_disc = 0;
        int *mask;
        psm_error_t  *errs;
        psm_epaddr_t *epaddr_array;

        psmi_epid_itor_init(&itor, ptl->ep);
        while ((epaddr = psmi_epid_itor_next(&itor))) {
            if (epaddr->ptl != ptl)
                continue;
            if (AMSH_CSTATE_TO_GET(epaddr) == AMSH_CSTATE_TO_ESTABLISHED) 
                num_disc++;
        }
        psmi_epid_itor_fini(&itor);

	mask = (int *) psmi_calloc(ptl->ep, UNDEFINED, num_disc, sizeof(int));
	errs = (psm_error_t *)
		psmi_calloc(ptl->ep, UNDEFINED, num_disc, sizeof(psm_error_t));
	epaddr_array = (psm_epaddr_t *) 
            psmi_calloc(ptl->ep, UNDEFINED, num_disc, sizeof(psm_epaddr_t));

	if (errs == NULL || epaddr_array == NULL || mask == NULL) {
	    err = PSM_NO_MEMORY;
	    goto fail;
	}
        psmi_epid_itor_init(&itor, ptl->ep);
        while ((epaddr = psmi_epid_itor_next(&itor))) {
            if (epaddr->ptl == ptl) {
                if (AMSH_CSTATE_TO_GET(epaddr) == AMSH_CSTATE_TO_ESTABLISHED) {
                    mask[i] = 1;
                    epaddr_array[i] = epaddr;
                    i++;
                }
            }
        }
        psmi_epid_itor_fini(&itor);
        psmi_assert(i == num_disc && num_disc > 0);
	err = amsh_ep_disconnect(ptl, force, num_disc, epaddr_array, 
			    mask, errs, timeout_ns);
        psmi_free(mask);
        psmi_free(errs);
        psmi_free(epaddr_array);
    }

    if (ptl->connect_from > 0 || ptl->connect_to > 0) {
        while (ptl->connect_from > 0 || ptl->connect_to > 0) {
            if (!psmi_cycles_left(t_start, timeout_ns)) {
                err = PSM_TIMEOUT;
                _IPATH_VDBG("CCC timed out with from=%d,to=%d\n",
                        ptl->connect_from,
                        ptl->connect_to);
                break;
            }
	    psmi_poll_internal(ptl->ep, 1);
        }
    }
    else
        _IPATH_VDBG("CCC complete disconnect from=%d,to=%d\n", 
                ptl->connect_from,
                ptl->connect_to);

    if ((err_seg = psmi_shm_detach(ptl->ep))) {
        err = err_seg;
        goto fail;
    }

    /* This prevents poll calls between now and the point where the endpoint is
     * deallocated to reference memory that disappeared */
    ptl->repH.head  = &ptl->amsh_empty_shortpkt;
    ptl->reqH.head  = &ptl->amsh_empty_shortpkt;

    return PSM_OK;
fail:
    return err;

}

static 
psm_error_t
amsh_setopt(const void *component_obj, int optname, 
	       const void *optval, uint64_t optlen)
{
  /* No options for AM PTL at the moment */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown AM ptl option %u.", optname);
}

static
psm_error_t
amsh_getopt(const void *component_obj, int optname,
	       void *optval, uint64_t *optlen)
{
  /* No options for AM PTL at the moment */
  return psmi_handle_error(NULL, PSM_PARAM_ERR, "Unknown AM ptl option %u.", optname);
}

/* Only symbol we expose out of here */
struct ptl_ctl_init
psmi_ptl_amsh = { 
  amsh_sizeof, amsh_init, amsh_fini, amsh_setopt, amsh_getopt
};

