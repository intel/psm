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
#include "scifrw.h"

struct psm_am_max_sizes {
    uint32_t   nargs;
    uint32_t   request_short;
    uint32_t   reply_short;
    uint32_t   request_long;
    uint32_t   reply_long;
};

int psmi_shm_mq_rv_thresh = PSMI_MQ_RV_THRESH_NO_KASSIST;

#ifdef PSM_HAVE_SCIF
#define PSM_SCIF_CONNECT_RETRIES_DEFAULT 40
int psmi_scif_connect_retries = PSM_SCIF_CONNECT_RETRIES_DEFAULT;
#endif

/* If we push bulk packets, we place them in the target's bulk packet region,
 * if we don't push bulk packets, we place them in *our* bulk packet region and
 * have the target pull the data from our region when it needs it. */
#define AMSH_BULK_PUSH  1

/* When do we start using the "huge" buffers -- at 1MB */
#define AMSH_HUGE_BYTES 1024*1024

#define AMMED_SZ    2048
#define AMLONG_SZ   8192
#define AMHUGE_SZ   (524288+sizeof(am_pkt_bulk_t)) /* 512k + E */

/*       short med long huge */
static const amsh_qinfo_t amsh_qcounts =
        { 1024, 256, 16, 1, 1024, 256, 16, 8 };

/*        short                   med          long       huge */
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
        
#define QGETPTR_SCIF(ptl, _shmidx_, _node_, _fifo, _fifotyp, _idx)	       \
	(am_pkt_ ## _fifotyp ## _t *)			                       \
	(((uintptr_t)ptl->ep->amsh_qdir[(_shmidx_)].qptrs[_node_].q ## _fifo) +\
		    (_idx) *amsh_qelemsz.q ## _fifo)

#ifdef PSM_HAVE_SCIF
static void *am_ctl_accept_thread(void *arg);
static psm_error_t amsh_scif_detach(psm_ep_t ep);
#endif
static psm_error_t amsh_poll(ptl_t *ptl, int replyonly);
static psm_error_t amsh_poll_internal_inner(ptl_t *ptl, int replyonly, int is_internal);
static void process_packet(ptl_t *ptl, am_pkt_short_t *pkt, int isreq);
static void amsh_conn_handler(void *toki, psm_amarg_t *args, int narg, 
                              void *buf, size_t len);
static void am_update_directory(ptl_t *ptl, int shmidx);

/* Kassist helper functions */
static const char * psmi_kassist_getmode(int mode);
static int psmi_get_kassist_mode();

/* SCIF DMA helper functions */
#ifdef PSM_HAVE_SCIF
static const char * psmi_scif_dma_getmode(int mode);
static int psmi_get_scif_dma_mode();
static int psmi_get_scif_dma_threshold();
#endif

/* Kcopy functionality */
int psmi_epaddr_kcopy_pid(psm_epaddr_t epaddr);
static int psmi_kcopy_find_minor(int *minor);
static int psmi_kcopy_open_minor(int minor);

static inline void
am_ctl_qhdr_init(volatile am_ctl_qhdr_t *q, int elem_cnt, int elem_sz)
{
    q->head = 0;
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

/**
 * Given a number of PEs, determine the amount of memory required.
 */
static
size_t
psmi_amsh_segsize(int num_pe, int num_nodes)
{
    size_t segsz;
    segsz  = PSMI_ALIGNUP(sizeof(struct am_ctl_dirpage), PSMI_PAGESIZE);
    segsz += am_ctl_sizeof_block() * num_pe * num_nodes;
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

/*
 * Scif init to modify the epid of current process.
 */
#ifdef PSM_HAVE_SCIF
static
psm_error_t
amsh_scif_init(psm_ep_t ep)
{
    scif_epd_t epd;
    int port, nnodes;
    uint16_t self;
    psm_error_t err;
    union psmi_envvar_val env_retries;

    if(!psmi_getenv("PSM_SCIF_CONNECT_RETRIES",
                "PSM SCIF connection retry count",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) psmi_scif_connect_retries,
                &env_retries)) {
        psmi_scif_connect_retries = env_retries.e_uint;
    }

    /* open end pt */
    if ((epd = scif_open()) < 0) {
	err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
			"scif_open() failed with err %d", errno);
	return err;
    }

    /* bind end pt to specified port */
    if ((port = scif_bind(epd, 0)) < 0) {
	scif_close(epd);
	err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
			"scif_bind() failed with err %d", errno);
	return err;
    }

    /* marks an end pt as listening end pt and queues up a maximum of 32
     * incoming connection requests */
    if (scif_listen(epd, 40) != 0) {
	scif_close(epd);
	err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
			"scif_listen() failed with err %d", errno);
	return err;
    }

    if ((nnodes = scif_get_nodeIDs(NULL, 0, &self)) < 0) {
	scif_close(epd);
	err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
			"scif_get_nodeIDs() failed with err %d", errno);
	return err;
    }

    _IPATH_VDBG("listening on SCIF %d:%d\n", self, port);

    /* Save total scif node #, modify epid to include port and self node ID.*/
    ep->scif_epd = epd;
    ep->scif_mynodeid = (int)self;
    ep->scif_nnodes = nnodes;

    /* Modify epid with acquired info as below */
    ep->epid |= (((uint64_t)self)&0xFF)<<48;
    ep->epid |= (((uint64_t)port)&0xFFFF)<<32;

    return PSM_OK;
}
#endif

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
    }

#ifdef PSM_HAVE_SCIF
    ep->amsh_qdir = psmi_calloc(NULL, PER_PEER_ENDPOINT,
			    PTL_AMSH_MAX_LOCAL_PROCS*ep->scif_nnodes,
			    sizeof(struct amsh_qdirectory));
#else
    ep->amsh_qdir = psmi_calloc(NULL, PER_PEER_ENDPOINT, 
			    PTL_AMSH_MAX_LOCAL_PROCS,
			    sizeof(struct amsh_qdirectory));
#endif

    if (ep->amsh_qdir == NULL) {
	err = PSM_NO_MEMORY;
	goto fail;
    }
    
    /* Get which kassist mode to use. */
    ep->psmi_kassist_mode = psmi_get_kassist_mode();
    use_kassist = (ep->psmi_kassist_mode != PSMI_KASSIST_OFF);
    use_kcopy = (ep->psmi_kassist_mode & PSMI_KASSIST_KCOPY);

#ifdef PSM_HAVE_SCIF
    ep->scif_dma_mode = psmi_get_scif_dma_mode();
    ep->scif_dma_threshold = psmi_get_scif_dma_threshold();
#endif

    /* Reserve enough space in the shared memory region for up to
       PTL_AMSH_MAX_LOCAL_PROCS.  Although that much space is reserved in
       virtual memory, physical pages are not allocated until the
       corresponding memory location is touched.  Memory in this region is
       only touched as processes initialize their shared queue area in
       amsh_init_segment(), and physical memory is only allocated by the OS
       accordingly.  So, it looks like this is consumes a lot of memory,
       but really it consumes as much as necessary for each active process. */
#ifdef PSM_HAVE_SCIF
    segsz = psmi_amsh_segsize(PTL_AMSH_MAX_LOCAL_PROCS,
                              PTL_AMSH_MAX_LOCAL_NODES);
#else
    /* In the non-SCIF case we should be able to get away with just allocating
     * enough shm for the number of mpi ranks, if the number of ranks is
     * unavailable, then we will fallback to the number of online cpu cores.
     * This will help cut back on virtual memory usage.
     */
    int nranks, rankid, nprocs;
    psmi_sharedcontext_params(&nranks, &rankid);
    nprocs = (nranks <= 0) ? sysconf(_SC_NPROCESSORS_ONLN) : nranks;
    segsz = psmi_amsh_segsize(nprocs, PTL_AMSH_MAX_LOCAL_NODES);
#endif

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
    
    /* We map the entire shared memory area, consisting of a control structure
     * followed by per-process shared queue structures.  The "master" creates
     * the control structure and initializes it but every process must lock
     * appropriate data structures before it reads or writes it.
     */
    mapptr = mmap(NULL, segsz, PROT_READ|PROT_WRITE, MAP_SHARED,
                  ep->amsh_shmfd, 0);
    if (mapptr == MAP_FAILED) {
        err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                "Error mmapping shared memory: %s", strerror(errno));
        goto fail;
    }

    ep->amsh_shmbase = (uintptr_t) mapptr;
    ep->amsh_dirpage = (struct am_ctl_dirpage *) ep->amsh_shmbase;
    ep->amsh_blockbase = ep->amsh_shmbase + psmi_amsh_segsize(0, 0);

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

        for(i = 0; i < PTL_AMSH_MAX_LOCAL_PROCS*PTL_AMSH_MAX_LOCAL_NODES; i++) {
            struct amsh_qtail* qtail = &ep->amsh_dirpage->qtails[i];

            qtail->reqFifoShort.tail = 0;
            qtail->reqFifoMed.tail = 0;
            qtail->reqFifoLong.tail = 0;
            qtail->reqFifoHuge.tail = 0;

            qtail->repFifoShort.tail = 0;
            qtail->repFifoMed.tail = 0;
            qtail->repFifoLong.tail = 0;
            qtail->repFifoHuge.tail = 0;

            pthread_spin_init(&qtail->reqFifoShort.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->reqFifoMed.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->reqFifoLong.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->reqFifoHuge.lock, PTHREAD_PROCESS_SHARED);

            pthread_spin_init(&qtail->repFifoShort.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->repFifoMed.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->repFifoLong.lock, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&qtail->repFifoHuge.lock, PTHREAD_PROCESS_SHARED);
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
	_IPATH_PRDBG("Mapped and initialized shm object control page at %p,"
                    "size=%zu, kcopy minor is %d (mode=%s)\n", mapptr,
		    segsz, kcopy_minor,
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
	      else if(use_kcopy) {
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
#ifdef PSM_HAVE_SCIF
	    _IPATH_PRDBG("SCIF DMA MODE: %s\n", psmi_scif_dma_getmode(ep->scif_dma_mode));
	    _IPATH_PRDBG("SCIF DMA THRESHOLD: %d\n", ep->scif_dma_threshold);
#endif

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
    struct amsh_qptrs* qptrs;
    int shmidx;
    int i;
    psm_error_t err = PSM_OK;
    int scif_nnodes;

    /* Preconditions */
    psmi_assert_always(ptl != NULL);
    psmi_assert_always(ptl->ep != NULL);
    psmi_assert_always(ptl->epaddr != NULL);
    psmi_assert_always(ptl->ep->epid != 0);
    psmi_assert_always(ptl->ep->amsh_shmidx != -1);

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
	ptl->ep->amsh_dirpage->max_idx = shmidx;
    }

    ptl->shmidx = shmidx;
    ptl->ep->amsh_qdir[shmidx].amsh_epaddr = ptl->ep->epaddr;
    for(i = 0; i < PTL_AMSH_MAX_LOCAL_NODES; i++) {
        ptl->reqH[i].base = ptl->reqH[i].head = ptl->reqH[i].end = NULL;
        ptl->repH[i].base = ptl->repH[i].head = ptl->repH[i].end = NULL;
    }

    /* Update all of the local directory entries once here. */
    for(i = 0; i < PTL_AMSH_MAX_LOCAL_PROCS; i++) {
	ptl->ep->amsh_qdir[i].amsh_base =
		(void *)(ptl->ep->amsh_blockbase +
                        am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES * i);

	ptl->ep->amsh_qdir[i].amsh_shmidx = ptl->shmidx;

        /* Encode our SCIF nodeid here.  The full epid for local peers isn't
           known yet, but we do know their nodeid, which is the same as ours.
           Marking the nodeid here enables process_packet() to work correctly
           when packets arrive before this epid value has been set with the
           proper epid, without extra branches in the communication path. */
#ifdef PSM_HAVE_SCIF
        ptl->ep->amsh_qdir[i].amsh_epid =
            ((psm_epid_t)ptl->ep->scif_mynodeid & 0xff) << 48;
#endif

        /* Clear the SCIF socket to -1.  This indicates that the socket is not
           going to be used, ever -- which is true since this is a local peer.
           This prevents later code from trying to connect to self. */
        //ptl->ep->amsh_qdir[i].amsh_epd[0] = -1;

        am_update_directory(ptl, i);
    }

#ifdef PSM_HAVE_SCIF
    scif_nnodes = ptl->ep->scif_nnodes;
#else
    /* No SCIF: assume one node. */
    scif_nnodes = 1;
#endif

    /* touch all of my pages */
    memset(ptl->ep->amsh_qdir[shmidx].amsh_base,
	   0, am_ctl_sizeof_block() * scif_nnodes);

    for(i = 0; i < scif_nnodes; i++) {
        qptrs = &ptl->ep->amsh_qdir[shmidx].qptrs[i];

        am_ctl_qhdr_init(&qptrs->qreqH->shortq,
                amsh_qcounts.qreqFifoShort, amsh_qelemsz.qreqFifoShort);
        am_ctl_qhdr_init(&qptrs->qreqH->medbulkq,
                amsh_qcounts.qreqFifoMed, amsh_qelemsz.qreqFifoMed);
        am_ctl_qhdr_init(&qptrs->qreqH->longbulkq,
                amsh_qcounts.qreqFifoLong, amsh_qelemsz.qreqFifoLong);
        am_ctl_qhdr_init(&qptrs->qreqH->hugebulkq,
                amsh_qcounts.qreqFifoHuge, amsh_qelemsz.qreqFifoHuge);

        am_ctl_qhdr_init(&qptrs->qrepH->shortq,
                amsh_qcounts.qrepFifoShort, amsh_qelemsz.qrepFifoShort);
        am_ctl_qhdr_init(&qptrs->qrepH->medbulkq,
                amsh_qcounts.qrepFifoMed, amsh_qelemsz.qrepFifoMed);
        am_ctl_qhdr_init(&qptrs->qrepH->longbulkq,
                amsh_qcounts.qrepFifoLong, amsh_qelemsz.qrepFifoLong);
        am_ctl_qhdr_init(&qptrs->qrepH->hugebulkq,
                amsh_qcounts.qrepFifoHuge, amsh_qelemsz.qrepFifoHuge);

        /* Set bulkidx in every bulk packet */
        am_ctl_bulkpkt_init(qptrs->qreqFifoMed,
                amsh_qelemsz.qreqFifoMed,
                amsh_qcounts.qreqFifoMed);
        am_ctl_bulkpkt_init(qptrs->qreqFifoLong,
                amsh_qelemsz.qreqFifoLong,
                amsh_qcounts.qreqFifoLong);
        am_ctl_bulkpkt_init(qptrs->qreqFifoHuge,
                amsh_qelemsz.qreqFifoHuge,
                amsh_qcounts.qreqFifoHuge);

        am_ctl_bulkpkt_init(qptrs->qrepFifoMed,
                amsh_qelemsz.qrepFifoMed,
                amsh_qcounts.qrepFifoMed);
        am_ctl_bulkpkt_init(qptrs->qrepFifoLong,
                amsh_qelemsz.qrepFifoLong,
                amsh_qcounts.qrepFifoLong);
        am_ctl_bulkpkt_init(qptrs->qrepFifoHuge,
                amsh_qelemsz.qrepFifoHuge,
                amsh_qcounts.qrepFifoHuge);
    }

    /* install the old sighandler back */
    signal(SIGSEGV, old_handler_segv);
    signal(SIGBUS, old_handler_bus);

    pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
    return err;
}

psm_error_t
psmi_shm_detach(psm_ep_t ep)
{
    psm_error_t err = PSM_OK;

    if (ep->amsh_shmidx == -1 || ep->amsh_keyname == NULL)
        return err;

#ifdef PSM_HAVE_SCIF
    if (amsh_scif_detach(ep)) {
        err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                "Error with amsh_scif_detach() of shared segment: %s",
                strerror(errno));
        goto fail;
    }
#endif

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
	pthread_mutex_unlock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));

        /* Instead of dynamically shrinking the shared memory region, we always
           leave it allocated for up to PTL_AMSH_MAX_LOCAL_PROCS or number
           of processors online.
           Thus mremap() is never necessary, nor is ftruncate() here.
           However when the attached process count does go to 0, we should
           fully munmap() the entire region.
         */
#ifdef PSM_HAVE_SCIF
        if (munmap((void *) ep->amsh_shmbase,
                    psmi_amsh_segsize(PTL_AMSH_MAX_LOCAL_PROCS,
                                      PTL_AMSH_MAX_LOCAL_NODES))) {
#else
        int nranks, rankid, nprocs;
        psmi_sharedcontext_params(&nranks, &rankid);
        nprocs = (nranks <= 0) ? sysconf(_SC_NPROCESSORS_ONLN) : nranks;
        if (munmap((void *) ep->amsh_shmbase,
                    psmi_amsh_segsize(nprocs, PTL_AMSH_MAX_LOCAL_NODES))) {
#endif
            err = psmi_handle_error(NULL, PSM_SHMEM_SEGMENT_ERR,
                    "Error with munamp of shared segment: %s", strerror(errno));
            goto fail;
        }
    }
    else {
        int i, new_max_idx = ep->amsh_dirpage->max_idx;
        for (i = ep->amsh_dirpage->max_idx; i >= 0; i--) {
            if (ep->amsh_dirpage->shmidx_map_epid[i] == 0) 
                new_max_idx = i;
            else
                break;
        }

        ep->amsh_dirpage->max_idx = new_max_idx;

        pthread_mutex_unlock((pthread_mutex_t *) &(ep->amsh_dirpage->lock));
    }

    ep->amsh_max_idx = -1;
    ep->amsh_shmfd = -1;

    ep->amsh_shmbase = ep->amsh_blockbase = 0;
    ep->amsh_dirpage = NULL;
    memset(ep->amsh_keyno, 0, sizeof(ep->amsh_keyno));

    return PSM_OK;

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
    int node;

    for(node = 0; node < PTL_AMSH_MAX_LOCAL_NODES; node++) {
        reqH[node].base = QGETPTR_SCIF(ptl, shmidx, node,
                reqFifoShort, short, 0);
        reqH[node].head = QGETPTR_SCIF(ptl, shmidx, node,
                reqFifoShort, short, 0);
        reqH[node].end  = QGETPTR_SCIF(ptl, shmidx, node,
                reqFifoShort, short, amsh_qcounts.qreqFifoShort);

        repH[node].base = QGETPTR_SCIF(ptl, shmidx, node,
                repFifoShort, short, 0);
        repH[node].head = QGETPTR_SCIF(ptl, shmidx, node,
                repFifoShort, short, 0);
        repH[node].end  = QGETPTR_SCIF(ptl, shmidx, node,
                repFifoShort, short, amsh_qcounts.qrepFifoShort);
    }
}

/**
 * Update locally cached shared-pointer directory.
 *
 * @param shmidx Endpoint index for which to update local directory.
 */

static
void
am_update_directory(ptl_t *ptl, int shmidx)
{
    psm_ep_t ep = ptl->ep;
    uintptr_t base_this;
    uintptr_t base_node;
    struct amsh_qptrs* qptrs;
    int i;

    psmi_assert_always(shmidx != -1);
    base_this =
        (uintptr_t)ep->amsh_qdir[shmidx].amsh_base + AMSH_BLOCK_HEADER_SIZE;

    if (shmidx < PTL_AMSH_MAX_LOCAL_PROCS) {
        if(ep->amsh_dirpage->amsh_features[shmidx] & AMSH_HAVE_KASSIST) {
            ep->amsh_qdir[shmidx].kassist_pid =
                ep->amsh_dirpage->kassist_pids[shmidx];
        }
    } else {
        ep->amsh_qdir[shmidx].kassist_pid = 0;
    }

    for(i = 0; i < PTL_AMSH_MAX_LOCAL_NODES; i++) {
        qptrs = &ep->amsh_qdir[shmidx].qptrs[i];

        base_node = base_this + (i * am_ctl_sizeof_block());

        /* Request queues */
        qptrs->qreqH = (am_ctl_blockhdr_t *) base_node;

        qptrs->qreqFifoShort = (am_pkt_short_t *)
            ((uintptr_t) qptrs->qreqH +
             PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE));
        qptrs->qreqFifoMed = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qreqFifoShort +
             ptl->amsh_qsizes.qreqFifoShort);
        qptrs->qreqFifoLong = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qreqFifoMed +
             ptl->amsh_qsizes.qreqFifoMed);
        qptrs->qreqFifoHuge = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qreqFifoLong +
             ptl->amsh_qsizes.qreqFifoLong);

        /* Reply queues */
        qptrs->qrepH = (am_ctl_blockhdr_t *)
            ((uintptr_t) qptrs->qreqFifoHuge +
             ptl->amsh_qsizes.qreqFifoHuge);

        qptrs->qrepFifoShort = (am_pkt_short_t *)
            ((uintptr_t) qptrs->qrepH +
             PSMI_ALIGNUP(sizeof(am_ctl_blockhdr_t), PSMI_PAGESIZE));
        qptrs->qrepFifoMed = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qrepFifoShort +
             ptl->amsh_qsizes.qrepFifoShort);
        qptrs->qrepFifoLong = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qrepFifoMed +
             ptl->amsh_qsizes.qrepFifoMed);
        qptrs->qrepFifoHuge = (am_pkt_bulk_t *)
            ((uintptr_t) qptrs->qrepFifoLong +
             ptl->amsh_qsizes.qrepFifoLong);

        _IPATH_VDBG("shmidx=%d node=%d Request Hdr=%p,Pkt=%p,Med=%p,Long=%p,Huge=%p\n",
                shmidx, i,
                qptrs->qreqH,
                qptrs->qreqFifoShort,
                qptrs->qreqFifoMed,
                qptrs->qreqFifoLong,
                qptrs->qreqFifoHuge);
        _IPATH_VDBG("shmidx=%d node=%d Reply   Hdr=%p,Pkt=%p,Med=%p,Long=%p,Huge=%p\n",
                shmidx, i,
                qptrs->qrepH,
                qptrs->qrepFifoShort,
                qptrs->qrepFifoMed,
                qptrs->qrepFifoLong,
                qptrs->qrepFifoHuge);
    }

    /* Update local shorthand pointers */
#ifdef PSM_HAVE_SCIF
    qptrs = &ep->amsh_qdir[shmidx].qptrs[ptl->ep->scif_mynodeid];
#else
    qptrs = &ep->amsh_qdir[shmidx].qptrs[0];
#endif

    ep->amsh_qdir[shmidx].qreqH = qptrs->qreqH;
    ep->amsh_qdir[shmidx].qreqFifoShort = qptrs->qreqFifoShort;
    ep->amsh_qdir[shmidx].qreqFifoMed = qptrs->qreqFifoMed;
    ep->amsh_qdir[shmidx].qreqFifoLong = qptrs->qreqFifoLong;
    ep->amsh_qdir[shmidx].qreqFifoHuge = qptrs->qreqFifoHuge;

    ep->amsh_qdir[shmidx].qrepH = qptrs->qrepH;
    ep->amsh_qdir[shmidx].qrepFifoShort = qptrs->qrepFifoShort;
    ep->amsh_qdir[shmidx].qrepFifoMed = qptrs->qrepFifoMed;
    ep->amsh_qdir[shmidx].qrepFifoLong = qptrs->qrepFifoLong;
    ep->amsh_qdir[shmidx].qrepFifoHuge = qptrs->qrepFifoHuge;

    /* If we're updating our shmidx, we update our cached pointers */
    if (ptl->shmidx == shmidx)
	am_hdrcache_update_short(ptl, shmidx, 
                                 (am_ctl_qshort_cache_t *) ptl->reqH,
                                 (am_ctl_qshort_cache_t *) ptl->repH);

    /* Sanity check */
    uintptr_t base_next = 
	(uintptr_t) ep->amsh_qdir[shmidx].qptrs[PTL_AMSH_MAX_LOCAL_NODES - 1].qrepFifoHuge + ptl->amsh_qsizes.qrepFifoHuge;

    psmi_assert_always(base_next - base_this <=
            am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES);
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
            return PSM_NO_MEMORY;
        }
        psmi_assert_always(ptl->ep->amsh_qdir[shmidx].amsh_epaddr == NULL);
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

    ptl->ep->amsh_qdir[shmidx].amsh_epaddr = epaddr;

    /* Finally, add to table */
    if ((err = psmi_epid_add(ptl->ep, epid, epaddr)))
        goto fail;

    _IPATH_VDBG("epaddr=%s added to ptl=%p\n",
                psmi_epaddr_get_name(epid), ptl);

    *epaddr_o = epaddr;
    return PSM_OK;
fail:
    if (epaddr != ptl->epaddr) psmi_free(epaddr);
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

/*
 * function to make scif connection between nodes and exchange shared memory
 */
#ifdef PSM_HAVE_SCIF
static int
amsh_scif_send(scif_epd_t epd, void *buf, size_t len)
{
    int ret;
    while (len) {
        ret = scif_send(epd, buf, (uint32_t)len, SCIF_SEND_BLOCK);
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
amsh_scif_recv(scif_epd_t epd, void *buf, size_t len)
{
    int ret;
    while (len) {
        ret = scif_recv(epd, buf, (uint32_t)len, SCIF_RECV_BLOCK);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return ret;
        }
        buf += ret;
        len -= ret;
    }
    return 0;
}

static
psm_error_t
amsh_scif_connect(uint16_t nodeid, uint16_t port, scif_epd_t *epd_o)
{
    int tries;
    struct scif_portID portID;
    scif_epd_t epd;
    psm_error_t err;

    epd = scif_open();
    if (epd < 0) {
        err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
	        "scif_open failed with error %d\n", errno);
        return err;
    }

    portID.port = port;
    portID.node = nodeid;

    _IPATH_VDBG("scif connecting to %d:%d\n", nodeid, port);

    for(tries = 0; tries < psmi_scif_connect_retries; tries++) {
        if (scif_connect(epd, &portID) >= 0) {
            break;
        } else if(errno != ECONNREFUSED) {
            err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                    "scif_connect failed with error %d (%s)\n",
                    errno, strerror(errno));
            scif_close(epd);
            return err;
        }

        /* Wait a bit before trying again. */
        if(tries < 20) {
            usleep(100000);
        } else {
            usleep(250000);
        }
    }

    if(tries == psmi_scif_connect_retries) {
        err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                "scif_connect retry limit exceeded\n");
        return err;
    }

    *epd_o = epd;
    return PSM_OK;
}

/* Establish a connection to a single epid. */
static psm_error_t amsh_scif_setup(ptl_t* ptl, psm_epid_t epid)
{
    psm_ep_t ep = ptl->ep;
    psm_error_t err = PSM_OK;
    scif_epd_t epd = -1;
    void* addr;
    int peeridx;

    /* Send this struct to identify ourselves to the peer (offset unused) */
    /* Receive this struct to get memory mapping information. */
    struct { off_t offset; int verno; psm_epid_t epid; } buf;

    int port = (int)((epid>>32)&0xffff);
    int nodeid = (int)((epid>>48)&0xff);
    int shmidx = (int)((epid>>56)&0xff);

    /* Skip peers on the same node */
    if (nodeid == ep->scif_mynodeid) {
        return PSM_OK;
    }

    /* Figure out the peer's index. */
    /* 0        1 mynodeid 3 4 */
    /* nodeid 0 1          3 4 */
    if(nodeid > ep->scif_mynodeid) {
        peeridx = (PTL_AMSH_MAX_LOCAL_PROCS * nodeid) + shmidx;
    } else /*nodeid < ep->scif_mynodeid) */ {
        peeridx = (PTL_AMSH_MAX_LOCAL_PROCS * (nodeid + 1)) + shmidx;
    }

    _IPATH_VDBG("%lx scif_connect to %d:%d %d %lx\n",
            ep->epid, nodeid, port, peeridx, epid);

    if(ep->amsh_qdir[peeridx].amsh_epd[0] != 0) {
        /* Already established this side of the connection; all done. */
        return err;
    }

    buf.offset = 0;
    buf.verno = PSMI_VERNO;
    buf.epid = ep->epid;

    err = amsh_scif_connect(nodeid, port, &epd);
    if(err) {
        return err;
    }

    /* Send our identification information. */
    if (amsh_scif_send(epd, &buf, sizeof(buf))) {
        err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                "scif_send failed: %d %s\n", errno, strerror(errno));
        scif_close(epd);
        return err;
    }

    /* Receive memory registration information. */
    if(amsh_scif_recv(epd, &buf, sizeof(buf))) {
        err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                "scif_recv failed: %d %s\n", errno, strerror(errno));
        scif_close(epd);
        return err;
    }

    addr = scif_mmap(NULL, am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES,
            SCIF_PROT_READ|SCIF_PROT_WRITE, 0, epd, buf.offset);
    if(addr == SCIF_MMAP_FAILED) {
        err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                "scif_mmap failed: %d %s\n", errno, strerror(errno));
        scif_close(epd);
        return err;
    }

    _IPATH_PRDBG("%lx scif_mmap offset %p -> %p to addr %p -> %p length %ld\n",
            ep->epid, (void*)buf.offset,
            (void*)(buf.offset + am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES),
            addr,
            (void*)((uintptr_t)addr + am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES),
            am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES);

    ep->amsh_qdir[peeridx].amsh_offset = buf.offset;
    ep->amsh_qdir[peeridx].amsh_base = addr;
    ep->amsh_qdir[peeridx].amsh_epid = buf.epid;
    ep->amsh_qdir[peeridx].amsh_verno = buf.verno;

    /* Calculate my index from the peer's perspective. */
    /* 0        1 mynodeid 3 4 */
    /* nodeid   0 1        3 4 */
    if(ep->scif_mynodeid < nodeid) {
        ep->amsh_qdir[peeridx].amsh_shmidx =
            (PTL_AMSH_MAX_LOCAL_PROCS * (ep->scif_mynodeid + 1)) +
            ep->amsh_shmidx;
    } else {
        ep->amsh_qdir[peeridx].amsh_shmidx =
            (PTL_AMSH_MAX_LOCAL_PROCS * ep->scif_mynodeid) +
            ep->amsh_shmidx;
    }

    /* There are eventually two connections.  epd[0] always has the remote
       memory mapped region associated with it, and is used to make requests
       to that peer.  epd[1] exposes our local shared memory, and is used
       to respond to remote requests. */
    ep->amsh_qdir[peeridx].amsh_epd[0] = epd;

    am_update_directory(ptl, peeridx);

    _IPATH_VDBG("shmidx %d connected! set peeridx %d amsh_shmidx %d epd %d\n",
            ep->amsh_shmidx, peeridx,
            ep->amsh_qdir[peeridx].amsh_shmidx,
            ep->amsh_qdir[peeridx].amsh_epd[0]);
    return err;
}

static
psm_error_t
amsh_scif_detach(psm_ep_t ep)
{
    int i;
    int size = am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES;

    /* do the rest scif cleanup work */
    for (i = 0; i < ep->scif_nnodes*PTL_AMSH_MAX_LOCAL_PROCS; i++) {
	if (ep->amsh_qdir[i].amsh_epd[0] == 0) continue;

        if(i >= PTL_AMSH_MAX_LOCAL_PROCS) {
            if(scif_munmap(ep->amsh_qdir[i].amsh_base, size)) {
                _IPATH_INFO("SCIF: unmapping addr %p length %d failed: (%d) %s\n",
                        ep->amsh_qdir[i].amsh_base, size,
                        errno, strerror(errno));
                return PSM_INTERNAL_ERR;
            }

            ep->amsh_qdir[i].amsh_base = NULL;
        }

	if(scif_close(ep->amsh_qdir[i].amsh_epd[0])) {
            _IPATH_INFO("SCIF: closing epd[0] %d failed: (%d) %s\n",
                    ep->amsh_qdir[i].amsh_epd[0],
                    errno, strerror(errno));
            return PSM_INTERNAL_ERR;
        }

	if(scif_close(ep->amsh_qdir[i].amsh_epd[1])) {
            _IPATH_INFO("SCIF: closing epd[1] %d failed: (%d) %s\n",
                    ep->amsh_qdir[i].amsh_epd[1],
                    errno, strerror(errno));
            return PSM_INTERNAL_ERR;
        }

        ep->amsh_qdir[i].amsh_epd[0] = 0;
        ep->amsh_qdir[i].amsh_epd[1] = 0;
    }

    /* The accept thread will detect that the listen socket has been closed
       and will shut down gracefully. */
    if(scif_close(ep->scif_epd)) {
        _IPATH_INFO("SCIF: closing listen epd %d failed: (%d) %s\n",
                ep->scif_epd,
                errno, strerror(errno));
        return PSM_INTERNAL_ERR;
    }

    pthread_join(ep->scif_thread, NULL);

    return PSM_OK;
}

#endif //PSM_HAVE_SCIF

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

    if (req->epid_mask == NULL) {
	psmi_free(req);
	return PSM_NO_MEMORY;
    }

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

#ifdef PSM_HAVE_SCIF
                psm_error_t err = amsh_scif_setup(ptl, req->epids[i]);
                if(err != PSM_OK) {
                    psmi_free(req->epid_mask);
                    psmi_free(req);
                    return err;
                }
#endif
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
#ifdef PSM_HAVE_SCIF
                if (shmidx < PTL_AMSH_MAX_LOCAL_PROCS) {  /* not remote nodes */
#endif
                    /* Make sure the target of the disconnect is still there */
                    pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
                    if (ptl->ep->amsh_dirpage->shmidx_map_epid[shmidx] != epaddr->epid) {
                        req->numep_left--;
                        req->epid_mask[i] = AMSH_CMASK_DONE;
                        AMSH_CSTATE_TO_SET(epaddr, NONE);
                    }
                    pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
#ifdef PSM_HAVE_SCIF
                }
#endif
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
            char buf[32];
            uint16_t their_verno;

            psmi_assert(req->numep_left > 0);
            /* Go through the list of peers we need to connect to and find out
             * if they each shared ep is mapped into shm */
            pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
            for (i = 0; i < req->numep; i++) {
                if (req->epid_mask[i] != AMSH_CMASK_PREREQ)
                    continue;
                epid = req->epids[i];
                epaddr = req->epaddr[i];

#if PSM_HAVE_SCIF
		/* Get the peer node-ID and scif port # from epid */
		int nodeid = (int)((epid>>48)&0xff);
		if (nodeid != ptl->ep->scif_mynodeid) {
                    int peeridx = (int)((epid>>56)&0xff);

                    //Don't use a loop, compute the shmidx directly.
                    if(nodeid < ptl->ep->scif_mynodeid) {
                        shmidx =
                            (nodeid + 1) * PTL_AMSH_MAX_LOCAL_PROCS + peeridx;
                    } else {
                        shmidx = nodeid * PTL_AMSH_MAX_LOCAL_PROCS + peeridx;
                    }

		    psmi_assert(shmidx >= PTL_AMSH_MAX_LOCAL_PROCS);
                    their_verno = ptl->ep->amsh_qdir[shmidx].amsh_verno;
		} else
#endif
                {
                    /* Go through mapped epids and find the epid we're looking for */
                    for (shmidx = -1, j = 0; j <=
                            ptl->ep->amsh_dirpage->max_idx; j++) {
                        /* epid is connected and ready to go */
	                if (ptl->ep->amsh_dirpage->shmidx_map_epid[j] == epid) {
                            shmidx = j;
	                    break;
                        }
                    }

                    if (shmidx == -1)  /* couldn't find epid, go to next */
                        continue;
                    their_verno = ptl->ep->amsh_dirpage->psm_verno[shmidx];
		}

                /* Before we even send the request out, check to see if
                 * versions are interoperable */
                if (!psmi_verno_isinteroperable(their_verno)) {
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
    struct ptl_connection_req *req = NULL;
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
        else if (err != PSM_OK_NO_PROGRESS) {
	    psmi_free(req->epid_mask);
	    psmi_free(req);
	    goto fail;
        } else if (shm_polite_attach && 
            ++num_polls_noprogress == CONNREQ_ZERO_POLLS_BEFORE_YIELD) {
            num_polls_noprogress = 0;
	    PSMI_PYIELD();
        }
    }
    while (psmi_cycles_left(t_start, timeout_ns));

    err = amsh_ep_connreq_fini(ptl, req);

    /* Ensure that both sides of all connections are established before
       returning. This prevents MPI-level deadlocks where one rank returns from
       here before responding to another ranks handshake and enters a barrier
       (which does not poll PSM).  That other rank stays in PSM, never
       receiving the handshake, and never entering the barrier: deadlock. */
    /* This is fixed by Intel MPI 5.0. */
#if 0
    if(op == PTL_OP_CONNECT) {
        while(ptl->connect_to > ptl->connect_from) {
            psmi_poll_internal(ptl->ep, 1);
        }
    } else { //ABORT or DISCONNECT
        while(ptl->connect_to < ptl->connect_from) {
            psmi_poll_internal(ptl->ep, 1);
        }
    }
#endif

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

/* am_ctl_getslot_remote_inner works just like am_ctl_getslot_pkt_inner, but
   instead of using the tail/lock in the shq, use a separate per-domain
   tail/lock.  The queue is actually located on a remote node, but tailinfo
   is located on the local node (and shared by peers on the same node) */
static
am_pkt_short_t*
am_ctl_getslot_pkt_inner(struct amsh_qtail_info* tailinfo,
                         volatile am_ctl_qhdr_t *shq,
                         am_pkt_short_t *pkt0)
{
    am_pkt_short_t* pkt;
    uint32_t idx;

    /* Acquire a slot/packet in the remote queue. */
    pthread_spin_lock(&tailinfo->lock);
    idx = tailinfo->tail;

    /* Careful here -- pkt is pointing to memory on a remote node, so any
       accesses will be expensive over PCIE. */
    pkt = (void*)((uintptr_t)pkt0 + idx * shq->elem_sz);
    if(pkt->flag == QFREE) {
        ips_sync_reads();
        pkt->flag = QUSED;

        tailinfo->tail += 1;
        if(tailinfo->tail == shq->elem_cnt) {
            tailinfo->tail = 0;
        }
    } else {
        pkt = NULL;
    }
    pthread_spin_unlock(&tailinfo->lock);

    return pkt;
}

/* AWF - leaving this code for now.  With the addition of SCIF/symmetric
   support, all communication uses the 'remote' path. */
#if 0
#undef CSWAP
/* AWF - cswap appears to be broken.. fix? */
PSMI_ALWAYS_INLINE(
int32_t 
cswap(volatile uint32_t *p, uint32_t old_value, uint32_t new_value))
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
        pkt = NULL;
    }
    pthread_spin_unlock(&shq->lock);
#else
    uint32_t idx_next;
    do {
        idx = shq->tail;
        idx_next = (idx+1 == shq->elem_cnt) ? 0 : idx+1;
    } while (cswap(&shq->tail, idx, idx_next) != idx);

    pkt = (am_pkt_short_t *)((uintptr_t) pkt0 + idx * shq->elem_sz);
    //AWF - why is another cswap needed here? we already have the packet..
    //We'll wait until the packet goes from QUSED -> QFREE
    // And as soon as it does, toggle it back to QUSED.
    while (cswap(&pkt->flag, QFREE, QUSED) !=  QFREE)
        ;
#endif
    return pkt;
}
#endif

/* This is safe because 'flag' is at the same offset on both pkt and bulkpkt */
#define am_ctl_getslot_bulkpkt_inner(shq,pkt0) ((am_pkt_bulk_t *) \
            am_ctl_getslot_pkt_inner(shq,(am_pkt_short_t *)(pkt0)))

PSMI_ALWAYS_INLINE(
am_pkt_short_t *
am_ctl_getslot_pkt(ptl_t *ptl, int shmidx, int is_reply)
)
{
    struct amsh_qtail_info* tailinfo;
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_short_t  *pkt0;

        /* It's not obvious, but the packet acquisition code below is accessing
           memory mapped remotely from a peer on another SCIF node. Thus we
           have to make sure a SCIF connection to that peer is already
           established. */
#ifdef PSM_HAVE_SCIF
        if(shmidx >= PTL_AMSH_MAX_LOCAL_PROCS &&
                ptl->ep->amsh_qdir[shmidx].amsh_epd[0] == 0) {
            if(amsh_scif_setup(ptl, ptl->ep->amsh_qdir[shmidx].amsh_epid)
                    != PSM_OK) {
                psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
                        "am_ctl_getslot_remote(): amsh_scif_setup failed");
            }
        }
#endif

        if(!is_reply) {
            tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].reqFifoShort;
            shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->shortq);
            pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoShort;
        } else {
            tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].repFifoShort;
            shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->shortq);
            pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoShort;
        }

        return am_ctl_getslot_pkt_inner(tailinfo, shq, pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_med(ptl_t *ptl, int shmidx, int is_reply)
)
{
    struct amsh_qtail_info* tailinfo;
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;

    if(!is_reply) {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].reqFifoMed;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->medbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoMed; 
    } else {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].repFifoMed;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->medbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoMed; 
    }

    return (am_pkt_bulk_t*)am_ctl_getslot_pkt_inner(tailinfo,
            shq, (am_pkt_short_t*)pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_long(ptl_t *ptl, int shmidx, int is_reply)
)
{
    struct amsh_qtail_info* tailinfo;
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;

    if(!is_reply) {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].reqFifoLong;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->longbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoLong; 
    } else {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].repFifoLong;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->longbulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoLong; 
    }

    return (am_pkt_bulk_t*)am_ctl_getslot_pkt_inner(tailinfo,
            shq, (am_pkt_short_t*)pkt0);
}

PSMI_ALWAYS_INLINE(
am_pkt_bulk_t *
am_ctl_getslot_huge(ptl_t *ptl, int shmidx, int is_reply)
)
{
    struct amsh_qtail_info* tailinfo;
    volatile am_ctl_qhdr_t   *shq;
    am_pkt_bulk_t  *pkt0;

    if(!is_reply) {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].reqFifoHuge;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qreqH->hugebulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qreqFifoHuge; 
    } else {
        tailinfo = &ptl->ep->amsh_dirpage->qtails[shmidx].repFifoHuge;
        shq  = &(ptl->ep->amsh_qdir[shmidx].qrepH->hugebulkq);
        pkt0 = ptl->ep->amsh_qdir[shmidx].qrepFifoHuge; 
    }

    return (am_pkt_bulk_t*)am_ctl_getslot_pkt_inner(tailinfo,
            shq, (am_pkt_short_t*)pkt0);
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
 * AWF this trick won't work across nodes, since the receiver doesn't have
 * access to the tail value.
 */

PSMI_ALWAYS_INLINE(
psm_error_t
amsh_poll_internal_inner(ptl_t *ptl, int replyonly, int is_internal))
{
    psm_error_t err = PSM_OK_NO_PROGRESS;

    /* poll replies */
#ifdef PSM_HAVE_SCIF
    int node;
    int nnodes = ptl->ep->scif_nnodes;

    for(node = 0; node < nnodes; node++) {
        if (!QISEMPTY(ptl->repH[node].head->flag)) {
            do {
                ips_sync_reads();
                process_packet(ptl, (am_pkt_short_t *) ptl->repH[node].head, 0);
                advance_head(&ptl->repH[node]);
                err = PSM_OK;
            } while (!QISEMPTY(ptl->repH[node].head->flag));
        }
    }
#else
    if (!QISEMPTY(ptl->repH[0].head->flag)) {
        do {
            ips_sync_reads();
            process_packet(ptl, (am_pkt_short_t *) ptl->repH[0].head, 0);
            advance_head(&ptl->repH[0]);
            err = PSM_OK;
        } while (!QISEMPTY(ptl->repH[0].head->flag));
    }
#endif

    if (!replyonly) {
    /* Request queue not enable for 2.0, will be re-enabled to support long
     * replies */
        if (!is_internal && ptl->psmi_am_reqq_fifo.first != NULL) {
            psmi_am_reqq_drain(ptl);
            err = PSM_OK;
        }

#ifdef PSM_HAVE_SCIF
        for(node = 0; node < nnodes; node++) {
            if (!QISEMPTY(ptl->reqH[node].head->flag)) {
                do {
                    ips_sync_reads();
                    process_packet(ptl,
                            (am_pkt_short_t *) ptl->reqH[node].head, 1);
                    advance_head(&ptl->reqH[node]);
                    err = PSM_OK;
                } while (!QISEMPTY(ptl->reqH[node].head->flag));
            }
        }
#else
        if (!QISEMPTY(ptl->reqH[0].head->flag)) {
            do {
                ips_sync_reads();
                process_packet(ptl,
                        (am_pkt_short_t *) ptl->reqH[0].head, 1);
                advance_head(&ptl->reqH[0]);
                err = PSM_OK;
            } while (!QISEMPTY(ptl->reqH[0].head->flag));
        }
#endif
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

#ifdef __MIC__
    /* On MIC, a local copy of the packet struct should be filled in, then
       copied using one vector operation.  MIC does not have write combining,
       and the acquired packet is in remote (via PCIE) memory, so filling in
       each struct member will cause a separate PCIE transaction. Using a
       single vector write reduces latency. */
    am_pkt_short_t lcl_pkt; /* Local version of packet data */

    lcl_pkt.bulkidx = bulkidx;
    lcl_pkt.shmidx = ptl->ep->amsh_qdir[destidx].amsh_shmidx;
    lcl_pkt.type  = fmt;
    lcl_pkt.nargs = nargs;
    lcl_pkt.handleridx = handleridx;

    for (i = 0; i < nargs; i++)
        lcl_pkt.args[i] = args[i];

    if (fmt == AMFMT_SHORT_INLINE)
        mq_copy_tiny((uint32_t *) &lcl_pkt.args[nargs], (uint32_t *) src, len);

    /* Skip the memory fences in QMARKREADY; not necessary here. */
    //QMARKREADY(lcl_pkt);
    lcl_pkt.flag = QREADY;

    /* Now copy the local packet data to the remote packet. */
    memcpy((void*)pkt, &lcl_pkt, sizeof(am_pkt_short_t));

#else
    /* got a free pkt... fill it in */
    pkt->bulkidx = bulkidx;
    pkt->shmidx = ptl->ep->amsh_qdir[destidx].amsh_shmidx;
    pkt->type  = fmt;
    pkt->nargs = nargs;
    pkt->handleridx = handleridx;

    for (i = 0; i < nargs; i++)
        pkt->args[i] = args[i];

    if (fmt == AMFMT_SHORT_INLINE) 
        mq_copy_tiny((uint32_t *) &pkt->args[nargs], (uint32_t *) src, len);

    QMARKREADY(pkt);
#endif
}

/* It's probably unlikely that the alloca below is problematic, but
 * in case we think it is, define the next to 1
 */
#define ALLOCA_AS_SCRATCH 0

#if ALLOCA_AS_SCRATCH
static char amsh_medscratch[AMMED_SZ];
#endif

#ifdef __MIC__
#define amsh_shm_copy_short memcpy
#define amsh_shm_copy_long  memcpy
#define amsh_shm_copy_huge  psmi_memcpyo
#else
#define amsh_shm_copy_short psmi_mq_mtucpy
#define amsh_shm_copy_long  psmi_mq_mtucpy
#define amsh_shm_copy_huge  psmi_memcpyo
#endif

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

    tok.tok.epaddr_from = ptl->ep->amsh_qdir[shmidx].amsh_epaddr;
    tok.ptl = ptl;
    tok.mq = ptl->ep->mq;
    tok.shmidx = shmidx;

    uint16_t hidx = (uint16_t) pkt->handleridx;
    int myshmidx = ptl->shmidx;
    int shmidx_l = AMSH_BULK_PUSH ? myshmidx : shmidx;
    uint32_t bulkidx = pkt->bulkidx;
    uintptr_t bulkptr;
    am_pkt_bulk_t *bulkpkt;

    /* It is possible for packets to arrive (the initial ones for connection
       establishment) before amsh_epid is set correctly.  However this can only
       happen for peers in the same node -- those connecting inter-node via
       SCIF will always have their epid set first.  Since our local nodeid is
       encoded in the amsh_epid of all local proces at initialization time,
       it can always be safely extracted here, even before the amsh_epid is
       set to its proper value for a given peer. */
#ifdef PSM_HAVE_SCIF
    int nodeid = (int)((ptl->ep->amsh_qdir[shmidx].amsh_epid >> 48) & 0xff);
#else
    const int nodeid = 0;
#endif

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
                    bulkptr = (uintptr_t)
                        ptl->ep->amsh_qdir[myshmidx].qptrs[nodeid].qreqFifoMed;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoMed;
                } else {
                    bulkptr = (uintptr_t)
                        ptl->ep->amsh_qdir[myshmidx].qptrs[nodeid].qrepFifoMed;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoMed;
                }
                break;

            case AMFMT_LONG_END:
                isend = 1;
            case AMFMT_LONG:
                if (isreq) {
                    bulkptr = (uintptr_t)
                        ptl->ep->amsh_qdir[shmidx_l].qptrs[nodeid].qreqFifoLong;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoLong;
                }
                else {
                    bulkptr = (uintptr_t)
                        ptl->ep->amsh_qdir[shmidx_l].qptrs[nodeid].qrepFifoLong;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoLong;
                }
                break;

            case AMFMT_HUGE_END:
                isend = 1;
            case AMFMT_HUGE:
                if (isreq) {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qptrs[nodeid].qreqFifoHuge;
                    bulkptr += bulkidx * amsh_qelemsz.qreqFifoHuge;
                }
                else {
                    bulkptr = (uintptr_t) ptl->ep->amsh_qdir[shmidx_l].qptrs[nodeid].qrepFifoHuge;
                    bulkptr += bulkidx * amsh_qelemsz.qrepFifoHuge;
                }
                break;
            default:
                bulkptr = 0;
                psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
                    "Unknown/unhandled packet type 0x%x", pkt->type);
		return;
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
    psm_amarg_t args[5] = {};
    psm_error_t err = PSM_OK;

    args[0].u32w0 = MQ_MSG_RTS;
    args[0].u32w1 = len;
    args[1].u64w0 = tag;
    args[2].u64w0 = (uint64_t)(uintptr_t) req;
    args[3].u64w0 = (uint64_t)(uintptr_t) buf;

    /* OK so we want to use SCIF DMA here if enabled.
       First check: same node?  Use existing local path.
    */

#ifdef PSM_HAVE_SCIF
    int shmidx = epaddr->_shmidx;
    if(shmidx < PTL_AMSH_MAX_LOCAL_PROCS) {
#endif
        /* Intra-node: consider using kassist methods */
        if (ptl->ep->psmi_kassist_mode == PSMI_KASSIST_KNEM_GET)
            /* If KNEM Get is active register region for peer to get from */
            args[4].u64w0 = knem_register_region((void*) buf, len, PSMI_FALSE);
        else
            args[4].u64w0 = 0;
#ifdef PSM_HAVE_SCIF
    } else {
        /* Inter-node: use SCIF DMA */
        if(ptl->ep->scif_dma_mode == PSMI_SCIF_DMA_GET &&
                ptl->ep->scif_dma_threshold <= len) {
            /* Register the memory region with SCIF and pass the offset over. */
            off_t offset;

            scif_epd_t epd = epaddr->ep->amsh_qdir[shmidx].amsh_epd[0];

            err = scif_register_region(epd, (void*)buf, len, &offset);
            if(err != PSM_OK) {
                return err;
            }

            args[4].u64w0 = offset;
        } else {
            args[4].u64w0 = 0;
        }
    }
#endif
    
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
    psm_amarg_t args[3] = {};
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

#ifdef PSM_HAVE_SCIF
static int
psmi_get_scif_dma_mode()
{
    int mode = PSMI_SCIF_DMA_MODE_DEFAULT;
    union psmi_envvar_val env_scif_dma;

    if(!psmi_getenv("PSM_SCIF_DMA_MODE",
                "PSM Shared memory SCIF DMA transport mode "
                "(scif-put, scif-get, none)",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_STR,
                (union psmi_envvar_val) PSMI_SCIF_DMA_MODE_DEFAULT_STRING,
                &env_scif_dma))
    {
        char *s = env_scif_dma.e_str;
        if (strcasecmp(s, "scif-put") == 0)
            mode = PSMI_SCIF_DMA_PUT;
        else if (strcasecmp(s, "scif-get") == 0)
            mode = PSMI_SCIF_DMA_GET;
        else
            mode = PSMI_SCIF_DMA_OFF;
    }

    return mode;
}

static int
psmi_get_scif_dma_threshold()
{
    int threshold = PSMI_MQ_RV_THRESH_SCIF_DMA;
    union psmi_envvar_val env_scif_dma;

    if(!psmi_getenv("PSM_SCIF_DMA_THRESH",
                "PSM SCIF DMA (rendezvous) switchover",
                PSMI_ENVVAR_LEVEL_USER, PSMI_ENVVAR_TYPE_UINT,
                (union psmi_envvar_val) threshold,
                &env_scif_dma)) {
        threshold = env_scif_dma.e_uint;
    }

    return threshold;
}

static
const char *
psmi_scif_dma_getmode(int mode)
{
    switch (mode) {
        case PSMI_SCIF_DMA_OFF:
	    return "SCIF DMA off";
	case PSMI_SCIF_DMA_PUT:
	    return "SCIF put";
	case PSMI_SCIF_DMA_GET:
	    return "SCIF get";
	default:
	    return "unknown";
    }
}
#endif // PSM_HAVE_SCIF

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
                /* This can be nasty.  If the segment moves as a result of
                 * adding a new peer, we have to fix the input pointer 'args'
                 * since it comes from a shared memory location */
                if ((err = amsh_epaddr_add(ptl, epid, shmidx, &epaddr)))
                    /* Unfortunately, no way out of here yet */
                    psmi_handle_error(PSMI_EP_NORETURN, err, "Fatal error "
		     "in connecting to shm segment"); 
                psmi_assert(psmi_epid_lookup(ptl->ep, epid) != NULL);
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
            epaddr = ptl->ep->amsh_qdir[shmidx].amsh_epaddr;
            *perr = err;
            AMSH_CSTATE_TO_SET(epaddr, REPLIED);
            ptl->connect_to++;
            break;

        case PSMI_AM_DISC_REQ: 
            epaddr = tok->tok.epaddr_from;
            args[0].u32w0 = PSMI_AM_DISC_REP;
            args[2].u32w1 = PSM_OK;
            AMSH_CSTATE_FROM_SET(epaddr, DISC_REQ);
            ptl->connect_from--;
            /* Before sending the reply, make sure the process
             * is still connected */

	    is_valid = 1;
#ifdef PSM_HAVE_SCIF
            if (shmidx < PTL_AMSH_MAX_LOCAL_PROCS) {
#endif
                pthread_mutex_lock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
                if (ptl->ep->amsh_dirpage->shmidx_map_epid[shmidx] != epaddr->epid)
                    is_valid = 0;
                pthread_mutex_unlock((pthread_mutex_t *) &(ptl->ep->amsh_dirpage->lock));
#ifdef PSM_HAVE_SCIF
            }
#endif

            if (is_valid) {
                psmi_amsh_short_reply(tok, amsh_conn_handler_hidx, 
                                  args, narg, NULL, 0, 0);
	    }
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
    int shmidx;
    psm_error_t err = PSM_OK;

    _IPATH_VDBG("PSM Symmetric Mode!\n");
    /* Preconditions */
    psmi_assert_always(ep != NULL);
    psmi_assert_always(ep->epaddr != NULL);
    psmi_assert_always(ep->epid != 0);

    /* Setup scif listen port and query node information */
    /* This is important to get the node count for initializing queues */
#ifdef PSM_HAVE_SCIF
    if ((err = amsh_scif_init(ep)))
	goto fail;
#endif

    /* If we haven't attached to the segment yet, do it now */
    if ((err = psmi_shm_attach(ep, &shmidx)))
	goto fail;

    /* Modify epid with acquired info as below */
    ep->epid |= ((((uint64_t)shmidx)&0xFF)<<56);

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

#ifdef PSM_HAVE_SCIF
    /* Start a thread to service incoming SCIF connections. */
    if (pthread_create(&ptl->ep->scif_thread, NULL,
                am_ctl_accept_thread, (void*)ptl)) {
	err = psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                "amsh_init_segment(): pthread_create() failed: %d %s",
                errno, strerror(errno));
	goto fail;
    }
#endif

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
	    if (epaddr_array) psmi_free(epaddr_array);
	    if (errs) psmi_free(errs);
	    if (mask) psmi_free(mask);
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

    //At this point we are never getting a disconnect request from two peers.
    //Those peers are polling.. waiting for a response?
    //Are we somehow losing a message that arrives somewhere between where we
    //start to disconnect, and here?

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
    else {
        _IPATH_VDBG("CCC complete disconnect from=%d,to=%d\n", 
                ptl->connect_from,
                ptl->connect_to);
    }

    if ((err_seg = psmi_shm_detach(ptl->ep))) {
        err = err_seg;
        goto fail;
    }

    /* This prevents poll calls between now and the point where the endpoint is
     * deallocated to reference memory that disappeared */
#ifdef PSM_HAVE_SCIF
    for(i = 0; i < ptl->ep->scif_nnodes; i++) {
        ptl->repH[i].head  = &ptl->amsh_empty_shortpkt;
        ptl->reqH[i].head  = &ptl->amsh_empty_shortpkt;
    }
#else
    ptl->repH[0].head  = &ptl->amsh_empty_shortpkt;
    ptl->reqH[0].head  = &ptl->amsh_empty_shortpkt;
#endif

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

#ifdef PSM_HAVE_SCIF
/* Wait for incoming connections on the SCIF listen socket.
   When a connection arrives, store the SCIF socket in the correct place and
   respond so that the remote process can map our shared queue area.
 */
static void* am_ctl_accept_thread(void* arg)
{
    ptl_t* ptl = (ptl_t*)arg;
    psm_ep_t ep = ptl->ep;
    struct scif_portID peer;
    scif_epd_t epd;
    void* addr;
    int peeridx;
    int shmidx;
    int nodeid;

    /* Receive this struct to ID the peer (offset unused). */
    /* Send this struct to share memory mapping information. */
    struct { off_t offset; int verno; psm_epid_t epid; } inbuf, outbuf;

    while(1) {
        /* Block on accepting a new connection on the SCIF listen socket. */
        if(scif_accept(ep->scif_epd, &peer, &epd, SCIF_ACCEPT_SYNC)) {
            if(errno == EINTR) {
                /* Time to quit! */
                _IPATH_VDBG("SCIF accept thread quitting\n");
                pthread_exit(NULL);
                return NULL;
            }

	    psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,
                    "scif_accept failed: %d %s\n", errno, strerror(errno));
            continue;
        }

        /* Register the shared memory area this peer should access. */
        /* SCIF_MAP_FIXED is use to ensure that offset == addr, so that the
           returned offset does not need to be tracked as well. */
        addr = ep->amsh_qdir[ep->amsh_shmidx].amsh_base;
        outbuf.offset = scif_register(epd, addr,
                am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES,
                (off_t)addr, SCIF_PROT_READ|SCIF_PROT_WRITE, SCIF_MAP_FIXED);

        _IPATH_PRDBG("registered addr %p at offset %p length %ld\n",
                addr, (void*)outbuf.offset,
                am_ctl_sizeof_block() * PTL_AMSH_MAX_LOCAL_NODES);
        if(outbuf.offset == SCIF_REGISTER_FAILED) {
            psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                    "scif_register failed: %d %s\n", errno, strerror(errno));
            scif_close(epd);
            continue;
        }

        outbuf.verno = PSMI_VERNO;
        outbuf.epid = ep->epid;

        if (amsh_scif_send(epd, &outbuf, sizeof(outbuf))) {
            psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                    "scif_send epd %d failed: %d %s\n",
                    epd, errno, strerror(errno));
            scif_close(epd);
            continue;
        }

        /* Receive peer identification information */
        if(amsh_scif_recv(epd, &inbuf, sizeof(inbuf))) {
            psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                    "scif_recv failed: %d %s\n", errno, strerror(errno));
            scif_close(epd);
            continue;
        }

        /* Extract information from the peer's epid. */
        nodeid = (int)((inbuf.epid>>48)&0xff);
        shmidx = (int)((inbuf.epid>>56)&0xff);

        /* Port isn't supposed to match -- we have the peer's listen port,
           which won't be the same as the connect socket's port. */
        if(peer.node != nodeid) {
            psmi_handle_error(NULL, PSM_EP_NO_RESOURCES,
                    "SCIF node:port %d:%d does not match encoded epid nodeid %d",
                    peer.node, peer.port, nodeid);
            scif_close(epd);
            continue;
        }

        /* Now that the peer's identity is known, store the new connection. */
        /* 0        1 mynodeid 3 4 */
        /* mynodeid 0 1        3 4 */
        if(nodeid > ep->scif_mynodeid) {
            peeridx = (PTL_AMSH_MAX_LOCAL_PROCS * nodeid) + shmidx;
        } else if(nodeid < ep->scif_mynodeid) {
            peeridx = (PTL_AMSH_MAX_LOCAL_PROCS * (nodeid + 1)) + shmidx;
        } else {
            peeridx = shmidx;
        }

        ptl->ep->amsh_qdir[peeridx].amsh_epid = inbuf.epid;
        ptl->ep->amsh_qdir[peeridx].amsh_verno = inbuf.verno;

        /* There are eventually two connections.  epd[0] always has the remote
           memory mapped region associated with it, and is used to make requests
           to that peer.  epd[1] exposes our local shared memory, and is used
           to respond to remote requests. */
        ptl->ep->amsh_qdir[peeridx].amsh_epd[1] = epd;

        _IPATH_VDBG(
                "shmidx %d accepted %d:%d peeridx %d epd %d shmidx %d\n",
                ep->amsh_shmidx, peer.node, peer.port, peeridx,
                ep->amsh_qdir[peeridx].amsh_epd[1],
                ep->amsh_qdir[peeridx].amsh_shmidx);
    }

    return NULL;
}
#endif //PSM_HAVE_SCIF

