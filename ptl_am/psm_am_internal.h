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

#ifndef PSMI_AM_H
#define PSMI_AM_H

#include "../psm_am_internal.h"

#define NSHORT_ARGS 6
typedef
struct amsh_am_token 
{
  struct psmi_am_token tok;
  
  
  ptl_t	    *ptl; /**> What PTL was it received on */
  psm_mq_t	    mq;   /**> What matched queue is this for ? */
  int		    shmidx; /**> what shmidx sent this */
  int loopback;	  /**> Whether to reply as loopback */
}
amsh_am_token_t;

typedef void (*psmi_handler_fn_t)(void *token, psm_amarg_t *args, int nargs, void *src, size_t len);

typedef struct psmi_handlertab {
    psmi_handler_fn_t  fn;
} psmi_handlertab_t;

/*
 * Can change the rendezvous threshold based on usage of kcopy (or not)
 */
#define PSMI_MQ_RV_THRESH_KCOPY	   16000

/*
 * Can change the rendezvous threshold based on usage of knem (or not)
 */
#define PSMI_MQ_RV_THRESH_KNEM      16000

/* If no kernel assisted copy is available this is the rendezvous threshold */
#define PSMI_MQ_RV_THRESH_NO_KASSIST 16000

/* Threshold for using SCIF DMA to do data transfers */
#define PSMI_MQ_RV_THRESH_SCIF_DMA  (150000)

#define PSMI_AM_CONN_REQ    1
#define PSMI_AM_CONN_REP    2
#define PSMI_AM_DISC_REQ    3
#define PSMI_AM_DISC_REP    4

#define PSMI_KASSIST_OFF       0x0
#define PSMI_KASSIST_KCOPY_GET 0x1
#define PSMI_KASSIST_KCOPY_PUT 0x2
#define PSMI_KASSIST_KNEM_GET  0x4
#define PSMI_KASSIST_KNEM_PUT  0x8

#define PSMI_KASSIST_KCOPY     0x3
#define PSMI_KASSIST_KNEM      0xC
#define PSMI_KASSIST_GET       0x15
#define PSMI_KASSIST_PUT       0x2A
#define PSMI_KASSIST_MASK      0x3F

#define PSMI_KASSIST_MODE_DEFAULT PSMI_KASSIST_KNEM_PUT
#define PSMI_KASSIST_MODE_DEFAULT_STRING  "knem-put"

int psmi_epaddr_kcopy_pid(psm_epaddr_t epaddr);

#define PSMI_SCIF_DMA_OFF   0x0
#define PSMI_SCIF_DMA_GET   0x1
#define PSMI_SCIF_DMA_PUT   0x2

#define PSMI_SCIF_DMA_MODE_DEFAULT PSMI_SCIF_DMA_GET
#define PSMI_SCIF_DMA_MODE_DEFAULT_STRING  "scif-get"

/*
 * Eventually, we will allow users to register handlers as "don't reply", which
 * may save on some of the buffering requirements
 */
#define PSMI_HANDLER_NEEDS_REPLY(handler)    1
#define PSMI_VALIDATE_REPLY(handler)    assert(PSMI_HANDLER_NEEDS_REPLY(handler))

int psmi_amsh_poll(ptl_t *ptl, int replyonly);

/* Shared memory AM, forward decls */
int
psmi_amsh_short_request(ptl_t *ptl, psm_epaddr_t epaddr,
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
		        const void *src, size_t len, int flags);

void
psmi_amsh_short_reply(amsh_am_token_t *tok,
                      psm_handler_t handler, psm_amarg_t *args, int nargs,
		      const void *src, size_t len, int flags);

int
psmi_amsh_long_request(ptl_t *ptl, psm_epaddr_t epaddr,
                        psm_handler_t handler, psm_amarg_t *args, int nargs,
		        const void *src, size_t len, void *dest, int flags);

void
psmi_amsh_long_reply(amsh_am_token_t *tok,
                     psm_handler_t handler, psm_amarg_t *args, int nargs,
		     const void *src, size_t len, void *dest, int flags);

void psmi_am_mq_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);

void psmi_am_mq_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);
void psmi_am_mq_handler_data(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);
void psmi_am_mq_handler_complete(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);
void psmi_am_mq_handler_rtsmatch(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);
void psmi_am_mq_handler_rtsdone(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);
void psmi_am_handler(void *toki, psm_amarg_t *args, int narg, void *buf, size_t len);

/* AM over shared memory (forward decls) */
psm_error_t
psmi_amsh_am_short_request(psm_epaddr_t epaddr,
			   psm_handler_t handler, psm_amarg_t *args, int nargs,
			   void *src, size_t len, int flags,
			   psm_am_completion_fn_t completion_fn,
			   void *completion_ctxt);
psm_error_t
psmi_amsh_am_short_reply(psm_am_token_t tok,
			 psm_handler_t handler, psm_amarg_t *args, int nargs,
			 void *src, size_t len, int flags,
			 psm_am_completion_fn_t completion_fn,
			 void *completion_ctxt);

#define amsh_conn_handler_hidx	 1
#define mq_handler_hidx          2
#define mq_handler_data_hidx     3
#define mq_handler_rtsmatch_hidx 4
#define mq_handler_rtsdone_hidx  5
#define am_handler_hidx          6

#define AMREQUEST_SHORT 0
#define AMREQUEST_LONG  1
#define AMREPLY_SHORT   2
#define AMREPLY_LONG    3
#define AM_IS_REPLY(x)     ((x)&0x2)
#define AM_IS_REQUEST(x)   (!AM_IS_REPLY(x))
#define AM_IS_LONG(x)      ((x)&0x1)
#define AM_IS_SHORT(x)     (!AM_IS_LONG(x))

#define AM_FLAG_SRC_ASYNC   0x1
#define AM_FLAG_SRC_TEMP    0x2

/*
 * Request Fifo.
 */
typedef
struct am_reqq {
    struct am_reqq  *next;
    int             amtype;

    ptl_t	    *ptl;
    psm_epaddr_t    epaddr;
    psm_handler_t   handler;
    psm_amarg_t     args[8];
    int             nargs;
    void            *src;
    uint32_t        len;
    void            *dest;
    int             amflags;
    int             flags;
}
am_reqq_t;

struct am_reqq_fifo_t {
    am_reqq_t  *first;
    am_reqq_t  **lastp;
};

psm_error_t psmi_am_reqq_drain(ptl_t *ptl);
void psmi_am_reqq_add(int amtype, ptl_t *ptl, psm_epaddr_t epaddr,
                 psm_handler_t handler, psm_amarg_t *args, int nargs,
		 void *src, size_t len, void *dest, int flags);

/*
 * Shared memory Active Messages, implementation derived from
 * Lumetta, Mainwaring, Culler.  Multi-Protocol Active Messages on a Cluster of
 * SMP's. Supercomputing 1997.
 *
 * We support multiple endpoints in shared memory, but we only support one
 * shared memory context with up to AMSH_MAX_LOCAL_PROCS local endpoints. Some
 * structures are endpoint specific (as denoted * with amsh_ep_) and others are
 * specific to the single shared memory context * (amsh_ global variables). 
 *
 * Each endpoint maintains a shared request block and a shared reply block.
 * Each block is composed of queues for small, medium and large messages.
 */

#define QFREE      0
#define QUSED      1
#define QREADY     2
#define QREADYMED  3
#define QREADYLONG 4

#define QISEMPTY(flag) (flag<QREADY)
#ifdef __powerpc__
#  define _QMARK_FLAG_FENCE()  asm volatile("lwsync" : : : "memory")
#elif defined(__x86_64__) || defined(__i386__)
#ifdef __MIC__
#  define _QMARK_FLAG_FENCE()  asm volatile("lock; addl $0,0(%%rsp)" ::: "memory");
#else
#  define _QMARK_FLAG_FENCE()  asm volatile("sfence" : : : "memory");
//#  define _QMARK_FLAG_FENCE()  asm volatile("" : : : "memory")  /* compilerfence */
#endif
#else
#  error No _QMARK_FLAG_FENCE() defined for this platform
#endif

#define _QMARK_FLAG(pkt_ptr, _flag)      do {    \
        _QMARK_FLAG_FENCE();                     \
        (pkt_ptr)->flag = (_flag);               \
        _QMARK_FLAG_FENCE();                     \
        } while (0)

#define QMARKFREE(pkt_ptr)  _QMARK_FLAG(pkt_ptr, QFREE)
#define QMARKREADY(pkt_ptr) _QMARK_FLAG(pkt_ptr, QREADY)
#define QMARKUSED(pkt_ptr)  _QMARK_FLAG(pkt_ptr, QUSED)

#define AMFMT_SYSTEM       1
#define AMFMT_SHORT_INLINE 2
#define AMFMT_SHORT        3
#define AMFMT_LONG         4
#define AMFMT_LONG_END     5
#define AMFMT_HUGE         6
#define AMFMT_HUGE_END     7

#define _shmidx _ptladdr_u32[0]
#define _cstate _ptladdr_u32[1]

#define AMSH_CMASK_NONE    0
#define AMSH_CMASK_PREREQ  1
#define AMSH_CMASK_POSTREQ 2
#define AMSH_CMASK_DONE    3

#define AMSH_CSTATE_TO_MASK         0x0f
#define AMSH_CSTATE_TO_NONE         0x01
#define AMSH_CSTATE_TO_REPLIED      0x02
#define AMSH_CSTATE_TO_ESTABLISHED  0x03
#define AMSH_CSTATE_TO_DISC_REPLIED 0x04
#define AMSH_CSTATE_TO_GET(epaddr)  ((epaddr)->_cstate & AMSH_CSTATE_TO_MASK)
#define AMSH_CSTATE_TO_SET(epaddr,state)                                      \
            (epaddr)->_cstate = (((epaddr)->_cstate & ~AMSH_CSTATE_TO_MASK) | \
                            ((AMSH_CSTATE_TO_ ## state) & AMSH_CSTATE_TO_MASK))

#define AMSH_CSTATE_FROM_MASK         0xf0
#define AMSH_CSTATE_FROM_NONE         0x10
#define AMSH_CSTATE_FROM_DISC_REQ     0x40
#define AMSH_CSTATE_FROM_ESTABLISHED  0x50
#define AMSH_CSTATE_FROM_GET(epaddr)  ((epaddr)->_cstate & AMSH_CSTATE_FROM_MASK)
#define AMSH_CSTATE_FROM_SET(epaddr,state)                                      \
            (epaddr)->_cstate = (((epaddr)->_cstate & ~AMSH_CSTATE_FROM_MASK) | \
                           ((AMSH_CSTATE_FROM_ ## state) & AMSH_CSTATE_FROM_MASK))

/**********************************
 * Shared memory packet formats 
 **********************************/
typedef 
struct am_pkt_short {
    uint32_t        flag;     /**> Packet state */
    union {
        uint32_t        bulkidx;  /**> index in bulk packet queue */
        uint32_t        length;   /**> length when no bulkidx used */
    };
    uint16_t        shmidx;   /**> index in shared segment */
    uint16_t        type;
    uint16_t        nargs;
    uint16_t        handleridx;

    psm_amarg_t	    args[NSHORT_ARGS];	/* AM arguments */

    /* We eventually will expose up to 8 arguments, but this isn't implemented
     * For now.  >6 args will probably require a medium instead of a short */
}
am_pkt_short_t PSMI_CACHEALIGN;
PSMI_STRICT_SIZE_DECL(am_pkt_short_t,64);

typedef struct am_pkt_bulk {
    uint32_t    flag;
    uint32_t    idx;
    uintptr_t   dest;       /* Destination pointer in "longs" */
    uint32_t    dest_off;   /* Destination pointer offset */
    uint32_t    len;   /* Destination length within offset */
    psm_amarg_t	args[2];    /* Additional "spillover" for >6 args */
    uint8_t	payload[0];
}
am_pkt_bulk_t;
/* No strict size decl, used for mediums and longs */

/****************************************************
 * Shared memory header and block control structures
 ***************************************************/

/* Each pkt queue has the same header format, although the queue
 * consumers don't use the 'head' index in the same manner. */
typedef struct am_ctl_qhdr {
    uint32_t    head;		/* Touched only by 1 consumer */
    uint8_t	_pad0[64-4];

    /* tail is now located on the dirpage. */
    uint32_t    elem_cnt;
    uint32_t    elem_sz;
    uint8_t     _pad1[64-2*sizeof(uint32_t)];
}
am_ctl_qhdr_t;
PSMI_STRICT_SIZE_DECL(am_ctl_qhdr_t,128);

/* Each block reserves some space at the beginning to store auxiliary data */
#define AMSH_BLOCK_HEADER_SIZE  4096

/* Each process has a reply qhdr and a request qhdr */
typedef struct am_ctl_blockhdr {
    volatile am_ctl_qhdr_t    shortq;
    volatile am_ctl_qhdr_t    medbulkq;
    volatile am_ctl_qhdr_t    longbulkq;
    volatile am_ctl_qhdr_t    hugebulkq;
}
am_ctl_blockhdr_t;
PSMI_STRICT_SIZE_DECL(am_ctl_blockhdr_t,128*3);

/* We cache the "shorts" because that's what we poll on in the critical path.
 * We take care to always update these pointers whenever the segment is remapped.
 */ 
typedef struct am_ctl_qshort_cache {
    volatile am_pkt_short_t  *base;  
    volatile am_pkt_short_t  *head;
    volatile am_pkt_short_t  *end;
}
am_ctl_qshort_cache_t;

struct amsh_qptrs {
    am_ctl_blockhdr_t	*qreqH;
    am_pkt_short_t	*qreqFifoShort;
    am_pkt_bulk_t  	*qreqFifoMed;
    am_pkt_bulk_t  	*qreqFifoLong;
    am_pkt_bulk_t  	*qreqFifoHuge;

    am_ctl_blockhdr_t	*qrepH;
    am_pkt_short_t	*qrepFifoShort;
    am_pkt_bulk_t  	*qrepFifoMed;
    am_pkt_bulk_t  	*qrepFifoLong;
    am_pkt_bulk_t  	*qrepFifoHuge;
};

/******************************************
 * Shared segment local directory (global)
 ******************************************
 *
 * Each process keeps a directory for where request and reply structures are 
 * located at its peers.
 */
struct amsh_qdirectory {
    /* These pointers are convenience aliases for the local node queues
       also found in the qptrs array. */
    am_ctl_blockhdr_t	*qreqH;
    am_pkt_short_t	*qreqFifoShort;
    am_pkt_bulk_t  	*qreqFifoMed;
    am_pkt_bulk_t  	*qreqFifoLong;
    am_pkt_bulk_t  	*qreqFifoHuge;

    am_ctl_blockhdr_t	*qrepH;
    am_pkt_short_t	*qrepFifoShort;
    am_pkt_bulk_t  	*qrepFifoMed;
    am_pkt_bulk_t  	*qrepFifoLong;
    am_pkt_bulk_t  	*qrepFifoHuge;

    struct amsh_qptrs   qptrs[PTL_AMSH_MAX_LOCAL_NODES];

    int			kassist_pid;

/*
 * Peer view of my index. for initial node, it is the same as ep->amsh_shmidx,
 * for other remote nodes, it is calculated by circular offset of
 * PTL_AMSH_MAX_LOCAL_PROCS, node-ID, and ep->amsh_shmidx.
 */
    int			amsh_shmidx;
    psm_epid_t		amsh_epid;
    uint16_t		amsh_verno;
#ifdef PSM_HAVE_SCIF
    scif_epd_t		amsh_epd[2];
#endif
    off_t               amsh_offset;
    void		*amsh_base;
    psm_epaddr_t	amsh_epaddr;
} __attribute__ ((aligned(8)));

typedef struct amsh_qtail_info
{
    volatile uint32_t tail;
    volatile pthread_spinlock_t  lock;
    uint8_t  _pad0[64-1*4-sizeof(pthread_spinlock_t)];
} amsh_qtail_info_t;
PSMI_STRICT_SIZE_DECL(amsh_qtail_info_t,64);

struct amsh_qtail
{
    amsh_qtail_info_t reqFifoShort;
    amsh_qtail_info_t reqFifoMed;
    amsh_qtail_info_t reqFifoLong;
    amsh_qtail_info_t reqFifoHuge;

    amsh_qtail_info_t repFifoShort;
    amsh_qtail_info_t repFifoMed;
    amsh_qtail_info_t repFifoLong;
    amsh_qtail_info_t repFifoHuge;
} __attribute__ ((aligned(64)));

/* The first shared memory page is a control page to support each endpoint
 * independently adding themselves to the shared memory segment. */
struct am_ctl_dirpage {
    pthread_mutex_t lock;
    char            _pad0[64-sizeof(pthread_mutex_t)];
    volatile int    is_init;
    char            _pad1[64-sizeof(int)];

    uint16_t        psm_verno[PTL_AMSH_MAX_LOCAL_PROCS];
    uint32_t        amsh_features[PTL_AMSH_MAX_LOCAL_PROCS];
    int             num_attached; /* 0..MAX_LOCAL_PROCS-1 */
    int		    max_idx;

    psm_epid_t      shmidx_map_epid[PTL_AMSH_MAX_LOCAL_PROCS];
    int		    kcopy_minor;
    int		    kassist_pids[PTL_AMSH_MAX_LOCAL_PROCS];

    /* A set of tail queue data for each remote domain.  Each domain has
       a reserved set of queues for each other domain.  The queues are located
       in shared memory on the target domain, while the tail pointer is
       located on the source domain. */
    /* The tail pointers are located in the dirpage because each peer in this
       domain will be sharing them (atomically).  The dirpage is mapped by
       all processes already, so just use it. */
    struct amsh_qtail qtails[PTL_AMSH_MAX_LOCAL_PROCS*PTL_AMSH_MAX_LOCAL_NODES];
};

#define AMSH_HAVE_KCOPY	0x01
#define AMSH_HAVE_KNEM  0x02
#define AMSH_HAVE_SCIF  0x04
#define AMSH_HAVE_KASSIST 0x7

/******************************************
 * Shared fifo element counts and sizes
 ******************************************
 * These values are context-wide, they can only be set early on and can't be *
 * modified at runtime.  All endpoints are expected to use the same values.
 */
typedef
struct amsh_qinfo {
    int qreqFifoShort;
    int qreqFifoMed;
    int qreqFifoLong;
    int qreqFifoHuge;

    int qrepFifoShort;
    int qrepFifoMed;
    int qrepFifoLong;
    int qrepFifoHuge;
}
amsh_qinfo_t;

/******************************************
 * Per-endpoint structures (ep-local)
 ******************************************
 * Each endpoint keeps its own information as to where it resides in the
 * directory, and maintains its own cached copies of where the short header
 * resides in shared memory.
 *
 * NOTE: All changes must be reflected in PSMI_AMSH_EP_SIZE
 */
struct ptl {
    psm_ep_t		   ep;
    psm_epid_t             epid;
    psm_epaddr_t	   epaddr;
    ptl_ctl_t              *ctl;
    int                    shmidx; 
    am_ctl_qshort_cache_t  reqH[PTL_AMSH_MAX_LOCAL_NODES];
    am_ctl_qshort_cache_t  repH[PTL_AMSH_MAX_LOCAL_NODES];
    int                    zero_polls;
    int                    amsh_only_polls;

    pthread_mutex_t        connect_lock;
    int                    connect_phase;
    int                    connect_to;
    int                    connect_from;

/* List of context-specific shared variables */
    amsh_qinfo_t	   amsh_qsizes;
    am_pkt_short_t	   amsh_empty_shortpkt;
    struct am_reqq_fifo_t  psmi_am_reqq_fifo;

};

#endif
