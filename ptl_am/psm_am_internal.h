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
#define PSMI_KASSIST_GET       0x5
#define PSMI_KASSIST_PUT       0xA
#define PSMI_KASSIST_MASK      0xF

#define PSMI_KASSIST_MODE_DEFAULT PSMI_KASSIST_KNEM_PUT
#define PSMI_KASSIST_MODE_DEFAULT_STRING  "knem-put"

int psmi_kassist_mode;
int psmi_kassist_fd;
int psmi_epaddr_kcopy_pid(psm_epaddr_t epaddr);

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
psmi_amsh_am_short_request(ptl_t *ptl, psm_epaddr_t epaddr,
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
struct am_reqq_fifo_t psmi_am_reqq_fifo;

psm_error_t psmi_am_reqq_drain();
void psmi_am_reqq_add(int amtype, ptl_t *ptl, psm_epaddr_t epaddr,
                 psm_handler_t handler, psm_amarg_t *args, int nargs,
		 void *src, size_t len, void *dest, int flags);

#endif
