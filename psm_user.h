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

#ifndef _PSMI_USER_H
#define _PSMI_USER_H

#include <inttypes.h>
#include <pthread.h>

#include "psm.h"
#include "psm_mq.h"

#include "ptl.h"

#include "ipath_user.h"
#include "ipath_queue.h"
#include "valgrind/valgrind.h"
#include "valgrind/memcheck.h"

#define _PSMI_IN_USER_H
#include "psm_help.h"
#include "psm_error.h"
#include "psm_context.h"
#include "psm_utils.h"
#include "psm_timer.h"
#include "psm_mpool.h"
#include "psm_ep.h"
#include "psm_lock.h"
#include "psm_stats.h"
#undef _PSMI_IN_USER_H

#define PSMI_VERNO_MAKE(major,minor) ((((major)&0xff)<<8)|((minor)&0xff))
#define PSMI_VERNO  PSMI_VERNO_MAKE(PSM_VERNO_MAJOR, PSM_VERNO_MINOR)
#define PSMI_VERNO_GET_MAJOR(verno) ( ((verno)>>8) & 0xff )
#define PSMI_VERNO_GET_MINOR(verno) ( ((verno)>>0) & 0xff )

int psmi_verno_client();
int psmi_verno_isinteroperable(uint16_t verno);
int psmi_isinitialized();

psm_error_t psmi_poll_internal(psm_ep_t ep, int poll_amsh);
psm_error_t psmi_mq_wait_internal(psm_mq_req_t *ireq);

/*
 * Default setting for Receive thread
 *
 *   0 disables rcvthread by default
 * 0x1 enables ips receive thread by default
 */
#define PSMI_RCVTHREAD_FLAGS	0x1

/*
 * Define one of these below.
 *
 * Spinlock gives the best performance and makes sense with the progress thread
 * only because the progress thread does a "trylock" and then goes back to
 * sleep in a poll.
 *
 * Mutexlock should be used for experimentation while the more useful
 * mutexlock-debug should be enabled during developement to catch potential
 * errors.
 */
#ifdef PSM_DEBUG
  #define PSMI_PLOCK_IS_MUTEXLOCK_DEBUG
#else
  #define PSMI_PLOCK_IS_SPINLOCK
  //#define PSMI_PLOCK_IS_MUTEXLOCK
  //#define PSMI_PLOCK_IS_MUTEXLOCK_DEBUG
  //#define PSMI_PLOCK_IS_NOLOCK
#endif

#ifdef PSMI_PLOCK_IS_SPINLOCK
  extern psmi_spinlock_t  psmi_progress_lock;
  #define PSMI_PLOCK_INIT()   psmi_spin_init(&psmi_progress_lock)
  #define PSMI_PLOCK_TRY()    psmi_spin_trylock(&psmi_progress_lock)
  #define PSMI_PLOCK()	      psmi_spin_lock(&psmi_progress_lock)
  #define PSMI_PUNLOCK()      psmi_spin_unlock(&psmi_progress_lock)
  #define PSMI_PLOCK_ASSERT()
  #define PSMI_PUNLOCK_ASSERT()
  #define PSMI_PLOCK_DISABLED  0
#elif defined(PSMI_PLOCK_IS_MUTEXLOCK_DEBUG) 
  extern pthread_mutex_t  psmi_progress_lock;
  extern pthread_t	   psmi_progress_lock_owner;
  #define PSMI_PLOCK_NO_OWNER	((pthread_t)(-1))

  PSMI_ALWAYS_INLINE(
  int _psmi_mutex_trylock_inner(pthread_mutex_t *mutex, const char *curloc))
  {
    psmi_assert_always_loc(psmi_progress_lock_owner != pthread_self(), curloc);
    int ret = pthread_mutex_trylock(&psmi_progress_lock);
    if (ret == 0)
	psmi_progress_lock_owner = pthread_self();
    return ret;
  }

  PSMI_ALWAYS_INLINE(
  int _psmi_mutex_lock_inner(pthread_mutex_t *mutex, const char *curloc))
  {
    psmi_assert_always_loc(psmi_progress_lock_owner != pthread_self(), curloc);
    int ret = pthread_mutex_lock(&psmi_progress_lock);
    psmi_assert_always_loc(ret != EDEADLK, curloc);
    psmi_progress_lock_owner = pthread_self();
    return ret;
  }

  PSMI_ALWAYS_INLINE(
  void _psmi_mutex_unlock_inner(pthread_mutex_t *mutex, const char *curloc))
  {
    psmi_assert_always_loc(psmi_progress_lock_owner == pthread_self(), curloc);
    psmi_progress_lock_owner = PSMI_PLOCK_NO_OWNER;
    psmi_assert_always_loc(
	pthread_mutex_unlock(&psmi_progress_lock) != EPERM, curloc);
    return;
  }
  #define PSMI_PLOCK_INIT()   /* static initialization */
  #define PSMI_PLOCK_TRY()						\
	    _psmi_mutex_trylock_inner(&psmi_progress_lock, PSMI_CURLOC)
  #define PSMI_PLOCK()							\
	    _psmi_mutex_lock_inner(&psmi_progress_lock, PSMI_CURLOC)
  #define PSMI_PUNLOCK()						\
	    _psmi_mutex_unlock_inner(&psmi_progress_lock, PSMI_CURLOC)
  #define PSMI_PLOCK_ASSERT()						\
	    psmi_assert_always(psmi_progress_lock_owner == pthread_self());
  #define PSMI_PUNLOCK_ASSERT()						\
	    psmi_assert_always(psmi_progress_lock_owner != pthread_self());

  #define PSMI_PLOCK_DISABLED  0
#elif defined (PSMI_PLOCK_IS_MUTEXLOCK)
  pthread_mutex_t  psmi_progress_lock;
  #define PSMI_PLOCK_INIT()   /* static initialization */
  #define PSMI_PLOCK_TRY()    pthread_mutex_trylock(&psmi_progress_lock)
  #define PSMI_PLOCK()	      pthread_mutex_lock(&psmi_progress_lock)
  #define PSMI_PUNLOCK()      pthread_mutex_unlock(&psmi_progress_lock)
  #define PSMI_PLOCK_DISABLED  0
  #define PSMI_PLOCK_ASSERT()
  #define PSMI_PUNLOCK_ASSERT()
#elif defined(PSMI_PLOCK_IS_NOLOCK)
  #define PSMI_PLOCK_TRY()    0 /* 0 *only* so progress thread never succeeds */
  #define PSMI_PLOCK()	      
  #define PSMI_PUNLOCK()      
  #define PSMI_PLOCK_DISABLED  1
  #define PSMI_PLOCK_ASSERT()
  #define PSMI_PUNLOCK_ASSERT()
#else
  #error No PLOCK lock type declared
#endif

#define PSMI_PYIELD()							\
	  do { PSMI_PUNLOCK(); sched_yield(); PSMI_PLOCK(); } while (0)

#ifdef PSM_PROFILE
  void psmi_profile_block() __attribute__ ((weak));
  void psmi_profile_unblock() __attribute__ ((weak));
  void psmi_profile_reblock(int did_no_progress) __attribute__ ((weak));;

  #define PSMI_PROFILE_BLOCK()		psmi_profile_block()
  #define PSMI_PROFILE_UNBLOCK()	psmi_profile_unblock()
  #define PSMI_PROFILE_REBLOCK(noprog)	psmi_profile_reblock(noprog)
#else
  #define PSMI_PROFILE_BLOCK()
  #define PSMI_PROFILE_UNBLOCK()
  #define PSMI_PROFILE_REBLOCK(noprog)
#endif

#ifdef PSM_VALGRIND
  #define PSM_VALGRIND_REDZONE_SZ	     8
  #define PSM_VALGRIND_DEFINE_MQ_RECV(buf,posted_len,recv_len)	do {	\
	    VALGRIND_MAKE_MEM_DEFINED((void *)(buf), (posted_len));	\
	    if ((recv_len) < (posted_len))				\
		VALGRIND_MAKE_MEM_UNDEFINED(				\
		(void *) ((uintptr_t) (buf) + (recv_len)),		\
		(posted_len) - (recv_len));				\
	    } while (0)

#else
  #define PSM_VALGRIND_REDZONE_SZ	     0
  #define PSM_VALGRIND_DEFINE_MQ_RECV(buf,posted_len,recv_len)
#endif

/* Parameters for use in valgrind's "is_zeroed" */
#define PSM_VALGRIND_MEM_DEFINED     1
#define PSM_VALGRIND_MEM_UNDEFINED   0

#endif /* _PSMI_USER_H */
