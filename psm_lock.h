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

#ifndef _PSMI_IN_USER_H
#error psm_lock.h not meant to be included directly, include psm_user.h instead
#endif

#ifndef _PSMI_LOCK_H
#define _PSMI_LOCK_H

#ifndef PSMI_USE_PTHREAD_SPINLOCKS
  #if defined(__powerpc__)
    #define PSMI_USE_PTHREAD_SPINLOCKS 1
  #else
    #define PSMI_USE_PTHREAD_SPINLOCKS 0
  #endif
#endif

#if PSMI_USE_PTHREAD_SPINLOCKS
  typedef pthread_spinlock_t	  psmi_spinlock_t;

  #define psmi_spin_init(lock)	  pthread_spin_init(lock,0)
  #define psmi_spin_lock(lock)	  pthread_spin_lock(lock)
  #define psmi_spin_trylock(lock) pthread_spin_trylock(lock)
  #define psmi_spin_unlock(lock)  pthread_spin_unlock(lock)
#else
  typedef ips_atomic_t psmi_spinlock_t;
  #define PSMI_SPIN_LOCKED    1
  #define PSMI_SPIN_UNLOCKED  0

  PSMI_ALWAYS_INLINE(
  int 
  psmi_spin_init(psmi_spinlock_t *lock)) {
    ips_atomic_set(lock, PSMI_SPIN_UNLOCKED);
    return 0;
  }

  PSMI_ALWAYS_INLINE(
  int
  psmi_spin_trylock(psmi_spinlock_t *lock)) {
    if (ips_atomic_cmpxchg(lock,PSMI_SPIN_UNLOCKED,PSMI_SPIN_LOCKED) 
		    == PSMI_SPIN_UNLOCKED)
	return 0;
    else
	return EBUSY;
  }

  PSMI_ALWAYS_INLINE(
  int
  psmi_spin_lock(psmi_spinlock_t *lock)) {
    while (psmi_spin_trylock(lock) == EBUSY)
	  {}
    return 0;
  }

  PSMI_ALWAYS_INLINE(
  int
  psmi_spin_unlock(psmi_spinlock_t *lock)) {
    atomic_set(lock, PSMI_SPIN_UNLOCKED);
    return 0;
  }
#endif /* PSMI_USE_PTHREAD_SPINLOCKS */

#endif /* _PSMI_LOCK_H */
