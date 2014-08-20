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

#ifndef _PSMI_HELP_H
#define _PSMI_HELP_H

/* XXX pathcc and gcc only */
#define PSMI_INLINE(FN)					\
    static inline FN

#define PSMI_ALWAYS_INLINE(FN)                            \
    static __inline__ FN __attribute__((always_inline));  \
    static __inline__ FN

#define PSMI_NEVER_INLINE(FN)             \
    static FN __attribute__((noinline));  \
    static FN

#define _PPragma(x) _Pragma(x)

#define STRINGIFY(s)	_STRINGIFY(s)
#define _STRINGIFY(s)	#s
#define PSMI_CURLOC	__FILE__ ":" STRINGIFY(__LINE__)
#define psmi_assert_always_loc(x,curloc)    do {			\
	    if_pf (!(x)) {						\
		psmi_handle_error(PSMI_EP_NORETURN, PSM_INTERNAL_ERR,	\
		    "Assertion failure at %s: %s", curloc,		\
		     STRINGIFY(x));					\
	    } } while (0)

#define psmi_assert_always(x)  psmi_assert_always_loc(x,PSMI_CURLOC)

#ifdef PSM_DEBUG
#  define psmi_assert(x)	psmi_assert_always(x)
#  define PSMI_ASSERT_INITIALIZED() psmi_assert_always(psmi_isinitialized())
#else
#  define psmi_assert(x)
#  define PSMI_ASSERT_INITIALIZED()
#endif

#define _PSMI_API_NAME(FN)  __ ## FN
#define _PSMI_API_STR(FN)   _STRINGIFY(__ ## FN)
#define PSMI_API_DECL(FN)							\
	typeof(_PSMI_API_NAME(FN)) FN __attribute__((weak, alias(_PSMI_API_STR(FN))));

#define PSMI_ERR_UNLESS_INITIALIZED(ep)    do {			    \
	    if (!psmi_isinitialized())				    \
		return psmi_handle_error(ep, PSM_INIT_NOT_INIT,	    \
			"PSM has not been initialized");	    \
	} while (0)
		

#define PSMI_CHECKMEM(err,mem)  do {	\
	    if ((mem) == NULL) {	\
		(err) = PSM_NO_MEMORY;	\
		goto fail;		\
	    }				\
	} while (0)

#define PSMI_CACHEALIGN	__attribute__((aligned(64)))

/* Easy way to ignore the OK_NO_PROGRESS case */
PSMI_ALWAYS_INLINE(
psm_error_t
psmi_err_only(psm_error_t err))
{
    if (err > PSM_OK_NO_PROGRESS)
	return err;
    else
	return PSM_OK;
}

#ifdef min
#undef min
#endif
#define min(a,b) ((a) < (b) ? (a) : (b))

#ifdef max
#undef max
#endif
#define max(a,b) ((a) > (b) ? (a) : (b))

#define SEC_ULL	 1000000000ULL
#define MSEC_ULL 1000000ULL
#define USEC_ULL 1000ULL
#define NSEC_ULL 1ULL

#define PSMI_TRUE   1
#define PSMI_FALSE  0

#define PSMI_CYCLES_TO_SECSF(cycles)			\
	    ((double) cycles_to_nanosecs(cycles) / 1.0e9)

#define PSMI_PAGESIZE       psmi_getpagesize()
#define PSMI_POWEROFTWO(P)  (((P)&((P)-1)) == 0)
#define PSMI_ALIGNDOWN(p,P) (((uintptr_t)(p))&~((uintptr_t)((P)-1)))
#define PSMI_ALIGNUP(p,P)   (PSMI_ALIGNDOWN((uintptr_t)(p)+((uintptr_t)((P)-1)),(P)))

#define PSMI_MAKE_DRIVER_VERSION(major,minor) ((major)<<16 | ((minor) & 0xffff))

#define PSMI_STRICT_SIZE_DECL(member,sz) static const size_t __psm_ss_ ## member = sz
#define PSMI_STRICT_SIZE_VERIFY(member,sz)  do {                    \
            if (__psm_ss_ ## member != (sz)) {			    \
                char errmsg[64];                                    \
                snprintf(errmsg,32, "Internal error: %s "           \
                  "size doesn't match expected %d bytes",           \
                  STRINGIFY(member), (int) __psm_ss_ ## member);    \
		exit(-1);					    \
            }                                                       \
        } while (0)


#endif /* _PSMI_HELP_H */
