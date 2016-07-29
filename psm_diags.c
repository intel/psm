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

#include "psm_user.h"
#include "psm_mq_internal.h"

typedef void (*memcpy_fn_t)(void *dst, const void *src, size_t n);
static int psmi_test_memcpy(memcpy_fn_t, const char *name);
static int psmi_test_epid_table(int numelems);

int psmi_diags(void);

#define diags_assert(x)	do {					\
	    if (!(x))  {					\
		_IPATH_ERROR("Diags assertion failure: %s\n",	\
		    #x);					\
		goto fail;					\
	    }							\
	} while (0)

#define DIAGS_RETURN_PASS(str)						\
	do { _IPATH_INFO("%s: PASSED %s\n", __func__, str); return 0; } \
	    while (0)
#define DIAGS_RETURN_FAIL(str)						\
	do { _IPATH_INFO("%s: FAILED %s\n", __func__, str); return 1; } \
	    while (0)

int
psmi_diags(void)
{
    int ret = 0;
    ret |= psmi_test_epid_table(2048);
    ret |= psmi_test_memcpy((memcpy_fn_t) psmi_memcpyo, "psmi_memcpyo");
    //ret |= psmi_test_memcpy((memcpy_fn_t) psmi_mq_mtucpy, "psmi_mq_mtucpy");

    if (ret)
	DIAGS_RETURN_FAIL("");
    else
	DIAGS_RETURN_PASS("");
}

/*
 * Hash table test
 */
#define NALLOC	1024
static int
psmi_test_epid_table(int numelems)
{
    psm_epaddr_t    *ep_array, epaddr, ep_alloc;
    psm_epid_t	*epid_array, epid_tmp;
    psm_ep_t	ep = (psm_ep_t) (uintptr_t) 0xabcdef00;
    struct psmi_epid_table  *tab;
    int i, j;

    ep_alloc = (psm_epaddr_t) psmi_calloc(PSMI_EP_NONE, UNDEFINED, numelems, sizeof(struct psm_epaddr));
    ep_array = (psm_epaddr_t *) psmi_calloc(PSMI_EP_NONE, UNDEFINED, numelems, sizeof(struct psm_epaddr *));
    epid_array = (psm_epid_t *) psmi_calloc(PSMI_EP_NONE, UNDEFINED, numelems, sizeof(psm_epid_t));
    diags_assert(ep_alloc != NULL);
    diags_assert(ep_array != NULL);
    diags_assert(epid_array != NULL);

    srand(12345678);

    psmi_epid_init();
    tab = &psmi_epid_table;

    for (i = 0; i < numelems; i++) {
	epid_array[i] = i;
	ep_alloc[i].ep = ep;
	ep_alloc[i].epid = epid_array[i];
	ep_array[i] = &ep_alloc[i];
    }
    for (i = 0 ; i < numelems; i++) {
	psmi_epid_add(ep, epid_array[i], ep_array[i]);
    }

    /* Randomize epid_array */
    for (i = 0; i < numelems; i++) {
	j = rand() % numelems;
	epid_tmp = epid_array[i];
	epid_array[i] = epid_array[j];
	epid_array[j] = epid_tmp;
    }
    /* Lookup. */
    for (i = 0; i < numelems; i++) {
	epaddr = psmi_epid_lookup(ep, epid_array[i]);
	diags_assert(epaddr != NULL);
	diags_assert(epaddr->epid == epid_array[i]);
	diags_assert(epaddr->ep == ep);
    }

    /* Randomize epid_array again */
    for (i = 0; i < numelems; i++) {
	j = rand() % numelems;
	epid_tmp = epid_array[i];
	epid_array[i] = epid_array[j];
	epid_array[j] = epid_tmp;
    }
    /* Delete half */
    for (i = 0; i < numelems/2; i++) {
	epaddr = psmi_epid_remove(ep, epid_array[i]);
	diags_assert(epaddr != NULL);
	diags_assert(epaddr->epid == epid_array[i]);
	diags_assert(epaddr->ep == ep);
    }
    /* Lookup other half -- expect non-NULL, then delete */
    for (i = numelems/2; i < numelems; i++) {
	epaddr = psmi_epid_lookup(ep, epid_array[i]);
	diags_assert(epaddr != NULL);
	diags_assert(epaddr->epid == epid_array[i]);
	diags_assert(epaddr->ep == ep);
	epaddr = psmi_epid_remove(ep, epid_array[i]);
	epaddr = psmi_epid_lookup(ep, epid_array[i]);
	diags_assert(epaddr == NULL);
    }
    /* Lookup whole thing, expect done */
    for (i = 0; i < numelems; i++) {
	epaddr = psmi_epid_lookup(ep, epid_array[i]);
	diags_assert(epaddr == NULL);
    }
    for (i = 0; i < tab->tabsize; i++) {
	diags_assert(tab->table[i].entry == NULL || 
		     tab->table[i].entry == EPADDR_DELETED);
    }

    /* Make sure we're not leaking memory somewhere... */
    diags_assert(tab->tabsize > tab->tabsize_used &&
		 tab->tabsize * PSMI_EPID_TABLOAD_FACTOR >
			tab->tabsize_used);

    /* Only free on success */
    psmi_epid_fini();
    psmi_free(epid_array);
    psmi_free(ep_array);
    psmi_free(ep_alloc);
    DIAGS_RETURN_PASS("");

fail:
    /* Klocwork scan report memory leak. */
    psmi_epid_fini();
    if (epid_array) psmi_free(epid_array);
    if (ep_array) psmi_free(ep_array);
    if (ep_alloc) psmi_free(ep_alloc);
    DIAGS_RETURN_FAIL("");
}

/*
 * Memcpy correctness test
 */
static int memcpy_check_size (memcpy_fn_t fn, int *p, int *f, size_t n);
static void *memcpy_check_one (memcpy_fn_t fn, void *dst, void *src, size_t n);

static int
psmi_test_memcpy(memcpy_fn_t fn, const char *memcpy_name)
{
    const int CORNERS = 0;
    const long long lo = 1;
    const long long hi = 16 * 1024 * 1024;
    const long long below = 32;
    const long long above = 32;
    long long n, m;
    char buf[128];
    int ret = 0;
    int memcpy_passed;
    int memcpy_failed;

    memcpy_passed = 0;
    memcpy_failed = 0;

    ret = memcpy_check_size(fn, &memcpy_passed, &memcpy_failed, 0);
    if (ret < 0)
	DIAGS_RETURN_FAIL("no heap space");

    for (n = lo; n <= hi; n <<= 1) {
	_IPATH_INFO("%s %d align=0..16\n", memcpy_name, (int) n);
	for (m = n - below; m <= n + above; m++) {
	    if (m == n) {
		ret = memcpy_check_size(fn, &memcpy_passed, &memcpy_failed, n);
		if (ret < 0)
		    DIAGS_RETURN_FAIL("no heap space");
	    }
	    else if (CORNERS && m >= lo && m <= hi && m > (n >> 1) &&
	       m < max(n, ((n << 1) - below))) 
	    {
		ret = memcpy_check_size(fn, &memcpy_passed, &memcpy_failed, (size_t) m);
		if (ret < 0)
		    DIAGS_RETURN_FAIL("no heap space");
	    }
	}
    }

    int total = memcpy_passed + memcpy_failed;
    if (total > 0) {
	_IPATH_INFO("%d memcpy tests with %d passed (%.2f%%) "
		    "and %d failed (%.2f%%)\n",
           total, memcpy_passed, (100.0 * memcpy_passed) / total, 
           memcpy_failed, (100.0 * memcpy_failed) / total);
    }
    if (memcpy_failed) {
	snprintf(buf, sizeof buf, "%s %.2f%% of tests memcpy_failed",
			memcpy_name, (100.0 * memcpy_failed) / total);
	DIAGS_RETURN_FAIL(buf);
    }
    else {
	DIAGS_RETURN_PASS(memcpy_name);
    }
}

void *memcpy_check_one (memcpy_fn_t fn, void *dst, void *src, size_t n)
{
  int ok = 1;
  unsigned int seed = (unsigned int)
	  ((uintptr_t) dst ^ (uintptr_t) src ^ (uintptr_t) n);
  unsigned int state;
  size_t i;
  psmi_assert_always(n > 0);
  memset(src, 0x55, n);
  memset(dst, 0xaa, n);
  srand(seed);
  state = seed;
  for (i = 0; i < n; i++) {
    ((uint8_t *) src)[i] = (rand_r(&state) >> 16) & 0xff;
  }

  fn(dst, src, n);
  memset(src, 0, n);
  srand(seed);
  state = seed;
  for (i = 0; i < n; i++) {
    int value = (int) (uint8_t) (rand_r(&state) >> 16);
    int v = (int) ((uint8_t *) dst)[i];
    if (v != value) {
      _IPATH_ERROR("Error on index %llu : got %d instead of %d\n",
             (unsigned long long) i, v, value);
      ok = 0;
    }
  }
  return ok ? dst : NULL;
}

int
memcpy_check_size (memcpy_fn_t fn, int *p, int *f, size_t n)
{
#define num_aligns 16
#define USE_MALLOC 0
#define DEBUG 0
  uint8_t *src;
  uint8_t *dst;
  size_t size = n * 2 + num_aligns;
  if (USE_MALLOC) {
    src = psmi_malloc(PSMI_EP_NONE, UNDEFINED, size);
    dst = psmi_malloc(PSMI_EP_NONE, UNDEFINED, size);
    if (src == NULL || dst == NULL) {
      if (src) psmi_free(src);
      if (dst) psmi_free(dst);
      return -1;
	}
  }
  else {
    void *src_p = NULL, *dst_p = NULL;
    if (posix_memalign(&src_p, 64, size) != 0 ||
        posix_memalign(&dst_p, 64, size) != 0) {
      if (src_p) psmi_free(src_p);
      if (dst_p) psmi_free(dst_p);
      return -1;
    }
    else {
	src = (uint8_t *) src_p;
	dst = (uint8_t *) dst_p;
    }
  }
  int src_align, dst_align;
  for (src_align = 0; src_align < num_aligns; src_align++) {
    for (dst_align = 0; dst_align < num_aligns; dst_align++) {
      uint8_t *d = ((uint8_t *) dst) + dst_align;
      uint8_t *s = ((uint8_t *) src) + src_align;
      int ok = (memcpy_check_one(fn, d, s, n) != NULL);
      if (DEBUG || !ok) {
        _IPATH_INFO("memcpy(%p, %p, %llu) : %s\n", d, s, 
	       (unsigned long long) n,
               ok ? "passed" : "failed");
      }
      if (ok) {
        (*p)++;
      }
      else {
        (*f)++;
      }  
    }
  }
  psmi_free(src);
  psmi_free(dst);
  return 0;
}
