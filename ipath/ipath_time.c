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

#define __USE_GNU
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "ipath_user.h"

// init the cycle counter to picosecs/cycle conversion automatically
// at program startup, if it's using timing functions.
static void init_picos_per_cycle(void) __attribute__ ((constructor));
static int      ipath_timebase_isvalid(uint32_t pico_per_cycle);
static uint32_t ipath_timebase_from_cpuinfo(uint32_t old_pico_per_cycle);

// in case two of our mechanisms fail
#ifdef __powerpc__
#define SAFEDEFAULT_PICOS_PER_CYCLE 69000
#else
#define SAFEDEFAULT_PICOS_PER_CYCLE 500
#endif

uint32_t __ipath_pico_per_cycle = SAFEDEFAULT_PICOS_PER_CYCLE; 

// This isn't perfect, but it's close enough for rough timing. We want this
// to work on systems where the cycle counter isn't the same as the clock
// frequency.
// __ipath_pico_per_cycle isn't going to lead to completely accurate
// conversions from timestamps to nanoseconds, but it's close enough for
// our purposes, which is mainly to allow people to show events with nsecs
// or usecs if desired, rather than cycles.   We use it in some performance
// analysis, but it has to be done with care, since cpuspeed can change,
// different cpu's can have different speeds, etc.
//
// Some architectures don't have their TSC-equivalent running at anything
// related to the the processor speed (e.g. G5 Power systems use a fixed
// 33 MHz frequency).

#define MIN_TEST_TIME_IN_PICOS (100000000000LL) /* 100 milliseconds */

static int timebase_debug = 0; /* off by default */

#define timebase_warn_always(fmt,...)				    \
	    ipath_syslog("timebase", 1, LOG_ERR, fmt, ##__VA_ARGS__)
#define timebase_warn(fmt,...)	if (timebase_debug)		    \
	    timebase_warn_always(fmt, ##__VA_ARGS__)

static int ipath_timebase_isvalid(uint32_t pico_per_cycle)
{
#if defined(__x86_64__) || defined(__i386__)
    /* If pico-per-cycle is less than 200, the clock speed would be greater
     * than 5 GHz.  Similarly, we minimally support a 1GHz clock.
     * Allow some slop, because newer kernels with HPET can be a few
     * units off, and we don't want to spend the startup time needlessly */
    if (pico_per_cycle >= 198 && pico_per_cycle <= 1005)
	return 1;
#elif defined(__powerpc__)
    /* If pico-per-cycle is not between 1MHz and 1GHz, complain */
    if (pico_per_cycle >= 9950 && pico_per_cycle <= 1005000)
	return 1;
#endif
    else
	return 0;
}

/* 
 * Method #1:
 *
 * Derive the pico-per-cycle by trying to correlate the difference between two
 * reads of the tsc counter to gettimeofday.
 */
static void init_picos_per_cycle()
{
    struct timeval tvs, tve;
    int64_t usec = 0;
    uint64_t ts, te;
    int64_t delta;
    uint32_t picos = 0;
    int trials = 0;
    int retry = 0;
    cpu_set_t cpuset, cpuset_saved;
    int have_cpuset = 1;

    /*
     * Make sure we try to calculate the cycle time without being migrated.
     */
    CPU_ZERO(&cpuset_saved);
    if (sched_getaffinity(0, sizeof cpuset, &cpuset_saved))
	have_cpuset = 0;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    if(have_cpuset && sched_setaffinity(0,sizeof cpuset, &cpuset)) 
	have_cpuset = 0;

    /*
     * If we set affinity correctly, give the scheduler another change to put
     * us on processor 0
     */
    if (have_cpuset) 
	sched_yield();

retry_pico_test:
    if (++retry == 10) {
	__ipath_pico_per_cycle = 
	    ipath_timebase_from_cpuinfo(picos);
	goto reset_cpu_mask; /* Reset CPU mask before exiting */
    }

    usec = 0;
    gettimeofday(&tvs, NULL);
    ts = get_cycles();
    while (usec < MIN_TEST_TIME_IN_PICOS) { /* wait for at least 100 millisecs */
	trials++;
	usleep(125);
	gettimeofday(&tve, NULL);
	usec = 1000000LL * (tve.tv_usec - tvs.tv_usec) +
	       1000000000000LL *  (tve.tv_sec - tvs.tv_sec);
	if (usec < 0) {
	    timebase_warn("RTC timebase, gettimeofday is negative (!) %lld\n",
		(long long) usec);
	    goto retry_pico_test;
	}
    }
    te = get_cycles();
    delta = te - ts;
    picos = (uint32_t)(usec / delta);

    if (!ipath_timebase_isvalid(picos)) {
	cpu_set_t cpuget;
	int affinity_valid = !sched_getaffinity(0, sizeof cpuget, &cpuget);
	if (affinity_valid && !CPU_ISSET(0, &cpuget))
	    affinity_valid = 0;
	timebase_warn("Failed to get valid RTC timebase, gettimeofday delta=%lld, "
	    "rtc delta=%lld, picos_per_cycle=%d affinity_valid=%s (trial %d/10)\n",
	    (long long) usec, (long long) delta, picos, 
	    affinity_valid ? "YES" : "NO", retry);
	goto retry_pico_test;
    }

    /* If we've had to retry even once, let that be known */
    if (retry > 1) 
	timebase_warn("Clock is %d picos/cycle found in %d trials and "
		      "%.3f seconds (retry=%d)\n", picos, trials, 
		      (double) usec / 1.0e12, retry);

    __ipath_pico_per_cycle = picos;

 reset_cpu_mask:
    /* Restore affinity */
    if (have_cpuset) {
	sched_setaffinity(0, sizeof cpuset, &cpuset_saved);
	/*
	 * Give a chance to other processes that also set affinity to 0 for
	 * doing this test.
	 */
	sched_yield();
    }
}

/* 
 * Method #2:
 *
 * Derive the pico-per-cycle from /proc instead of using sleep trick
 * that relies on scheduler.
 */
static uint32_t 
ipath_timebase_from_cpuinfo(uint32_t old_pico_per_cycle)
{
    /* we only validate once */
    uint32_t new_pico_per_cycle = old_pico_per_cycle;

    char hostname[80];
    gethostname(hostname, 80);
    hostname[sizeof hostname - 1] = '\0';

    if (getenv("IPATH_DEBUG_TIMEBASE"))
	timebase_debug = 1;

    /* If the old one is valid, don't bother with this mechanism */
    if (ipath_timebase_isvalid(old_pico_per_cycle)) 
	return old_pico_per_cycle;

#if defined(__x86_64__) || defined(__i386__)
    {
      	FILE *fp = fopen("/proc/cpuinfo","r");
      	char input[255];
	char *p = NULL;

	if (!fp)
	    goto fail;

	while (!feof(fp) && fgets(input, 255, fp)) {
	    if (strstr(input,"cpu MHz")) {
		p = strchr(input,':');
		double MHz = 0.0;
		if (p) MHz = atof(p+1);
		new_pico_per_cycle = (uint32_t)(1000000. / MHz);
		break;  
	    }
	}       
	fclose(fp);
	if (!p) 
	    goto fail;
    }
#elif defined(__powerpc__)
  #include <sys/types.h>
  #include <dirent.h>
    {
	DIR *dp = opendir("/proc/device-tree/cpus");
	uint32_t freq;
	FILE *fp = NULL;
	char buf[256];
	struct dirent *de = NULL;
	int found = 0;
	if (!dp)
	    goto fail;
	do {
	    de = readdir(dp);
	    if (de && (de->d_name == strstr(de->d_name, "PowerPC,"))) {
		found = 1;
		break;
	    }
	} while (de != NULL);
	if (!found)
	    goto fail;

	snprintf(buf, sizeof buf, 
	    "/proc/device-tree/cpus/%s/timebase-frequency", de->d_name);
	if ((fp = fopen(buf, "r"))) {
	    if (fread((void *) &freq, sizeof(uint32_t), 1, fp) != 1) 
		goto fail;
	    /* freq is in Hz */
	    new_pico_per_cycle = 1e6 / (freq / 1e6);
	    fclose(fp);
	}
	else
	    goto fail;
    }
#endif

    /* If there's no change (within a small range), just return the old one */
    if (abs(new_pico_per_cycle - old_pico_per_cycle) < 5)
	return old_pico_per_cycle;

    if (ipath_timebase_isvalid(new_pico_per_cycle)) {
	timebase_warn_always("RTC timebase, using %d picos/cycle from /proc "
		      "instead of the detected %d picos/cycle\n",
		      new_pico_per_cycle, old_pico_per_cycle);
	return new_pico_per_cycle;
    }

fail:
    new_pico_per_cycle = SAFEDEFAULT_PICOS_PER_CYCLE;
    timebase_warn_always(
	    "Problem obtaining CPU time base, detected to be %d "
	    "pico/cycle, adjusted to safe default %d picos/cycle", 
	    old_pico_per_cycle, new_pico_per_cycle);
    return new_pico_per_cycle;
}

