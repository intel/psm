#
#  Copyright (c) 2010 Lawrence Livermore National Security.  All rights reserved
#
#  This software is available to you under a choice of one of two
#  licenses.  You may choose to be licensed under the terms of the GNU
#  General Public License (GPL) Version 2, available from the file
#  COPYING in the main directory of this source tree, or the
#  OpenIB.org BSD license below:
#
#      Redistribution and use in source and binary forms, with or
#      without modification, are permitted provided that the following
#      conditions are met:
#
#       - Redistributions of source code must retain the above
#         copyright notice, this list of conditions and the following
#         disclaimer.
#
#       - Redistributions in binary form must reproduce the above
#         copyright notice, this list of conditions and the following
#         disclaimer in the documentation and/or other materials
#         provided with the distribution.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
#  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
#  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#

#
# global
#
INCLUDES=-I$(srcdir)/include \
	 -I$(srcdir)/mpspawn \
	 -I$(srcdir)/ptl_ips \
	 -D_GNU_SOURCE \
	 -I$(srcdir)/include/$(TARGET_SYSTEM)-$(TARGET_ARCH)

if DEBUG
DBGFLAGS = -O0 -g3 -DPSM_DEBUG -funit-at-a-time -D_DEBUG_
else
DBGFLAGS = -O3 -g3
endif

if PSM_PROFILE
PROFILE_FLGS = -DPSM_PROFILE
else
PROFILE_FLGS =
endif

if PSM_VALGRIND
VALGRIND = -DPSM_VALGRIND
else
VALGRIND = -DNVALGRIND
endif

if PSM_USE_SYS_UUID
SYS_UUID = -DPSM_USE_SYS_UUID
EX_LIBS = -luuid
else
SYS_UUID =
EX_LIBS =
endif

AM_CFLAGS = -fpic -fPIC -funwind-tables \
		-Wall $(DBGFLAGS) $(PROFILE_FLGS) $(VALGRIND) \
		$(SYS_UUID)

if HAVE_LD_VERSION_SCRIPT
libpsm_infinipath_version_script = -Wl,--version-script=$(srcdir)/src/libpsm_infinipath.map
libinfinipath_version_script = -Wl,--version-script=$(srcdir)/src/libinfinipath.map
else
libpsm_infinipath_version_script =
libinfinipath_version_script =
endif

lib_LTLIBRARIES = libinfinipath.la libpsm_infinipath.la

#
# libinfinipath
#
libinfinipathincludedir = $(includedir)
libinfinipathinclude_HEADERS = 
libinfinipath_la_CFLAGS = $(AM_CFLAGS)
# automake does not allow variables in the "SOURCES" list
# configure defines the CPU we are compiling for and include those files in the
# sources only
if CPU_X86_64
	CPU_SOURCES=ipath/ipath_dwordcpy-x86_64-fast.S \
			ipath/ipath_dwordcpy-x86_64.c \
			ipath/ipath_write_pio-x86_64.c
endif
if CPU_I386
	CPU_SOURCES=ipath/ipath_dwordcpy-i386.S \
			ipath/ipath_write_pio-i386.c
endif
if CPU_PPC
libinfinipath_la_CFLAGS += -maltivec
	CPU_SOURCES=ipath/ipath_write_pio-ppc.c
endif
if CPU_PPC64
	CPU_SOURCES=ipath/ipath_dwordcpy-ppc64.c \
			ipath/ipath_write_pio-ppc64.c
endif
libinfinipath_la_SOURCES = ipath/ipath_debug.c \
			ipath/ipath_time.c \
			ipath/ipath_proto.c \
			ipath/ipath_i2cflash.c \
			ipath/ipath_sysfs.c \
			ipath/ipath_syslog.c \
			ipath/pscrevision.c \
			$(CPU_SOURCES)

libinfinipath_la_LDFLAGS = -version-info $(infinipath_api_version) \
    -export-dynamic $(libinfinipath_version_script) $(EX_LIBS)
libinfinipath_la_DEPENDENCIES = $(srcdir)/src/libinfinipath.map

#
# libpsm_infinipath
#
libpsm_infinipathincludedir = $(includedir)
libpsm_infinipathinclude_HEADERS = psm.h psm_mq.h
libpsm_infinipath_la_CFLAGS = $(AM_CFLAGS)
libpsm_infinipath_la_SOURCES = ptl_am/am_reqrep_shmem.c	\
		   ptl_am/am_reqrep.c		\
		   ptl_am/ptl_am.c		\
		   ptl_am/kcopyrwu.c		\
		   psm_context.c		\
		   psm_ep.c			\
		   psm_ep_connect.c		\
		   psm_error.c			\
		   psm_utils.c			\
		   psm_timer.c			\
		   psm_am.c			\
		   psm_mq.c			\
		   psm_mq_utils.c		\
		   psm_mq_recv.c		\
		   psm_mpool.c			\
		   psm_stats.c			\
		   psm_memcpy.c			\
		   psm.c			\
		   libuuid/psm_uuid.c		\
		   ptl_ips/ptl_ips.c		\
		   ptl_ips/ptl_rcvthread.c	\
		   ptl_ips/ipserror.c		\
		   ptl_ips/ips_scb.c		\
		   ptl_ips/ips_epstate.c	\
		   ptl_ips/ips_recvq.c		\
		   ptl_ips/ips_recvhdrq.c	\
		   ptl_ips/ips_spio.c		\
		   ptl_ips/ips_proto.c		\
		   ptl_ips/ips_proto_recv.c	\
		   ptl_ips/ips_proto_connect.c  \
		   ptl_ips/ips_proto_expected.c \
		   ptl_ips/ips_tid.c		\
		   ptl_ips/ips_crc32.c 		\
		   ptl_ips/ips_tidflow.c        \
		   ptl_ips/ips_proto_dump.c	\
		   ptl_ips/ips_proto_mq.c       \
		   ptl_ips/ips_proto_am.c       \
		   ptl_ips/ips_subcontext.c	\
		   ptl_ips/ips_path_rec.c       \
		   ptl_ips/ips_opp_path_rec.c   \
		   ptl_ips/ips_writehdrq.c	\
		   ptl_self/ptl_self.c		\
		   psm_diags.c                  \
		   psmrevision.c

libpsm_infinipath_la_LDFLAGS = -version-info $(psm_infinipath_api_version) \
    -export-dynamic $(libpsm_infinipath_version_script) \
    -lpthread -lrt -ldl -L$(srcdir)/ipath -linfinipath $(EX_LIBS)
libpsm_infinipath_la_DEPENDENCIES = $(srcdir)/src/libpsm_infinipath.map

#
# Distribution
#
# just find all the headers for the distribution
headers:=$(shell find . -name '*.h')
EXTRA_DIST = \
	$(headers) \
	libuuid \
	autogen.sh \
	infinipath-psm.spec.in \
	infinipath-psm.spec \
	libpsm_infinipath.ver \
	libinfinipath.ver \
	psmrevision.c.in \
	ipath/pscrevision.c.in \
	$(srcdir)/src/libpsm_infinipath.map \
	$(srcdir)/src/libinfinipath.map

