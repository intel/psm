# Copyright (c) 2006, 2007, 2008 QLogic Corporation. All rights reserved.
# Copyright (c) 2003, 2004, 2005 PathScale, Inc.  All rights reserved.
# 
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# OpenIB.org BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# set top_srcdir and include this file

ifeq (,$(top_srcdir))
$(error top_srcdir must be set to include makefile fragment)
endif

export os ?= $(shell uname -s | tr '[A-Z]' '[a-z]')
export arch := $(shell uname -p | sed -e 's,\(i[456]86\|athlon$$\),i386,')

ifeq (${CCARCH},pathcc)
	export CC := pathcc -fno-fast-stdlib 
	export PATH := ${PATH}:/opt/pathscale/bin/
else
	ifeq (${CCARCH},gcc)
		export CC := gcc 
	else
		ifeq (${CCARCH},gcc4)
			export CC := gcc4
		else
			anerr := $(error Unknown C compiler arch: ${CCARCH})
		endif # gcc4
	endif # gcc
endif # pathcc

ifeq (${FCARCH},pathf90)
	export FC := pathf90 
	export PATH := ${PATH}:/opt/pathscale/bin/
else
	ifeq (${FCARCH},gfortran)
		export FC := gfortran 
	else
		anerr := $(error Unknown Fortran compiler arch: ${FCARCH})
	endif # gfortran
endif # pathf90

BASECFLAGS += $(BASE_FLAGS)
LDFLAGS += $(BASE_FLAGS)
ASFLAGS += $(BASE_FLAGS)

WERROR := -Werror
INCLUDES := -I. -I$(top_srcdir)/include -I$(top_srcdir)/mpspawn -I$(top_srcdir)/include/$(os)-$(arch) 
BASECFLAGS +=-Wall $(WERROR)
ifneq (,${PSM_DEBUG})
  BASECFLAGS += -O0 -g3 -DPSM_DEBUG -funit-at-a-time -Wp,-D_FORTIFY_SOURCE=2
else
  BASECFLAGS += -O3 -g3 
endif
ifneq (,${PSM_PROFILE})
  BASECFLAGS += -DPSM_PROFILE
endif
BASECFLAGS += -fpic -fPIC -funwind-tables -D_GNU_SOURCE

ifeq (1,${PSM_USE_SYS_UUID})
  BASECFLAGS += -DPSM_USE_SYS_UUID
  EXTRA_LIBS = -luuid
endif

ifneq (,${PSM_VALGRIND})
  CFLAGS += -DPSM_VALGRIND
else
  CFLAGS += -DNVALGRIND
endif

ASFLAGS += -g3 -fpic

BASECFLAGS += ${IPATH_CFLAGS}

ifeq (${CCARCH},icc)
    BASECFLAGS = -O2 -g3 -fpic -fPIC -D_GNU_SOURCE
    CFLAGS += $(BASECFLAGS)
else
    ifeq (${CCARCH},pathcc)
	CFLAGS += $(BASECFLAGS)
	ifeq (,${PSM_DEBUG})
	    CFLAGS += -OPT:Ofast
	endif
    else
	ifeq (${CCARCH},gcc)
	    CFLAGS += $(BASECFLAGS) -Wno-strict-aliasing 
	else
	    ifeq (${CCARCH},gcc4)
		CFLAGS += $(BASECFLAGS)
	    else
		$(error Unknown compiler arch "${CCARCH}")
	    endif # gcc4
	endif # gcc
    endif # pathcc
endif # icc

