# Copyright (c) 2006, 2007, 2008 QLogic Corporation. All rights reserved.
# Copyright (c) 2003, 2004, 2005 PathScale, Inc.  All rights reserved.
# Unpublished -- rights reserved under the copyright laws of the United States.
# USE OF A COPYRIGHT NOTICE DOES NOT IMPLY PUBLICATION OR DISCLOSURE.
# THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF
# PATHSCALE, INC.  USE, DISCLOSURE, OR REPRODUCTION IS PROHIBITED
# WITHOUT THE PRIOR EXPRESS WRITTEN PERMISSION OF PATHSCALE, INC.

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

