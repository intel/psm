# Copyright (c) 2012. Intel Corporation. All rights reserved.
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

CC ?= gcc

SCIF_LINK_FLAGS :=
SCIF_INCLUDE_FLAGS :=

compiler_arch := $(shell $(CC) -dumpmachine || echo "none")
ifeq ($(compiler_arch),none)
$(error Could not determine compiler arch for $(CC))
endif
MIC := $(if $(findstring k1om,$(compiler_arch)),1,0)

# If SCIF_ROOT_DIR is set, we should assume using SCIF
# If SCIF_INCLUDE_FLAGS is set, we should assume using SCIF
# If /usr/include/scif.h exists, we should assume using SCIF

ifdef SCIF_ROOT_DIR
	SCIF_LINK_FLAGS := -L$(SCIF_ROOT_DIR)/source-root/k1om-hybrid/$(if $(MIC:0=),card,host)/scif_lib #-lscif
	SCIF_INCLUDE_FLAGS := -I$(SCIF_ROOT_DIR)/source-root/k1om-hybrid/include
endif

PSM_HAVE_SCIF ?= $(shell printf '\#include <scif.h>\nint main(void){return(0);}\n' | \
	$(CC) $(CFLAGS) $(LDFLAGS) -x c - -o /dev/null &> /dev/null && echo 1 || echo 0)

ifeq (1,$(PSM_HAVE_SCIF))
	SCIF_INCLUDE_FLAGS += -DPSM_HAVE_SCIF=1
	SCIF_LINK_FLAGS += -lscif
endif

WERROR := -Werror
INCLUDES := -I. -I$(top_srcdir)/include -I$(top_srcdir)/mpspawn \
	-I$(top_srcdir)/include/$(os)-$(arch) $(SCIF_INCLUDE_FLAGS)
BASECFLAGS += $(BASE_FLAGS) $(if $(MIC:0=),$(if $(filter $(CC),icc),-mmic,-D__MIC__)) \
	-Wall $(WERROR) $(if $(MIC:0=),-Wno-unused) -fpic -fPIC -D_GNU_SOURCE \
	$(if $(filter $(CC),icc),,-funwind-tables) $(if $(PSM_PROFILE:0=),-DPSM_PROFILE) \
	${IPATH_CFLAGS}
ASFLAGS += $(BASE_FLAGS) $(if $(MIC:0=),$(if $(filter $(CC),icc),-mmic,-D__MIC__)) -g3 -fpic

LDFLAGS += $(SCIF_LINK_FLAGS)

# If linker flags are needed, uncomment the line below and set flags
#LDFLAGS +=

ifneq (,${PSM_DEBUG})
  BASECFLAGS += -O -g3 -DPSM_DEBUG $(if $(filter $(CC),icc),,-funit-at-a-time) \
	-Wp,-D_FORTIFY_SOURCE=2
else
  BASECFLAGS += -O3 -g3 
endif
ifeq (1,${PSM_USE_SYS_UUID})
  BASECFLAGS += -DPSM_USE_SYS_UUID
  EXTRA_LIBS = -luuid
endif

CFLAGS += $(BASECFLAGS) $(if $(filter $(CC),gcc),-Wno-strict-aliasing) \
	$(if $(PSM_VALGRIND:0=),-DPSM_VALGRIND,-DNVALGRIND)

