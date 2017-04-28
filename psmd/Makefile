#
#
#  This file is provided under a dual BSD/GPLv2 license.  When using or
#  redistributing this file, you may do so under either license.
#
#  GPL LICENSE SUMMARY
#
#  Copyright(c) 2012, 2017. Intel Corporation.
#  Copyright(c) 2005, 2006. QLogic Corporation.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of version 2 of the GNU General Public License as
#  published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  Contact Information:
#  Intel Corporation, www.intel.com 
#
#  BSD LICENSE
#
#  Copyright(c) 2012, 2017. Intel Corporation.
#  Copyright(c) 2005, 2006. QLogic Corporation.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include $(top_srcdir)/buildflags.mak
CFLAGS += -Wall -Werror -D_IPATH_DEBUGGING=0
LDFLAGS += $(SCIF_LINK_FLAGS)
INCLUDES += -I$(top_srcdir)/include -I$(top_srcdir)/include/linux-x86_64 $(SCIF_INCLUDE_FLAGS)
TARGETS = psmd

all: ${TARGETS}

${TARGETS}-objs := psmd.o ipath_service.o ipath_sysfs.o

${TARGETS}: ${$(TARGETS)-objs}
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

psmd.o: psmd.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

ipath_service.o: $(top_srcdir)/ipath/ipath_service.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

ipath_sysfs.o: $(top_srcdir)/ipath/ipath_sysfs.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

install:
	install -D psmd ${DESTDIR}${INSTALL_SBIN_TARG}/psmd
clean:
	rm -f *.o $(TARGETS)

