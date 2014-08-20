# Copyright (c) 2006-2010. QLogic Corporation. All rights reserved.
# Copyright (c) 2003-2006, PathScale, Inc. All rights reserved.
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

include $(top_srcdir)/buildflags.mak
INCLUDES += -I$(top_srcdir) -I$(top_srcidr)/ptl_ips

${TARGLIB}-objs := ptl.o ptl_rcvthread.o ips_proto.o ipserror.o ips_recvq.o \
		   ips_recvhdrq.o ips_spio.o ips_proto_recv.o ips_proto_connect.o \
		   ips_proto_dump.o ips_proto_mq.o ips_subcontext.o \
		   ips_writehdrq.o ips_proto_expected.o ips_tid.o

# enable mov,0 -> xor optimization for ips
ifeq (${CCARCH},pathcc)
  ifeq (,${PSM_DEBUG})
    CFLAGS += -CG:use_xortozero=1
  endif
endif

all: ${${TARGLIB}-objs}

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.o

