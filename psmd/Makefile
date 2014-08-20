#       Copyright (c) 2012. Intel Corporation. All rights reserved.
#	Copyright (C) 2005, 2006. QLogic Corporation.  All rights reserved.
#	Permission is granted to QLogic customers to use this software in 
#	source and binary forms, with or without modification, provided that 
#	the following conditions are met: 
#	
#	+ All copies of source code must retain the above copyright notice, 
#	  this list of conditions and the following disclaimer. 
#	
#	+ Customer has a valid license agreement from QLogic Corporation. for the 
#	  software product with which this software is originally distributed. 
#	
#	+ Redistribution of original or modified versions to third parties is 
#	  prohibited without specific prior written permission of QLogic
#	  Corporation. 
#	
#	+ If customer makes modifications to this software, and provides those 
#	  modifications to QLogic, customer assigns to QLogic Corporation. 
#	  ownership of the provided modifications and all intellectual property 
#	  rights embodied in those modifications. 
#	
#	+ The name of QLogic Corporation. may not be used to endorse or promote 
#	  products derived from this software without specific prior written 
#	  permission. 
#	
#	THIS SOFTWARE IS PROVIDED BY QLOGIC CORPORATION. AND ITS LICENSORS "AS IS" 
#	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
#	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR 
#	PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL QLOGIC CORPORATION. OR ITS 
#	LICENSORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
#	EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
#	PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
#	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
#	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
#	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
#	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

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

