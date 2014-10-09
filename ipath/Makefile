# Copyright (c) 2012. Intel Corporation. All rights reserved.
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

TARGLIB := libinfinipath
MAJOR := $(IPATH_LIB_MAJOR)
MINOR := $(IPATH_LIB_MINOR)

include $(top_srcdir)/buildflags.mak
BASECFLAGS += -D_GNU_SOURCE
INCLUDES += -I$(top_srcdir)/ptl_ips

ifeq (${arch},x86_64)
	PLATFORM_OBJ=ipath_dwordcpy-x86_64-fast.o
else
	PLATFORM_OBJ=
endif

${TARGLIB}-objs := ipath_debug.o ipath_time.o ipath_proto.o \
	ipath_utils.o ipath_service.o ipath_protomic.o \
	ipath_dwordcpy-$(arch).o ipath_i2cflash.o ipath_sysfs.o ipath_syslog.o \
	ipath_write_pio-$(arch).o $(PLATFORM_OBJ)

all .DEFAULT: ${TARGLIB}.so

install: all
	install -D ${TARGLIB}.so.${MAJOR}.${MINOR} \
		${DESTDIR}${INSTALL_LIB_TARG}/${TARGLIB}.so.${MAJOR}.${MINOR}
	(cd ${DESTDIR}${INSTALL_LIB_TARG} ; \
		ln -sf ${TARGLIB}.so.${MAJOR}.${MINOR} ${TARGLIB}.so.${MAJOR} ; \
		ln -sf ${TARGLIB}.so.${MAJOR} ${TARGLIB}.so)

${TARGLIB}.so: ${TARGLIB}.so.${MAJOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

${TARGLIB}.so.${MAJOR}: ${TARGLIB}.so.${MAJOR}.${MINOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

# when we build the shared library, generate a revision and date
# string in it, for easier id'ing when people may have copied the
# file around.  Generate it such that the ident command can find it
# and strings -a | grep InfiniPath does a reasonable job as well.
${TARGLIB}.so.${MAJOR}.${MINOR}: ${${TARGLIB}-objs}
	date +'static __attribute__ ((unused)) char __psc_infinipath_revision[] ="$$""Date: %F %R ${rpm_extra_description}InfiniPath $$";' > _revision.c
	$(CC) -c $(BASECFLAGS) $(INCLUDES) _revision.c -o _revision.o
	$(CC) -o $@ -Wl,-soname=${TARGLIB}.so.${MAJOR} -shared \
		-Wl,--unique='*fastpath*' \
		${${TARGLIB}-objs} _revision.o $(LDFLAGS) $(if $(MIC:0=),$(SCIF_LINK_FLAGS))

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $(if $(MIC:0=),$(SCIF_INCLUDE_FLAGS)) -c $< -o $@

%.o: %.S
	$(CC) $(ASFLAGS) -c $< -o $@

ipath_debug.o: WERROR :=
# This is temporarily necessary in order to get backtrace to work. Bug 3536
ipath_debug.o: ipath_debug.c
	$(CC) $(BASECFLAGS) $(INCLUDES) -c $< -o $@

ipath_write_pio-ppc.o: ipath_write_pio-ppc.c
	$(CC) $(CFLAGS) -maltivec $(INCLUDES) -c $< -o $@

ipath_write_pio-ppc64.o: ipath_write_pio-ppc64.c
	$(CC) $(CFLAGS) -maltivec $(INCLUDES) -c $< -o $@

clean:
	rm -f _revision.c
	rm -f *.o ${TARGLIB}.*
