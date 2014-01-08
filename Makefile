# Copyright (c) 2013 Intel Corporation.  All rights reserved.
# Copyright (c) 2006-2011. QLogic Corporation. All rights reserved.
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

RPM_NAME := infinipath-psm

SUBDIRS:= ptl_self ptl_ips ptl_am libuuid ipath
export build_dir := .

PSM_VERNO_MAJOR := $(shell sed -n 's/^\#define.*PSM_VERNO_MAJOR.*0x0\?\([1-9a-f]\?[0-9a-f]\+\).*/\1/p' $(build_dir)/psm.h)
PSM_VERNO_MINOR := $(shell sed -n 's/^\#define.*PSM_VERNO_MINOR.*0x\([0-9]\?[0-9a-f]\+\).*/\1/p' $(build_dir)/psm.h)
PSM_LIB_MAJOR   := $(shell printf "%d" ${PSM_VERNO_MAJOR})
PSM_LIB_MINOR   := $(shell printf "%d" `sed -n 's/^\#define.*PSM_VERNO_MINOR.*\(0x[0-9a-f]\+\).*/\1/p' $(build_dir)/psm.h`)

IPATH_LIB_MAJOR := 4
IPATH_LIB_MINOR := 0

export PSM_VERNO_MAJOR
export PSM_LIB_MAJOR
export PSM_VERNO_MINOR
export PSM_LIB_MINOR
export IPATH_LIB_MAJOR
export IPATH_LIB_MINOR
export CCARCH := gcc
export FCARCH := gfortran

# Try to figure out which libuuid to use. This needs to be
# done before we include buildflags.mak
PSM_USE_SYS_UUID=0
ifneq (1,${USE_PSM_UUID})
    # Check whether the uuid header file is present. The header file is
    # installed by the -devel package, which should have a dependency
    # on the package which installs the library.
    PSM_HAVE_UUID_H=$(shell if [ -f /usr/include/uuid/uuid.h ]; then echo 1; else echo 0; fi)
    ifeq (1,${PSM_HAVE_UUID_H})
       SYS_UUID_RPM_NAME=$(shell rpm -qf --qf "%{NAME} = %{VERSION}-%{RELEASE}" /usr/include/uuid/uuid.h)
       PSM_USE_SYS_UUID=1
    endif
endif
export PSM_USE_SYS_UUID

top_srcdir := .
include $(top_srcdir)/buildflags.mak
lib_build_dir := $(build_dir)

ifneq (x86_64,$(arch))
   ifneq (i386,$(arch))
      $(error Unsupported architecture $(arch))
   endif
endif

ifndef LIBDIR
   ifeq (${arch},x86_64)
      INSTALL_LIB_TARG=/usr/lib64
   else
      INSTALL_LIB_TARG=/usr/lib
   endif
else
   INSTALL_LIB_TARG=${LIBDIR}
endif
export DESTDIR
export INSTALL_LIB_TARG

TARGLIB := libpsm_infinipath

MAJOR := $(PSM_LIB_MAJOR)
MINOR := $(PSM_LIB_MINOR)

# The desired version number comes from the most recent tag starting with "v"
VERSION := $(shell if [ -d .git ] ; then  git  describe --tags --abbrev=0 --match='v*' | sed -e 's/^v//' -e 's/-/_/'; else echo "version" ; fi)

# The desired release number comes the git describe following the version which
# is the number of commits since the version tag was planted suffixed by the g<commitid>
RELEASE := $(shell if [ -d .git ] ; then git describe --tags --long --match='v*' | sed -e 's/v[0-9.]*-\(.*\)/\1_open/' -e 's/-/_/'; else echo "release" ; fi)

EPOCH := 4

# Concatenated version and release
VERSION_RELEASE := $(VERSION)-$(RELEASE)

LDLIBS := -linfinipath -lrt -lpthread -ldl ${EXTRA_LIBS}

all: symlinks
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@ ;\
	done
	$(MAKE) ${TARGLIB}.so

clean:
	rm -f _revision.c
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@ ;\
	done
	rm -f *.o ${TARGLIB}.*

distclean: cleanlinks clean
	rm -f ${RPM_NAME}.spec
	rm -f ${RPM_NAME}-${VERSION_RELEASE}.tar.gz

.PHONY: symlinks
symlinks:
	@[[ -L $(build_dir)/include/linux-ppc64 ]] || \
		ln -sf linux-ppc $(build_dir)/include/linux-ppc64
	@[[ -L $(build_dir)/include/linux-x86_64 ]] || \
		ln -sf linux-i386 $(build_dir)/include/linux-x86_64
	@[[ -L $(build_dir)/ipath/ipath_dwordcpy-ppc.c ]] || \
		ln -sf ipath_dwordcpy-ppc64.c $(build_dir)/ipath/ipath_dwordcpy-ppc.c

cleanlinks:
	rm -f $(build_dir)/include/linux-ppc64
	rm -f $(build_dir)/include/linux-x86_64
	rm -f $(build_dir)/ipath/ipath_dwordcpy-ppc.c

install: all
	for subdir in $(SUBDIRS); do \
		$(MAKE) -C $$subdir $@ ;\
	done
	install -D ${TARGLIB}.so.${MAJOR}.${MINOR} \
		${DESTDIR}${INSTALL_LIB_TARG}/${TARGLIB}.so.${MAJOR}.${MINOR}
	(cd ${DESTDIR}${INSTALL_LIB_TARG} ; \
		ln -sf ${TARGLIB}.so.${MAJOR}.${MINOR} ${TARGLIB}.so.${MAJOR} ; \
		ln -sf ${TARGLIB}.so.${MAJOR} ${TARGLIB}.so)
	install -D psm.h ${DESTDIR}/usr/include/psm.h
	install -D psm_mq.h ${DESTDIR}/usr/include/psm_mq.h

specfile:
	sed \
		-e 's/@VERSION@/'${VERSION}'/g' \
		-e 's/@RELEASE@/'${RELEASE}'/g' \
		-e 's/@EPOCH@/'${EPOCH}'/g' ${RPM_NAME}.spec.in | \
		sed -e 's/@RELEASE@/'${RELEASE}'/g' > \
		${RPM_NAME}.spec
	if [ X$(PSM_USE_SYS_UUID) = X1 ]; then \
		REQUIRES="Requires: $(shell echo $(SYS_UUID_RPM_NAME) | sed -e 's/-devel//')" ; \
		REQUIRESDEVEL="Requires: $(SYS_UUID_RPM_NAME)" ; \
		sed -i -e 's/@REQUIRES@/'"$${REQUIRES}"'/g' \
			-e 's/@REQUIRES-DEVEL@/'"$$REQUIRESDEVEL"'/g' \
			-e 's/@PSM_UUID@//g' ${RPM_NAME}.spec ; \
	else \
		sed -i -e '/@REQUIRES@/d' \
			-e '/@REQUIRES-DEVEL@/d' \
			-e 's/@PSM_UUID@/USE_PSM_UUID=1/g' ${RPM_NAME}.spec ; \
	fi

# The tar is done twice with the first one discarded. This is because of
# file system stat issues causing the first tar to fail with errors due
# to files updating while tar is running. I don't understand this.
dist: distclean specfile
	mkdir -p ${RPM_NAME}-${VERSION_RELEASE}
	for x in $$(/usr/bin/find . -name ".git" -prune -o \
			-name "cscope*" -prune -o \
			-name "*.spec.in" -prune -o \
			-name "${RPM_NAME}-${VERSION_RELEASE}" -prune -o \
			-name "*.orig" -prune -o \
			-name "*~" -prune -o \
			-name "#*" -prune -o \
			-name ".gitignore" -prune -o \
			-print); do \
		dir=$$(dirname $$x); \
		mkdir -p ${RPM_NAME}-${VERSION_RELEASE}/$$dir; \
		[ ! -d $$x ] && cp $$x ${RPM_NAME}-${VERSION_RELEASE}/$$dir; \
	done
	if [ -d .git ] ; then git log -n1 --pretty=format:%H > ${RPM_NAME}-${VERSION_RELEASE}/COMMIT ; fi
	-tar czvf ${RPM_NAME}-${VERSION_RELEASE}.tar.gz ${RPM_NAME}-${VERSION_RELEASE} > /dev/null 2>&1
	tar czvf ${RPM_NAME}-${VERSION_RELEASE}.tar.gz ${RPM_NAME}-${VERSION_RELEASE}
	rm -rf ${RPM_NAME}-${VERSION_RELEASE}

ofeddist:
	USE_PSM_UUID=1 $(MAKE) dist

# rebuild the cscope database, skipping sccs files, done once for
# top level
cscope:
	find * -type f ! -name '[ps].*' \( -iname '*.[cfhs]' -o \
	  -iname \\*.cc -o -name \\*.cpp -o -name \\*.f90 \) -print | cscope -bqu -i -

${TARGLIB}-objs := ptl_am/am_reqrep_shmem.o	\
		   ptl_am/am_reqrep.o		\
		   ptl_am/ptl.o			\
		   ptl_am/kcopyrwu.o		\
		   ptl_am/knemrwu.o		\
		   psm_context.o		\
		   psm_ep.o			\
		   psm_ep_connect.o		\
		   psm_error.o			\
		   psm_utils.o			\
		   psm_timer.o			\
		   psm_am.o			\
		   psm_mq.o			\
		   psm_mq_utils.o		\
		   psm_mq_recv.o		\
		   psm_mpool.o			\
		   psm_stats.o			\
		   psm_memcpy.o			\
		   psm.o			\
		   libuuid/psm_uuid.o		\
		   ptl_ips/ptl.o		\
		   ptl_ips/ptl_rcvthread.o	\
		   ptl_ips/ipserror.o		\
		   ptl_ips/ips_scb.o		\
		   ptl_ips/ips_epstate.o	\
		   ptl_ips/ips_recvq.o		\
		   ptl_ips/ips_recvhdrq.o	\
		   ptl_ips/ips_spio.o		\
		   ptl_ips/ips_proto.o		\
		   ptl_ips/ips_proto_recv.o	\
		   ptl_ips/ips_proto_connect.o  \
		   ptl_ips/ips_proto_expected.o \
		   ptl_ips/ips_tid.o		\
		   ptl_ips/ips_crc32.o 		\
		   ptl_ips/ips_tidflow.o        \
		   ptl_ips/ips_proto_dump.o	\
		   ptl_ips/ips_proto_mq.o       \
		   ptl_ips/ips_proto_am.o       \
		   ptl_ips/ips_subcontext.o	\
		   ptl_ips/ips_path_rec.o       \
		   ptl_ips/ips_opp_path_rec.o   \
		   ptl_ips/ips_writehdrq.o	\
		   ptl_self/ptl.o		\
		   psm_diags.o

${TARGLIB}.so: ${lib_build_dir}/${TARGLIB}.so.${MAJOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

${TARGLIB}.so.${MAJOR}: ${lib_build_dir}/${TARGLIB}.so.${MAJOR}.${MINOR}
	ln -fs ${TARGLIB}.so.${MAJOR}.${MINOR} $@

# when we build the shared library, generate a revision and date
# string in it, for easier id'ing when people may have copied the
# file around.  Generate it such that the ident command can find it
# and strings -a | grep InfiniPath does a reasonable job as well.
${TARGLIB}.so.${MAJOR}.${MINOR}: ${${TARGLIB}-objs}
	date +'char psmi_infinipath_revision[] ="$$""Date: %F %R ${rpm_extra_description}InfiniPath $$";' > ${lib_build_dir}/_revision.c
	$(CC) -c $(BASECFLAGS) $(INCLUDES) _revision.c -o _revision.o
	$(CC) $(LDFLAGS) -o $@ -Wl,-soname=${TARGLIB}.so.${MAJOR} -shared -Wl,--unique='*fastpath*' \
		${${TARGLIB}-objs} _revision.o -Lipath $(LDLIBS)
	@leaks=`nm $@ | grep ' [DT] ' | \
	 grep -v -e ' [DT] \(_edata\|_fini\|_init\|infinipath_\|ips_\|psmi\|__psmi\?_\|_\rest.pr\|_save.pr\|kcopy\|knem\)'`; \
	 if test -n "$$leaks"; then echo "Build failed, leaking symbols:"; echo "$$leaks"; exit 1; fi

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

.PHONY: $(SUBDIRS)

