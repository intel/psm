dnl
dnl  Copyright (c) 2010 Lawrence Livermore National Security.  All rights reserved
dnl
dnl  This software is available to you under a choice of one of two
dnl  licenses.  You may choose to be licensed under the terms of the GNU
dnl  General Public License (GPL) Version 2, available from the file
dnl  COPYING in the main directory of this source tree, or the
dnl  OpenIB.org BSD license below:
dnl
dnl      Redistribution and use in source and binary forms, with or
dnl      without modification, are permitted provided that the following
dnl      conditions are met:
dnl
dnl       - Redistributions of source code must retain the above
dnl         copyright notice, this list of conditions and the following
dnl         disclaimer.
dnl
dnl       - Redistributions in binary form must reproduce the above
dnl         copyright notice, this list of conditions and the following
dnl         disclaimer in the documentation and/or other materials
dnl         provided with the distribution.
dnl
dnl  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
dnl  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
dnl  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
dnl  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
dnl  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
dnl  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
dnl  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
dnl  SOFTWARE.
dnl

AC_INIT(InfiniPath-PSM)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(config)
AC_CONFIG_HEADERS(config)

dnl pick up the target_cpu, target_vendor, and target_os
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE(InfiniPath-PSM, 1.13.0)


dnl Checks for programs
AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_LIB(pthread, pthread_create, [],
        AC_MSG_ERROR([pthread_create() not found. infinipath-psm requires libpthread.]))
AC_CHECK_LIB(rt, aio_cancel, [],
        AC_MSG_ERROR([aio_cancel() not found. infinipath-psm requires librt.]))
AC_CHECK_LIB(dl, dlopen, [],
        AC_MSG_ERROR([dlopen() not found. infinipath-psm requires libdl.]))


dnl set up assembler
CCAS="$CC"
AC_SUBST(CCAS)
CCASFLAGS=""
AC_SUBST(CCASFLAGS)


dnl support debug mode
AC_ARG_ENABLE(debug,
[  --enable-debug      Turn on debug mode (default=no)],
[case "${enableval}" in
  yes) debug=true ;;
  no)  debug=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
esac],[debug=false])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

dnl Profiling
AC_ARG_ENABLE(profile,
[  --enable-profile    Enable PSM Profiling (default=no)],
[case "${enableval}" in
  yes) profile=true ;;
  no)  profile=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-profile) ;;
esac],[profile=false])
AM_CONDITIONAL(PSM_PROFILE, test x$profile = xtrue)

dnl Valgrind
AC_ARG_ENABLE(valgrind,
[  --enable-profile    Enable Valgrind (default=no)],
[case "${enableval}" in
  yes) valgrind=true ;;
  no)  valgrind=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-valgrind) ;;
esac],[valgrind=false])
AM_CONDITIONAL(PSM_VALGRIND, test x$valgrind = xtrue)

dnl Use Sys UUID
AC_ARG_ENABLE(sysuuid,
[  --disable-sysuuid   Use Sys UUID (default=yes)],
[case "${enableval}" in
  yes) sysuuid=true ;;
  no)  sysuuid=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-sysuuid) ;;
esac],[sysuuid=true])
if test x$sysuuid = xtrue; then
AC_CHECK_LIB(uuid, uuid_generate, [],
        AC_MSG_ERROR([uuid_generate() not found in uuid.  Please disable sysuuid]))
fi
AM_CONDITIONAL(PSM_USE_SYS_UUID, test x$sysuuid = xtrue)

dnl version of libpsm_infinipath
psm_infinipath_api_version=`grep LIBVERSION $srcdir/libpsm_infinipath.ver | sed 's/LIBVERSION=//'`
if test -z $psm_infinipath_api_version; then
    psm_infinipath_api_version=1:0:0
fi
AC_SUBST(psm_infinipath_api_version)

dnl version of libinfinipath
infinipath_api_version=`grep LIBVERSION $srcdir/libinfinipath.ver | sed 's/LIBVERSION=//'`
if test -z $infinipath_api_version; then
    infinipath_api_version=1:0:0
fi
AC_SUBST(infinipath_api_version)

dnl build date
BUILD_DATE=`date +'%F %R'`
AC_SUBST([BUILD_DATE])

AC_CACHE_CHECK(whether ld accepts --version-script, ac_cv_version_script,
    if test -n "`$LD --help < /dev/null 2>/dev/null | grep version-script`"; then
        ac_cv_version_script=yes
    else
        ac_cv_version_script=no
    fi)
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$ac_cv_version_script" = "yes")

dnl set spec file values
AC_SUBST(RELEASE, ${RELEASE:-unknown})
AC_SUBST(TARBALL, ${TARBALL:-${PACKAGE}-${VERSION}.tar.gz})

AC_MSG_CHECKING(target os)
TARGET_SYSTEM=""
case $target_os in
	linux*)
		TARGET_SYSTEM="linux"
	;;
	*)
		echo "ERROR: $target_os is not supported at this time"
		exit 1
	;;
esac
AC_SUBST([TARGET_SYSTEM])
AC_MSG_RESULT([$TARGET_SYSTEM])

cpu_i386=false
cpu_x86_64=false
cpu_ppc=false
cpu_ppc64=false
AC_MSG_CHECKING(target arch / cpu)
TARGET_ARCH=""
case $target_cpu in
	i386|i486|i586|i686)
		TARGET_ARCH="i386"
		cpu_i386=true
	;;
	x86_64)
		TARGET_ARCH="i386"
		cpu_x86_64=true
	;;
	powerpc|ppc)
		TARGET_ARCH="ppc"
		cpu_ppc=true
	;;
	powerpc64|ppc64)
		TARGET_ARCH="ppc"
		cpu_ppc64=true
	;;
	*)
		echo "ERROR: $target_cpu is not supported at this time"
		exit 1
	;;
esac
AC_SUBST([TARGET_ARCH])
AC_MSG_RESULT([$TARGET_ARCH / $target_cpu])

AM_CONDITIONAL(CPU_I386, test x$cpu_i386 = xtrue )
AM_CONDITIONAL(CPU_X86_64, test x$cpu_x86_64 = xtrue)
AM_CONDITIONAL(CPU_PPC, test x$cpu_ppc = xtrue)
AM_CONDITIONAL(CPU_PPC64, test x$cpu_ppc64 = xtrue)

AC_CONFIG_FILES([Makefile
		infinipath-psm.spec
		psmrevision.c
		ipath/pscrevision.c
		])
AC_OUTPUT
