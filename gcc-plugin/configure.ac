# file      : configure.ac
# copyright : Copyright (c) 2017-2019 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file.

AC_PREREQ(2.64)
AC_INIT([Binary Annotation plugin for gcc], 8.8,,[annobin-plugin])
AC_CANONICAL_SYSTEM
AC_USE_SYSTEM_EXTENSIONS
GCC_TOPLEV_SUBDIRS

# foreign: Don't require README, INSTALL, NEWS, etc.
# no-define: Don't define PACKAGE and VERSION.
# -Wall: Issue all automake warnings.
# -Wno-portability: Don't warn about constructs supported by GNU make.
#    (because GCC requires GNU make anyhow).
AM_INIT_AUTOMAKE([foreign no-dist no-define -Wall -Wno-portability])
AM_MAINTAINER_MODE

LT_INIT([disable-static])

AC_PROG_CXX
AC_SYS_LARGEFILE
ACX_PROG_CC_WARNING_OPTS([-Wall], [ac_annobin_warn_cflags])

# Check whether -static-libgcc is supported.
saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -static-libgcc"
AC_MSG_CHECKING([for -static-libgcc])
AC_LINK_IFELSE([AC_LANG_SOURCE([int main() {}])],
  [have_static_libgcc=yes],
  [have_static_libgcc=no])
AC_MSG_RESULT($have_static_libgcc); 
LDFLAGS="$saved_LDFLAGS"
# Need -Wc to get it through libtool.
if test "x$have_static_libgcc" = xyes; then
   ac_annobin_ldflags="-Wc,-static-libgcc"
fi
AC_SUBST(ac_annobin_ldflags)

if test x"$host_subdir" = x.; then
   gcc_build_dir=../gcc
else
   gcc_build_dir=../../$host_subdir/gcc
fi
AC_SUBST(gcc_build_dir)

# Used for constructing correct paths for offload compilers.
accel_dir_suffix=
real_target_noncanonical=${target_noncanonical}
if test x"$enable_as_accelerator_for" != x; then
  accel_dir_suffix=/accel/${target_noncanonical}
  real_target_noncanonical=${enable_as_accelerator_for}
fi
AC_SUBST(accel_dir_suffix)
AC_SUBST(real_target_noncanonical)

# Determine the target specific part of the plugin.
target_plugin="dummy.annobin.lo"
case ${target} in
  aarch64*-*-*)
    target_plugin="aarch64.annobin.lo"
    ;;
  powerpc*-*-*)
    target_plugin="powerpc.annobin.lo"
    ;;
  x86_64-*-*)
    target_plugin="x86_64.annobin.lo"
    ;;
  *)
    target_plugin="dummy.annobin.lo"
    ;;
esac
AC_SUBST(target_plugin)

# Determine what GCC version number to use in filesystem paths.
# GCC_BASE_VER

# GCC_ENABLE_PLUGINS
# AM_CONDITIONAL(ENABLE_PLUGIN, test $enable_plugin = yes)

AM_PROG_LIBTOOL

ACX_LT_HOST_FLAGS
AC_SUBST(target_noncanonical)
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_HEADER_SYS_WAIT
AC_CONFIG_FILES(Makefile)
AC_CONFIG_HEADERS(config.h)
AC_OUTPUT
