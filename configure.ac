# file      : configure.ac
# copyright : Copyright (c) 2017-2020 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file.

AC_PREREQ(2.64)
AC_INIT([Binary Annotations], 9.0,,[annobin-plugin])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_SRCDIR([annobin-global.h])

AC_CANONICAL_SYSTEM
AC_USE_SYSTEM_EXTENSIONS
GCC_TOPLEV_SUBDIRS

# foreign: Don't require README, INSTALL, NEWS, etc.
# no-define: Don't define PACKAGE and VERSION.
# -Wall: Issue all automake warnings.
# -Wno-portability: Don't warn about constructs supported by GNU make.
#    (because GCC requires GNU make anyhow).
AM_INIT_AUTOMAKE([foreign no-dist no-define -Wall -Wno-portability])

AC_PROG_CXX
AC_LANG(C++)

LT_INIT([disable-static])
LT_OUTPUT

# Determine the target specific part of the plugin.
target_plugin="dummy.annobin.lo"
case ${target} in
  aarch64*-*-*)
    target_plugin="aarch64.annobin.lo"
    ;;
  powerpc*-*-*)
    target_plugin="powerpc.annobin.lo"
    ;;
  *86-*-*)
    target_plugin="i686.annobin.lo"
    ;;
  x86_64-*-*)
    target_plugin="x86_64.annobin.lo"
    ;;
  s390*-*-*)
    target_plugin="s390.annobin.lo"
    ;;
  *)
    target_plugin="dummy.annobin.lo"
    ;;
esac
AC_SUBST(target_plugin)

# Use an alternative GMP if requested.
GMP

# Determine if we should build annocheck.
BUILD_ANNOCHECK
# Determine if we should build the clang-plugin
BUILD_CLANG_PLUGIN
# Determine if we should build the gcc-plugin
BUILD_GCC_PLUGIN
# Determine if we should build the llvm-plugin
BUILD_LLVM_PLUGIN
# Determine if we should build the documentation
BUILD_DOCS

AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
AC_ARG_ENABLE(maintainer-mode,
[AS_HELP_STRING([--enable-maintainer-mode],
		[enable make rules and dependencies not useful
		 (and sometimes confusing) to the casual installer])],
      USE_MAINTAINER_MODE=$enableval,
      USE_MAINTAINER_MODE=no)
AC_MSG_RESULT($USE_MAINTAINER_MODE)
AC_SUBST(MAINTAINER_MODE_TRUE)
AC_SUBST(MAINTAINER_MODE_FALSE)
if test "$USE_MAINTAINER_MODE" = yes; then
  MAINTAINER_MODE_TRUE=
  MAINTAINER_MODE_FALSE='#'
else
  MAINTAINER_MODE_TRUE='#'
  MAINTAINER_MODE_FALSE=
fi	
MAINT=$MAINTAINER_MODE_TRUE
AC_SUBST(MAINT)dnl


if test "x$with_gcc_plugin" != xno; then

  # We need GCC plugin support.
  GCC_PLUGIN

  if test x$gcc_plugin_dir != xno; then
    AC_DEFINE([ANNOBIN_GCC_PLUGIN_DIR], [1], [Plugin is in GCC plugin directory.])
    plugindir=$gcc_plugin_dir
  # Otherwise, try to figure out a relative path from the driver (bindir) to
  # the plugin (libexecdir).
  else
    # Get the expanded values for bindir and libexecdir.
    if test x$exec_prefix = xNONE; then
      if test x$prefix = xNONE; then
        e_exec_prefix=$ac_default_prefix
       else
        e_exec_prefix=$prefix
      fi
    else
      e_exec_prefix=$exec_prefix
    fi

    e_pkglibexecdir=`echo "$libexecdir/$PACKAGE_NAME" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`
    e_bindir=`echo "$bindir" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`

    # Try to find a common prefix.
    common=$e_bindir
    rel_plugindir=$e_pkglibexecdir

    while test x$common != x/; do
      suffix=`echo "$e_pkglibexecdir" | sed "s?^$common/*??"`
      if test "x$suffix" != "x$e_pkglibexecdir"; then
        # Replace all the remaining directories in bindir with ".."
        # and append the suffix.
        rel_plugindir=`echo "$e_bindir" | sed "s?^$common/*??"`
        rel_plugindir=`echo "$rel_plugindir" | sed ['s?[^/][^/]*?..?g']`
        if test "x$rel_plugindir" != x -a "x$suffix" != x; then
          rel_plugindir="$rel_plugindir/$suffix"
        else
          rel_plugindir="$rel_plugindir$suffix"
        fi
        break
      fi
      common=`AS_DIRNAME(["$common"])`
    done
    AC_DEFINE_UNQUOTED([ANNOBIN_PLUGIN_PATH], ["$rel_plugindir"], [Plugin path.])
    plugindir='$(pkglibexecdir)'
  fi

  AC_SUBST([plugindir])
fi

# Check for debuginfod availability
DEBUGINFOD

DISABLE_RPATH

ACX_LT_HOST_FLAGS
AC_SUBST(target_noncanonical)
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_HEADER_SYS_WAIT

AM_CONDITIONAL([COND_DOCS],       [test "$with_docs" != no])
AM_CONDITIONAL([COND_TESTS],      [test "$with_tests" != no])
AM_CONDITIONAL([COND_ANNOCHECK],  [test "$with_annocheck" != no])
AM_CONDITIONAL([COND_CLANG],      [test "$with_clang_plugin" == yes])
AM_CONDITIONAL([COND_GCC_PLUGIN], [test "$with_gcc_plugin" != no])
AM_CONDITIONAL([COND_LLVM],       [test "$with_llvm_plugin" == yes])

AC_CONFIG_FILES(Makefile)

if test "$with_annocheck" != no -o test "$with_gcc_plugin" != no; then
  AC_CONFIG_HEADERS(gcc-plugin/config.h)
fi
if test "$with_docs" != no; then
  AC_CONFIG_FILES(doc/Makefile)
fi
if test "$with_tests" != no; then
  AC_CONFIG_FILES(tests/Makefile)
fi
if test "$with_annocheck" != no; then
  AC_CONFIG_FILES(annocheck/Makefile)
fi
if test "$with_clang" = yes; then
  AC_CONFIG_FILES(clang-plugin/Makefile)
fi
if test "$with_gcc_plugin" != no; then
  AC_CONFIG_FILES(gcc-plugin/Makefile)
fi
if test "$with_llvm" = yes; then
  AC_CONFIG_FILES(llvm-plugin/Makefile)
fi

AC_OUTPUT
