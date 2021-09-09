dnl file      : m4/gcc-plugin.m4
dnl copyright : Copyright (c) 2009-2015 Code Synthesis Tools CC
dnl license   : GNU GPL v3; see accompanying LICENSE file
dnl
dnl GCC_PLUGIN
dnl
AC_DEFUN([GCC_PLUGIN], [
static_plugin=$enable_static

AC_ARG_WITH(
  [gcc-plugin-dir],
  [AC_HELP_STRING([--with-gcc-plugin-dir=DIR], [install annobin plugin into the GCC plugin directory])],
  [gcc_plugin_dir=$withval],
  [gcc_plugin_dir=test])

if test x"$static_plugin" = xyes; then
  gcc_plugin_dir=no
else
  if test x"$cross_compiling" = xyes; then
    AC_MSG_CHECKING([whether to install into default GCC plugin dir])
    case $gcc_plugin_dir in
       yes)
         AC_MSG_ERROR([GCC plugin directory must be specified explicitly when cross-compiling])
         ;;
       test)
         # We cannot detect the plugin directory since there is no way to
         # run host GCC. So assume no.
         #
         gcc_plugin_dir=no
         ;;
       no)
         ;;
       *)
         # Add the include/ subdirectory of the plugin dir to CPPFLAGS since
         # the plugin headers are normally installed there.
         #
         CPPFLAGS="$CPPFLAGS -I$gcc_plugin_dir/include"
         ;;
    esac
  else
    if test x"$GXX" != xyes; then
      AC_MSG_ERROR([$CXX is not a GNU C++ compiler])
    fi

    AC_MSG_CHECKING([whether $CXX supports plugins])
    dir=`$CXX -print-file-name=plugin 2>/dev/null`

    if test x"$dir" = xplugin; then
      dir=`$CXX -print-file-name=.`/plugin
    fi
    AC_MSG_RESULT([yes])

    CPPFLAGS="$CPPFLAGS -I$dir/include"

    AC_MSG_CHECKING([whether to install annobin plugin into default GCC plugin directory])
    case $gcc_plugin_dir in
       yes)
         gcc_plugin_dir=$dir
         ;;
       test)
         # Only install into the GCC plugin dir if both GCC and annobin are
         # installed into the same prefix. Testing whether $libdir or
         # $libexecdir is a prefix of the GCC plugin dir is a good
         # approximation.
         #

         # Get the expanded values for libdir and libexecdir.
         #
         if test x$exec_prefix = xNONE; then
           if test x$prefix = xNONE; then
             e_exec_prefix=$ac_default_prefix
           else
             e_exec_prefix=$prefix
           fi
         else
           e_exec_prefix=$exec_prefix
         fi

         # On some systems GCC is installed into $prefix/lib even though
         # libdir is $prefix/lib64 and libexecdir is $prefix/libexec. To
         # cover this special case, we will also test $prefix/lib.
         #
         e_libdir=`echo "$libdir" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`
         e_libexecdir=`echo "$libexecdir" | sed "s?^\\\${exec_prefix}?$e_exec_prefix?"`
         e_libdir32=$e_exec_prefix/lib

         # See if either one of them is a prefix of the plugin dir.
         #
         ld_suffix=`echo "$dir" | sed "s?^$e_libdir/*??"`
         led_suffix=`echo "$dir" | sed "s?^$e_libexecdir/*??"`
         l32d_suffix=`echo "$dir" | sed "s?^$e_libdir32/*??"`

         if test x$ld_suffix != x$dir -o x$led_suffix != x$dir -o x$l32d_suffix != x$dir; then
           gcc_plugin_dir=$dir
         else
           gcc_plugin_dir=no
         fi
         ;;
       *)
         # Add the include/ subdirectory of the plugin dir to CPPFLAGS since
         # the plugin headers are normally installed there.
         #
         CPPFLAGS="$CPPFLAGS -I$gcc_plugin_dir/include"
         ;;
    esac
  fi

  if test x"$gcc_plugin_dir" != xno; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
  fi
fi

AC_MSG_CHECKING([for GCC plugin headers])

CXX_LIBTOOL_LINK_IFELSE([
AC_LANG_SOURCE([
#include <bversion.h>

#ifndef BUILDING_GCC_MAJOR
#  error no BUILDING_GCC_MAJOR in bversion.h
#endif

int main () {}
])],
[gcc_plugin_headers=yes],
[gcc_plugin_headers=no])

if test x"$gcc_plugin_headers" = xyes; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([GCC plugin headers not found; consider installing GCC plugin development package])
fi
])dnl
