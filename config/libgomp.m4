dnl file      : m4/libgmp.m4
dnl copyright : Copyright (c) 2020 Theobroma Systems Design und Consulting GmbH
dnl license   : MIT; see accompanying LICENSE file
dnl
dnl GMP
dnl
dnl
AC_DEFUN([GMP], [

AC_ARG_WITH(
  [gmp],
  [AC_HELP_STRING([--with-gmp=PATH],[specify PATH to gmp])],
  [:],
  [with_gmp=no])

if test "x$with_gmp" != xno; then
  LDFLAGS="$LDFLAGS -L$with_gmp/lib"
  CPPFLAGS="$CPPFLAGS -I$with_gmp/include"
fi
])
