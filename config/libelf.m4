dnl file      : config/libelf.m4
dnl copyright : Copyright (c) 2020 Theobroma Systems Design und Consulting GmbH
dnl license   : MIT; see accompanying LICENSE file
dnl
dnl LIBELF
dnl
dnl
AC_DEFUN([LIBELF], [
libelf_found=no

AC_ARG_WITH(
  [libelf],
  [AC_HELP_STRING([--without-libelf],[remove libelf dependency])],
  [with_libelf=no],
  [:])

AC_MSG_CHECKING([for libelf])

AS_IF([test "x$with_libelf" != xno],
  [AC_CHECK_LIB([elf], [elf_begin], [libelf_found=yes], [AC_MSG_FAILURE([libelf test failed (--without-libelf to disable)])])],
  [:])
])
