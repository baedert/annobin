dnl file      : config/annocheck.m4
dnl copyright : Copyright (c) 2020 Theobroma Systems Design und Consulting GmbH
dnl license   : MIT; see accompanying LICENSE file
dnl
dnl ANNOCHECK
dnl
dnl
AC_DEFUN([ANNOCHECK], [

AC_ARG_WITH(
  [annocheck],
  [AC_HELP_STRING([--without-annocheck],[do not build annocheck])],
  [with_annocheck=no],
  [:])

AS_IF([test "x$with_annocheck" != xno],

[
LIBELF

# Check for rpmlib availability.
AC_CHECK_HEADER([rpm/rpmlib.h], ,[AC_MSG_ERROR(["Required header 'rpm/rpmlib.h' not found."])])
AC_CHECK_LIB([rpm], [rpmReadPackageFile], [RPMLIBS="-lrpm"], [AC_MSG_ERROR(["Required library 'rpm' not found.])])
AC_CHECK_LIB([rpmio], [rpmConfigDir], [RPMLIBS="$RPMLIBS -lrpmio"], [AC_MSG_ERROR(["Required library 'rpmio' not found.])])
AC_SUBST(RPMLIBS)
  
],
[:])

])
