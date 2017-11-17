dnl file      : m4/libcutl.m4
dnl copyright : Copyright (c) 2009-2015 Code Synthesis Tools CC
dnl license   : MIT; see accompanying LICENSE file
dnl
dnl LIBCUTL([ACTION-IF-FOUND[, ACTION-IF-NOT-FOUND]])
dnl
dnl
AC_DEFUN([LIBCUTL], [
libcutl_found=no

AC_ARG_WITH(
  [libcutl],
  [AC_HELP_STRING([--with-libcutl=DIR],[location of libcutl build directory])],
  [libcutl_dir=${withval}],
  [libcutl_dir=])

AC_MSG_CHECKING([for libcutl])

# If libcutl_dir was given, add the necessary preprocessor and linker flags.
#
if test x"$libcutl_dir" != x; then
  save_CPPFLAGS="$CPPFLAGS"
  save_LDFLAGS="$LDFLAGS"

  AS_SET_CATFILE([abs_libcutl_dir], [$ac_pwd], [$libcutl_dir])

  CPPFLAGS="$CPPFLAGS -I$abs_libcutl_dir"
  LDFLAGS="$LDFLAGS -L$abs_libcutl_dir/cutl"
fi

save_LIBS="$LIBS"
LIBS="-lcutl $LIBS"

CXX_LIBTOOL_LINK_IFELSE([
AC_LANG_SOURCE([
#include <cutl/exception.hxx>

void
f ()
{
}

const char*
g ()
{
  try
  {
    f ();
  }
  catch (const cutl::exception& e)
  {
    return e.what ();
  }
  return 0;
}

int
main ()
{
  const char* m (g ());
  return m != 0;
}
])],
[libcutl_found=yes])

if test x"$libcutl_found" = xno; then
  LIBS="$save_LIBS"

  if test x"$libcutl_dir" != x; then
    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
  fi
fi

if test x"$libcutl_found" = xyes; then
  AC_MSG_RESULT([yes])
  $1
else
  AC_MSG_RESULT([no])
  $2
fi
])dnl
