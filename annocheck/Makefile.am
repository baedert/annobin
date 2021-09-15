# copyright : Copyright (c) 2017-2021 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file

AM_CPPFLAGS = -I'$(top_builddir)' -I'$(top_srcdir)'
AUTOMAKE_OPTIONS = no-dependencies


bin_PROGRAMS = annocheck
annocheck_SOURCES = annocheck.c timing.c size.c notes.c hardened.c built-by.c annocheck.h ../annobin-global.h
annocheck_LDADD   = -lelf -ldw $(RPMLIBS) -liberty $(LIBDEBUGINFOD)

