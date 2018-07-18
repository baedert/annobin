# copyright : Copyright (c) 2017-2018 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file

AM_CPPFLAGS = -I'$(top_builddir)' -I'$(top_srcdir)'
AUTOMAKE_OPTIONS = no-dependencies


bin_PROGRAMS = annocheck
annocheck_SOURCES = annocheck.c hardened.c built-by.c annocheck.h
annocheck_LDADD = -lelf -ldw -lrpm -lrpmio -liberty
annocheck_CFLAGS = -O2 -ansi -g -Wall -Werror

