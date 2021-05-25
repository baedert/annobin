# copyright : Copyright (c) 2017-2021 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file

plugindir = @plugindir@

plugin_LTLIBRARIES = annobin.la

AM_CPPFLAGS = -I'$(top_builddir)' -I'$(top_srcdir)'
AUTOMAKE_OPTIONS = no-dependencies

annobin_la_SOURCES = annobin.cc
EXTRA_annobin_la_SOURCES = aarch64.annobin.cc arm.annobin.cc dummy.annobin.cc powerpc.annobin.cc s390.annobin.cc x86_64.annobin.cc i686.annobin.cc riscv.annobin.cc
annobin_la_LIBADD = @target_plugin@
annobin_la_DEPENDENCIES = @target_plugin@

annobin_la_LDFLAGS = -module
AM_CXXFLAGS =

annobin_la_LINK = $(LIBTOOL) --tag=CXX $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CXXLD) $(AM_CXXFLAGS) $(CXXFLAGS) \
	$(annobin_la_LDFLAGS) $(LTLDFLAGS) -o $@

# Remove the .la file from the final install.
#
install-data-hook:
	rm -f '$(DESTDIR)$(plugindir)/annobin.la'
