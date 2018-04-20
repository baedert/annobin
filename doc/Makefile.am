## Copyright (C) 2017-2018 Red Hat.

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

# Extra documentation.
dist_doc_DATA = annotation.proposal.txt

# Info file generation.
info_TEXINFOS = annobin.texi
annobin_TEXINFOS = fdl.texi

# Man page creation.
man_MANS = annobin.1 built-by.1 check-abi.1 hardened.1 run-on-binaries.1

MANCONF = -Dman

TEXI2POD = perl $(srcdir)/texi2pod.pl $(AM_MAKEINFOFLAGS)

POD2MAN = pod2man --center="RPM Development Tools" --release="annobin-1" --section=1

annobin.1:	$(srcdir)/$(info_TEXINFOS)
	touch $@
	-$(TEXI2POD) $(MANCONF) -Dannobin < $(srcdir)/$(info_TEXINFOS) > annobin.pod
	-($(POD2MAN) annobin.pod | sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	rm -f annobin.pod

built-by.1:	$(srcdir)/$(info_TEXINFOS)
	touch $@
	-$(TEXI2POD) $(MANCONF) -Dbuilt-by < $(srcdir)/$(info_TEXINFOS) > built-by.pod
	-($(POD2MAN) built-by.pod | sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	rm -f built-by.pod

check-abi.1:	$(srcdir)/$(info_TEXINFOS)
	touch $@
	-$(TEXI2POD) $(MANCONF) -Dcheck-abi < $(srcdir)/$(info_TEXINFOS) > check-abi.pod
	-($(POD2MAN) check-abi.pod | sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	rm -f check-abi.pod

hardened.1:	$(srcdir)/$(info_TEXINFOS)
	touch $@
	-$(TEXI2POD) $(MANCONF) -Dhardened < $(srcdir)/$(info_TEXINFOS) > hardened.pod
	-($(POD2MAN) hardened.pod | sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	rm -f hardened.pod

run-on-binaries.1:	$(srcdir)/$(info_TEXINFOS)
	touch $@
	-$(TEXI2POD) $(MANCONF) -Drun-on-binaries < $(srcdir)/$(info_TEXINFOS) > run-on-binaries.pod
	-($(POD2MAN) run-on-binaries.pod | sed -e '/^.if n .na/d' > $@.T$$$$ && \
		mv -f $@.T$$$$ $@) || (rm -f $@.T$$$$ && exit 1)
	rm -f run-on-binaries.pod
