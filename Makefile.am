## Copyright (C) 2017-2018 Red Hat.

## You should have received a copy of the GNU General Public License v3
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

if COND_TESTS
  MAYBE_TESTS = tests
endif

if COND_ANNOCHECK
  MAYBE_ANNOCHECK = annocheck
endif

SUBDIRS = plugin scripts doc $(MAYBE_TESTS) $(MAYBE_ANNOCHECK)
dist_doc_DATA = LICENSE COPYING3
ACLOCAL_AMFLAGS = -I config
