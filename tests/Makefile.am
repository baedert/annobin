## Copyright (C) 2017-2019 Red Hat

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

TESTS=compile-test \
      hardening-test \
      hardening-fail-test \
      missing-notes-test \
      active-checks-test \
      abi-test \
      function-sections-test \
      assembler-gap-test \
      dynamic-notes-test \
      instrumentation-test \
      section-size-test

if HAVE_DEBUGINFOD
TESTS += debuginfod-test
endif

XFAIL_TESTS=hardening-fail-test \
      missing-notes-test \
      active-checks-test \
      property-note-test


# FIXME: Add a test for merging notes...
# FIXME: Add a test for examining archives...
# FIXME: Add a test for examining rpms...
# FIXME: Add a test for examining repositories...
