## Copyright (C) 2017-2020 Red Hat

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in.

TESTS=\
      abi-test \
      active-checks-test \
      assembler-gap-test \
      atexit-test \
      compile-test \
      fortify-test \
      function-sections-test \
      gaps-test \
      glibc-notes-test \
      hardening-fail-test \
      hardening-test \
      instrumentation-test \
      ldconfig-test \
      lto-test \
      missing-notes-test \
      objcopy-test \
      property-note-test \
      section-size-test \
      stat-test \
      unicode-test

if HAVE_DEBUGINFOD
TESTS += debuginfod-test
endif

if COND_ANNOCHECK
TESTS += libannocheck-test
endif

# FIXME: Add a test for merging notes...
# FIXME: Add a test for examining archives...
# FIXME: Add a test for examining rpms...
# FIXME: Add a test for examining repositories...
