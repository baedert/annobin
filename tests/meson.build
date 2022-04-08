## Copyright (C) 2017-2020 Red Hat

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

tests = [
  'abi',
  'active-checks',
  'compile',
  'function-sections',
  'hardening-fail',
  'hardening',
  'instrumentation',
  'ldconfig',
  'missing-notes',
  'property-note',
  'section-size',
]

env = {
  'srcdir' : meson.current_source_dir(),
  'PLUGIN' : gcc_plugin.full_path(),
  'TOP_BUILDDIR' : join_paths(meson.current_build_dir(), '..'),
}

if get_option('annocheck')
  env += {
    'ANNOCHECK' : annocheck.full_path(),
    'LIBANNOCHECKDIR' : '../annocheck/',
  }

  tests += [
    'atexit',
    'fortify',
    'assembler-gap',
    'libannocheck',
    'glibc-notes',
    'lto',
    'objcopy',
    'unicode',
    'stat',
    'gaps',
  ]

  if have_debuginfod
    tests += 'debuginfod'
  endif
endif

if get_option('llvm-plugin')
  env += {'LLVM_PLUGIN' : llvm_plugin.full_path()}
  tests += ['llvm']
endif

if get_option('clang-plugin')
  env += {'CLANG_PLUGIN' : clang_plugin.full_path()}
  tests += ['clang']
endif

foreach testname : tests
  prog = find_program(testname + '-test')
  test(testname, prog, env: env)
endforeach
