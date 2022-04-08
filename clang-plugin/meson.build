

# No shared_module here either, we need to force clang.
clang = find_program('clang++')
search_dirs = run_command(clang , '--print-search-dirs', check: true).stdout().strip()
install_dir = search_dirs.split('\n')[1].split(':')[1].replace('=', '').strip()

clang_plugin = custom_target(
  'annobin-for-clang.so',
  input: 'annobin.cpp',
  output: 'annobin-for-clang.so',
  install: true,
  install_dir: install_dir,
  command: [
    clang,
    '@INPUT@',
    '-I' + join_paths(meson.current_source_dir(), '..'),
    '-lLLVM',
    '-lclang-cpp', # TODO: Is this correct?
    '-o', '@OUTPUT@',

    # TODO: The following should probably only come from the env
    '-D_FORTIFY_SOURCE=2',
    '-D_GLIBCXX_ASSERTIONS',
    '-shared',
    '-fPIC',
    '-Wall',
    '-O2',
    '-flto',
    '-g', '-grecord-gcc-switches',
    '-Wl,--build-id=md5',
    '-Wl,-z,now',
    '-D_GNU_SOURCE',
    '-D__STDC_CONSTANT_MACROS',
    '-D__STDC_FORMAT_MACROS',
    '-D__STDC_LIMIT_MACROS',
  ]
)
