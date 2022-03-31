project(
  'annobin',
  ['c', 'cpp'],
  version: '9.0',
  meson_version: '>=0.59'
)

cxx = meson.get_compiler('cpp')

# Feature detection
debuginfod_lib = cxx.find_library('debuginfod', required: get_option('debuginfod'))
have_debuginfod = debuginfod_lib.found()

# directory variables
toplevel_incdir = include_directories('.')
gcc_plugin_incdir = include_directories('gcc-plugin/')



# Subdirs
subdir('gcc-plugin')

if get_option('clang-plugin')
  subdir('clang-plugin')
endif
if get_option('llvm-plugin')
  subdir('llvm-plugin')
endif
if get_option('annocheck')
  subdir('annocheck')
endif
subdir('tests')
if get_option('docs')
  subdir('doc')
endif


# Summary
summary('C++ Compiler', meson.get_compiler('cpp').get_id(), section: 'Toolchain')
summary('C++ Linker', meson.get_compiler('cpp').get_linker_id(), section: 'Toolchain')

summary('Build LLVM plugin', get_option('llvm-plugin'))
summary('Build Clang plugin', get_option('clang-plugin'))
summary('Build annocheck', get_option('annocheck'))
summary('debuginfod support', have_debuginfod)
