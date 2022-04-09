# copyright : Copyright (c) 2017-2021 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file

# Configure the config.h
cdata = configuration_data()
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_STRING', meson.project_name() + ' ' + meson.project_version())
cdata.set_quoted('PACKAGE_TARNAME', 'annobin-plugin')

headers = [
  'memory.h',
  'stdint.h',
  'stdlib.h',
  'strings.h',
  'string.h',
  'sys/stat.h',
  'sys/types.h',
  'sys/wait.h',
  'unistd.h'
]
foreach header : headers
  cdata.set10('HAVE_' + header.underscorify().to_upper(), cxx.has_header(header))
endforeach

cdata.set10('HAVE_DEBUGINFOD', have_debuginfod)

# Our config.h
configure_file(output: 'config.h', configuration: cdata)


target_plugin = 'dummy.annobin.cc'
target = target_machine.cpu_family()
if target == 'aarch64'
  target_plugin = 'aarch64.annobin.cc'
elif target.startswith('ppc')
  target_plugin = 'powerpc.annobin.cc'
elif target == 'x86'
  target_plugin = 'i686.annobin.cc'
elif target == 'x86_64'
  target_plugin = 'x86_64.annobin.cc'
elif target == 's390' # TODO: Should this include s390x?
  target_plugin = 's390.annobin.cc'
endif


# We can't use shared_module() here since we need to force
# using GCC, even if the environment wants another compiler.
gxx = find_program('g++')
plugin_dev_path = run_command(gxx, '-print-file-name=plugin', check: true).stdout().strip()
gcc_plugin = custom_target(
  'annobin.so',
  input: ['annobin.cc', target_plugin],
  output: 'annobin.so',
  install: true,
  install_dir : plugin_dev_path,
  command: [
    gxx,
    '@INPUT@',
    '-g', '-fPIC', '-DPIC', '-shared', '-nostdlib',
    '-DHAVE_CONFIG_H',
    '-I' + join_paths(meson.current_build_dir(), '..'),
    '-I' + join_paths(plugin_dev_path, 'include'),
    '-o', '@OUTPUT@',
  ]
)
