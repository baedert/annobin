# copyright : Copyright (c) 2017-2021 Red Hat
# license   : GNU GPL v3; see accompanying LICENSE file

elf_lib = cxx.find_library('elf')
iberty_lib = cxx.find_library('iberty')
dw_lib = cxx.find_library('dw')
rpm_lib = cxx.find_library('rpm')
rpmio_lib = cxx.find_library('rpmio')
rpmio_lib = cxx.find_library('rpmio')

annocheck = executable(
  'annocheck',
  files([
    'annocheck.c',
    'timing.c',
    'size.c',
    'notes.c',
    'hardened.c',
    'built-by.c',
  ]),
  dependencies: [
    elf_lib,
    iberty_lib,
    dw_lib,
    rpm_lib,
    rpmio_lib,
    debuginfod_lib,
  ],
  include_directories: [
    toplevel_incdir,
    gcc_plugin_incdir,
  ],
)

libannocheck = static_library(
  'annocheck',
  files([
    'annocheck.c',
    'hardened.c'
  ]),
  dependencies: [
    elf_lib,
    iberty_lib,
    dw_lib,
    rpm_lib,
    rpmio_lib,
    debuginfod_lib,
  ],
  c_args: [
    '-DLIBANNOCHECK=1',
  ],
  include_directories: [
    toplevel_incdir,
    gcc_plugin_incdir,
  ]
)
