## Copyright (C) 2017-2018 Red Hat.

## You should have received a copy of the GNU General Public License
## along with this program; see the file COPYING3.  If not see
## <http://www.gnu.org/licenses/>.

# Man pages
perl = find_program('perl')
pod2man = find_program('pod2man')
makeinfo = find_program('makeinfo')

manpages= [
  'annobin',
  'built-by',
  'check-abi',
  'hardened',
  'run-on-binaries',
  'annocheck'
]

foreach manpage : manpages
  # texi -> pod
  pod = custom_target(
    'annobin.texi to ' + manpage + '.pod',
    input: 'annobin.texi',
    output: manpage + '.pod',
    command: [
      perl, join_paths(meson.current_source_dir(), 'texi2pod.pl'),
      '-Dman', '-D' + manpage, '@INPUT@'
    ],
    capture: true,
  )
  # pod -> man
  man = custom_target(
    manpage + '.pod to ' + manpage + '.1',
    input: pod,
    output: manpage + '.1',
    command: [
      pod2man,
      '--center=RPM Development Tools',
      '--release=annobin-1',
      '--section=1',
      '@INPUT@'
    ],
    capture: true,
    install: true,
    install_dir: join_paths(get_option('mandir'), '1')
  )
endforeach

# annobin.info from annobin.texi
# TODO: Should just be a run_command()?
custom_target(
  'annobin.texi to annobin.info',
  input: 'annobin.texi',
  output: 'annobin.info',
  command: [makeinfo, '@INPUT@']
)
