#!/bin/bash

# Script to run another script/program on the executables inside a given file.
#
# Created by Nick Clifton.
# Copyright (c) 2018 Red Hat.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
# option) any later version.

# It is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Usage:
#   run-on-binaries-in [options] program [options-for-the-program] file(s)
#
# This script does not handle directories.  This is deliberate.
# It is intended that if recursion is needed then it will be
# invoked from find, like this:
#
#   find . -name "*.rpm" -exec run-on-binaries-in.sh <script-to-run> {} \;


version=1.0

help ()
{
  # The following exec goop is so that we don't have to manually
  # redirect every message to stderr in this function.
  exec 4>&1    # save stdout fd to fd #4
  exec 1>&2    # redirect stdout to stderr

  cat <<__EOM__

This is a shell script to run another script/program on one or more binary
files.  If the file(s) specified are archives of some kind (including rpms)
then the script/program is run on the binary excecutables inside the archive.

Usage: $prog {options} {program} {options-for-the-program} files(s)

  {options} are:
  -h        --help            Display this information and then exits.
  -v        --version         Report the version number of this script.
  -V        --verbose         Report on progress.  Repeat for more verbosity.
  -q        --quiet           Do not include the script name in the output.
  -i        --ignore          Silently ignore files that are not exectuables or archives.
  -p=<NAME> --prefix=<NAME>   Prefix normal output with this string.
  -t=<PATH> --tmpdir=<PATH>   Temporary directory to use when opening archives.
  --                          Stop accumulating options.

Examples:

  $prog hardened.sh foo.rpm
                              Runs the hardened.sh script on the executable
                              files inside foo.rpm.

  $prog check-abi.sh -v fred.tar
                              Runs the check-abi.sh script on the file
                              fred.tar, passing the -v option to check-abi.sh
                              as it does so.      

  $prog -V readelf -a *
                              Runs the readelf program, with the -a option on
                              every file in the current directory.  Describes
                              what is being done as it works.

  $prog -v -- -fred -a jim -b bert -- -c harry
                              Runs the script "-fred" on the files jim, bert,
                              "-c" and harry.  Passes the options "-a" and
                              "-b" to the script (even when run on jim).
                              Reports the version of this script as well.

__EOM__
  exec 1>&4   # Copy stdout fd back from temporary save fd, #4
}

main ()
{
    init
    
    parse_args ${1+"$@"}

    if [ $failed -eq 0 ];
    then
	# Use quotes when accessing files in order to preserve
	# any spaces that might be in the directory name.
	script="${files[0]}";

	if ! [ -a "$script" ]
	then
	    fail "$script: script not found"
	elif  ! [ -x "$script" ]
	then
	    fail "$script: script not executable"
	else
	    run_script_on_files
	fi
    fi

    if [ $failed -ne 0 ];
    then
	exit 1
    else
	exit 0
    fi
}

report ()
{
    if [ $quiet -eq 0 ];
    then
	echo -n $prog": "
    fi
    
    echo ${1+"$@"}
}

report_n ()
{
    if [ $quiet -eq 0 ];
    then
	echo -n $prog": "
    fi
    
    echo -n ${1+"$@"}
}

ice ()
{
    report "Internal error: " ${1+"$@"}
    exit 1
}

fail ()
{
    report "Failure:" ${1+"$@"}
    failed=1
}

verbose ()
{
    if [ $verbose -ne 0 ]
    then
	report ${1+"$@"}
    fi
}

# Initialise global variables.
init ()
{
    files[0]="";  
    # num_files is the number of files to be scanned.
    # files[0] is the script to run on the files.
    num_files=0;

    script=""
    script_opts="";

    prog_opts="-i"

    prefix=""
    
    tmpdir=/dev/shm

    failed=0
    verbose=0
    ignore=0
    quiet=0
}

# Parse our command line
parse_args ()
{
    abs_prog=$0;
    prog=`basename $abs_prog`;

    # Locate any additional command line switches
    # Likewise accumulate non-switches to the files list.
    while [ $# -gt 0 ]
    do
	optname="`echo $1 | sed 's,=.*,,'`"
	optarg="`echo $1 | sed 's,^[^=]*=,,'`"
	case "$optname" in
	    -v | --version)
		report "version: $version"
		;;
	    -h | --help)
		help
		exit 0
		;;
	    -q | --quiet)
		quiet=1;
		prog_opts="$prog_opts -q"
		;;
	    -V | --verbose)
		if [ $verbose -eq 1 ];
		then
		    # This has the effect of cancelling out the prog_opts="-i"
		    # in the init function, so that recursive invocations of this
		    # script will complain about unrecognised file types.
		    if [ $quiet -eq 0 ];
		    then
			prog_opts="-V"
		    else
			prog_opts="-V -q"
		    fi
		else
		    verbose=1;
		    prog_opts="$prog_opts -V"
		fi
		;;
	    -i | --ignore)
		ignore=1
		;;
	    -t | --tmpdir)
		if test "x$optarg" = "x" ;
		then
		    fail "-t option must have a directory name attached to it with an equals sign"
		else
		    tmpdir="$optarg"
		fi
		;;
	    -p | --prefix)
		if test "x$optarg" = "x" ;
		then
		    fail "-p option must have a directory name attached to it with an equals sign"
		else
		    prefix="$optarg"
		fi
		;;
	    --)
		shift
		break;
		;;
	    --*)
		fail "unrecognised option: $1"
		help
		;;
	    *)
		files[$num_files]="$1";
		let "num_files++"
		# After we have seen the first non-option we stop
		# accumulating options for this script and instead
		# start accumulating options for the script to be
		# run.
		shift
		break;
		;;
	esac
	shift
    done

    # Accumulate any remaining arguments separating out the arguments
    # for the script from the names of the files to scan.
    while [ $# -gt 0 ]
    do
	optname="`echo $1 | sed 's,=.*,,'`"
	optarg="`echo $1 | sed 's,^[^=]*=,,'`"
	case "$optname" in
	    --)
		shift
		break;
		;;
	    -*)
		script_opts="$script_opts $1"
		;;
	    *)
		files[$num_files]="$1";
		let "num_files++"
		;;
	esac
	shift
    done

    # Accumulate any remaining arguments without processing them.
    while [ $# -gt 0 ]
    do
	files[$num_files]="$1";
	let "num_files++";
	shift
    done

    if [ $num_files -gt 1 ];
    then
	# Remember that we are counting from zero not one.
	let "num_files--"
    else
	fail "Must specify a script and at least one file to scan."
    fi
}

run_script_on_files ()
{
    local i

    i=1;
    while [ $i -le $num_files ]
    do
	run_on_file i
	let "i++"
    done
}

# syntax: run <command> [<args>]
#  If being verbose report the command being run, and
#   the directory in which it is run.
run ()
{
  local where

  if test "x$1" = "x" ;
  then
    fail "run() called without an argument."
  fi

  verbose "  Running: ${1+$@}"

  ${1+$@}
}

run_on_file ()
{
    local file

    # Paranoia checks - the user should never encounter these.
    if test "x$1" = "x" ;
    then
	ice "scan_file called without an argument"
    fi
    if test "x$2" != "x" ;
    then
	ice "scan_file called with too many arguments"
    fi

    # Use quotes when accessing files in order to preserve
    # any spaces that might be in the directory name.
    file="${files[$1]}";

    # Catch names that start with a dash - they might confuse readelf
    if test "x${file:0:1}" = "x-" ;
    then
	file="./$file"
    fi

    if ! [ -a "$file" ]
    then
	fail "$file: file not found"
	return
    fi

    if ! [ -r "$file" ]
    then
	if [ $ignore -eq 0 ];
	then
	    fail "$file: not readable"
	fi
	return
    fi

    if [ -d "$file" ]
    then
	if [ $ignore -eq 0 ];
	then
	    if [ $num_files -gt 1 ];
	    then
		verbose "$file: skipping - it is a directory"
	    else
		report "$file: skipping - it is a directory"
	    fi
	fi
	return
    fi

    if ! [ -f "$file" ]
    then
	if [ $ignore -eq 0 ];
	then
	    fail "$file: not an ordinary file"
	fi
	return
    fi

    file_type=`file -b $file`
    case "$file_type" in
	*"ELF "*)
            verbose "$file: RPM format."
	    if test "x$prefix" != "x" ;
	    then
		report_n "$prefix: "
	    fi
	    run $script $script_opts $file
	    return
	    ;;
	"RPM "*)
            verbose "$file: RPM format."
	    ;;
	*" cpio "*)
            verbose "$file: CPIO format."
	    ;;
	*"tar "*)
	    verbose "$file: TAR archive."
	    ;;
	*"XZ compressed data"*)
	    verbose "$file: contains xz compressed data"
	    ;;
	*"gzip compressed data"*)
	    verbose "$file: contains gzip compressed data"
	    ;;
	*"shell script"* | *"ASCII text"*)
	    if [ $ignore -eq 0 ];
	    then
		fail "$file: test/scripts cannot be scanned."
	    fi
	    return
	    ;;
        *)
	    if [ $ignore -eq 0 ];
	    then
		fail "$file: Unsupported file type: $file_type"
	    fi
	    return
	    ;;
    esac
    
    # We now know that we will need a temporary directory
    # so create one, and create paths to the file and scripts.
    if test "x${file:0:1}" = "x/" ;
    then
	abs_file=$file
    else
	abs_file="$PWD/$file"
    fi
    
    if test "x${abs_prog:0:1}" != "x/" ;
    then
	abs_prog="$PWD/$abs_prog"
    fi

    if test "x${script:0:1}" = "x/" ;
    then
	abs_script=$script
    else
	abs_script="$PWD/$script"
    fi
    
    tmp_root=$tmpdir/delme.run.on.binary
    run mkdir -p "$tmp_root/$file"

    verbose "  Changing to directory: $tmp_root/$file"
    pushd "$tmp_root/$file" > /dev/null
    if [ $? != 0 ];
    then
	fail "Unable to change to temporary directory: $tmp_root/$file"
	return
    fi
			 
    # Run the file type switch again, although this time we do not need to check
    # for unrecognised types.  Note since are transforming the file we reinvoke
    # the run-on-binaries script on the decoded contents.  This allows for archives
    # that contain other archives, and so on.  We pass the -i option to the invoked
    # script so that it will not complain about unrecognised files in the decoded
    # archive.  We also pass the -t option to ensure that any sub-archives are
    # extracted into a unique directory tree.

    case "$file_type" in
	"RPM "*)
	    # The output redirect confuses the run function...
	    verbose "  Running: rpm2cpio $abs_file > delme.cpio"
	    rpm2cpio $abs_file > delme.cpio
	    if [ $? != 0 ];
	    then
		fail "$file: Unable to extract from rpm archive"
	    else
		# Save time - run cpio now.
		run cpio --quiet --extract --make-directories --file delme.cpio
		if [ $? != 0 ];
		then
		    fail "$file: Unable to extract from cpio archive"
		fi
		run rm -f delme.cpio
	    fi
	    ;;

	*" cpio "*)
	    run cpio --quiet --extract --make-directories --file=$abs_file
	    if [ $? != 0 ];
	    then
		fail "$file: Unable to extract from cpio archive"
	    fi
	    ;;

	*"tar "*)
	    run tar --extract --file=$abs_file
	    if [ $? != 0 ];
	    then
		fail "$file: Unable to extract from tar file"
	    fi
	    ;;

	*"XZ compressed data"*)
	    run cp $abs_file `basename $file`
	    run xz --quiet --decompress `basename $file`
	    if [ $? != 0 ];
	    then
		fail "$file: Unable to decompress"
	    fi
	    ;;

	*"gzip compressed data"*)
	    run cp $abs_file `basename $file`
	    run gzip --quiet --decompress `basename $file`
	    if [ $? != 0 ];
	    then
		fail "$file: Unable to decompress"
	    fi
	    ;;
     esac

    if [ $failed -eq 0 ];
    then
	# Now scan the file(s) created in the previous step.
	run find . -type f -execdir $abs_prog $prog_opts -t=$tmp_root/$file -p=$file $abs_script $script_opts {} +
    fi

    verbose "  Deleting temporary directory: $tmp_root/$file"
    rm -fr $tmp_root/$file

    verbose "  Return to previous directory"
    popd > /dev/null
}

# Invoke main
main ${1+"$@"}
