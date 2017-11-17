#!/bin/bash

# Script to check for ABI conflicts in annotated binaries
#
# Created by Nick Clifton.
# Copyright (c) 2017 Red Hat.
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
#   check-abi.sh [switches] file(s)
#
# This script does not handle directories.  This is deliberate.
# It is intended that if recursion is needed then it will be
# invoked from find, like this:
#
#   find . -type f -exec check-abi.sh {} \;

# To Do:
#    * Allow arguments to command line options to be separated from the
#      the option name by a space.  Eg: --readelf foobar

version=2.0

help ()
{
  # The following exec goop is so that we don't have to manually
  # redirect every message to stderr in this function.
  exec 4>&1    # save stdout fd to fd #4
  exec 1>&2    # redirect stdout to stderr

  cat <<__EOM__

This is a shell script to check that the given program(s) have not
been built with object files that contain conflicting ABI options.

Usage: $prog {files|options}

  {options} are:
  -h        --help             Display this information.
  -v        --version          Report the version number of this script.
  -s        --silent           Produce no output, just an exit status.
  -i        --inconsistencies  Only report potential ABI problems.
  -V        --verbose          Report files without conflicts
  -r=<PATH> --readelf=<PATH>   Path to version of readelf to use to read notes.
  -t=<PATH> --tmpfile=<PATH>   Temporary file to use.

  --ignore-unknown             Silently skip files of unknown type.
  --ignore-ABI                 Do not check ABI annotation.
  --ignore-no-ABI              Check ABI information but do not complain if none is found.
  --ignore-enum                Do not check enum size annotation.
  --ignore-no-enum             Check enum size information but do not complain if none is found.
  --ignore-FORTIFY             Do not check FORTIFY SOURCE annotation.
  --ignore-no-FORTIFY          Check FORTIFY SOURCE information but do not complain if none is found.
  --ignore-stack-prot          Do not check stack protection annotation.
  --ignore-no-stack-prot       Check stack protection information but do not complain if none is found.

  --                           Stop accumulating options.

__EOM__
  exec 1>&4   # Copy stdout fd back from temporary save fd, #4
}

main ()
{
    init
    
    parse_args ${1+"$@"}

    scan_files

    if [ $failed -ne 0 ] ; then
	exit 1
    else
	exit 0
    fi
}

report ()
{
    if [ $silent -ne 0 ]
    then
	return
    fi
    echo $prog":" ${1+"$@"}
}

fail ()
{
    report "Internal error: " ${1+"$@"}
    exit 1
}

# Initialise global variables.
init ()
{
    files[0]="";  
    # num_files is the number of files to be listed minus one.
    # This is because we are indexing the files[] array from zero.
    num_files=0;

    failed=0
    silent=0
    verbose=0
    inconsistencies=0
    ignore_abi=0
    ignore_enum=0
    ignore_fortify=0
    ignore_stack_prot=0
    ignore_unknown=0
    scanner=readelf
    tmpfile=/dev/shm/check.abi.delme
}

# Parse our command line
parse_args ()
{
    prog=`basename $0`;

    # Locate any additional command line switches
    # Likewise accumulate non-switches to the files list.
    while [ $# -gt 0 ]
    do
	optname="`echo $1 | sed 's,=.*,,'`"
	optarg="`echo $1 | sed 's,^[^=]*=,,'`"

	case "$optname" in
	    -v | --version)
		report "version: $version"
		exit 0
		;;

	    -h | --help)
		help 
		exit 0
		;;
	    -s | --silent)
		silent=1;
		verbose=0;
		;;
	    -V | --verbose)
		silent=0;
		verbose=1;
		;;
	    -i | --inconsistencies)
		silent=0;
		inconsistencies=1;
		;;
	    -r | --readelf)
		scanner="$optarg"
		;;
	    -t | --tmpfile)
		tmpfile="$optarg"
		;;

	    --ignore-unknown)
		ignore_unknown=1;
		;;
	    --ignore-abi | --ignore-ABI)
		ignore_abi=1;
		;;
	    --ignore-no-abi | --ignore-no-ABI)
		ignore_abi=2;
		;;
	    --ignore-enum)
		ignore_enum=1;
		;;
	    --ignore-no-enum)
		ignore_enum=2;
		;;
	    --ignore-fortify | --ignore-FORTIFY)
		ignore_fortify=1;
		;;
	    --ignore-no-fortify | --ignore-no-FORTIFY)
		ignore_fortify=2;
		;;
	    --ignore-stack-prot)
		ignore_stack_prot=1;
		;;
	    --ignore-no-stack-prot)
		ignore_stack_prot=2;
		;;
	    
	    --)
		break;
		;;
	    --*)
		report "unrecognised option: $1"
		help
		exit 1
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

    if [ $num_files -gt 0 ] ;
    then
	# Remember that we are counting from zero not one.
	let "num_files--"
    else
	report "must specify at least one file to scan"
	exit 1
    fi
}

scan_files ()
{
    local i

    i=0;
    while [ $i -le $num_files ]
    do
	scan_file i
	let "i++"
    done
}

scan_file ()
{
    local file

    # Paranoia checks - the user should never encounter these.
    if test "x$1" = "x" ;
    then
	fail "scan_file called without an argument"
    fi
    if test "x$2" != "x" ;
    then
	fail "scan_file called with too many arguments"
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
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: file not found"
	    failed=1
	fi
	return
    fi
    
    if ! [ -f "$file" ]
    then
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: not an ordinary file"
	    failed=1
	fi
	return
    fi

    if ! [ -r "$file" ]
    then
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: not readable"
	    failed=1
	fi
	return
    fi

    file $file | grep --silent -e ELF
    if [ $? != 0 ] ;
    then
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: not an ELF format file"
	    failed=1
	fi
	return
    fi
    
    $scanner --wide --notes $file > $tmpfile 2>&1
    if [ $? != 0 ] ;
    then
	report "$file: scanner '$scanner' failed - see $tmpfile"
	failed=1
	# Leave the tmpfile intact so that it can be examined by the user.
	return
    fi

    local -a abis

    if [ $ignore_abi -ne 1 ];
    then
	# Convert:
	#   *<ABI>0x145e82c442000192 0x00000000 NT_GNU_BUILD...
	# or:
	#   GA*<ABI>0x145e82c442000192 0x00000000 NT_GNU_BUILD...
	# into:
	#   abis[n]=145e82c442000192

	eval 'abis=($(grep -e \<ABI\> $tmpfile | cut -d " " -f 3 | cut -d x -f 2))'

	if [ ${#abis[*]} -lt 1 ];
	then
	    if [[ $ignore_abi -eq 0 && $inconsistencies -eq 0 ]];
	    then
		report "$file: does not have an ABI note"
		# grep -e ABI $tmpfile
	    fi
	else
	    if [ ${#abis[*]} -eq 1 ];
	    then
		if [ $verbose -eq 1 ];
		then
		    report "$file: ABI: ${abis[0]}"
		fi
	    else
		local i mismatch=0

		if [ $inconsistencies -eq 0 ];
		then
		    report "$file: contains ${#abis[*]} ABI notes"
		fi
		i=1;
		while [ $i -lt ${#abis[*]} ]
		do
		    if test "${abis[i]}" != "${abis[i-1]}" ;
		    then
			# FIXME: Add code to differentiate between functions which have changed ABI and files ?
			report "$file: differing ABI values detected: ${abis[i]} vs ${abis[i-1]}"
			failed=1;
			mismatch=1;
		    fi
		    let "i++"
		done

		if [ $mismatch -eq 0 ];
		then
		    if [ $verbose -eq 1 ];
		    then
			report "$file: ABI: ${abis[0]}"
		    fi
		fi
	    fi
	fi
    fi

    if [ $ignore_enum -ne 1 ];
    then
	# Convert:
	#   +<short enum>true or  GA+<short enum>true
	# into:
	#   abis[n]=true
	# and
	#   !<short enum>false or  GA!<short enum>false
	# into:
	#   abis[n]=false

	eval 'abis=($(grep -e "short enum" $tmpfile | cut -f 2 -d ">" | cut -f 1 -d " "))'

	if [ ${#abis[*]} -lt 1 ];
	then
	    if [[ $ignore_enum -eq 0 && $inconsistencies -eq 0 ]];
	    then
		report "$file: does not record enum size"
	    fi
	else
	    if [ ${#abis[*]} -eq 1 ];
	    then
		if [ $verbose -eq 1 ];
		then
		    report "$file: -fshort-enums: ${abis[0]}"
		fi
	    else
		local i mismatch=0

		if [ $inconsistencies -eq 0 ];
		then
		    report "$file: contains ${#abis[*]} enum size notes"
		fi
		i=1;
		while [ $i -lt ${#abis[*]} ]
		do
		    if test "${abis[i]}" != "${abis[i-1]}" ;
		    then
			report "$file: differing -fshort-enums detected: ${abis[i]} vs ${abis[i-1]}"
			failed=1;
			mismatch=1;
		    fi
		    let "i++"
		done

		if [ $mismatch -eq 0 ] ;
		then
		    if [ $verbose -eq 1 ];
		    then
			report "$file: -fshort-enums: ${abis[0]}"
		    fi
		fi
	    fi
	fi
    fi

    if [ $ignore_fortify -ne 1 ];
    then
	# Convert:
	#   *FORTIFY:0x1
	# or:
	#   GA*FORTIFY:0x1
	# into:
	#   abis[n]=1

	eval 'abis=($(grep -e FORTIFY $tmpfile | cut -f 2 -d ":" | cut -b 3-5 | sed -e "s/ff/unknown/"))'

	if [ ${#abis[*]} -lt 1 ];
	then
	    if [[ $ignore_fortify -eq 0 && $inconsistencies -eq 0 ]];
	    then
		report "$file: does not record _FORTIFY_SOURCE level"
	    fi
	else
	    if [ ${#abis[*]} -eq 1 ];
	    then
		if [ $verbose -eq 1 ];
		then
		    report "$file: -D_FORTIFY_SOURCE=${abis[0]}"
		fi
	    else
		local i mismatch=0

		if [ $inconsistencies -eq 0 ];
		then
		    report "$file: contains ${#abis[*]} FORTIFY_SOURCE notes"
		fi
		i=1;
		while [ $i -lt ${#abis[*]} ]
		do
		    if test "${abis[i]}" != "${abis[i-1]}" ;
		    then
			report "$file: differing FORTIFY SOURCE levels: ${abis[i]} vs ${abis[i-1]}"
			failed=1;
			mismatch=1;
		    fi
		    let "i++"
		done

		if [ $mismatch -eq 0 ];
		then
		    if [ $verbose -eq 1 ];
		    then
			report "$file: -D_FORTIFY_SOURCE=${abis[0]}"
		    fi
		fi
	    fi
	fi
    fi

    if [ $ignore_stack_prot -ne 1 ];
    then
	# Convert:
	#   *<stack prot><type>
	# into:
	#   abis[n]=<type>

	eval 'abis=($(grep -e "stack prot" $tmpfile | cut -f 4 -d " " | cut -b 6-))'

	if [ ${#abis[*]} -lt 1 ];
	then
	    if [[ $ignore_stack_prot -eq 0 && $inconsistencies -eq 0 ]];
	    then
		report "$file: does not record -fstack-protect status"
	    fi
	else
	    if [ ${#abis[*]} -eq 1 ];
	    then
		if [ $verbose -eq 1 ];
		then
		    report "$file: -fstack-protect=${abis[0]}"
		fi
	    else
		local i mismatch=0

		if [ $inconsistencies -eq 0 ];
		then
		    report "$file: contains ${#abis[*]} stack protection notes"
		fi
		i=1;
		while [ $i -lt ${#abis[*]} ]
		do
		    if test "${abis[i]}" != "${abis[i-1]}" ;
		    then
			report "$file: differing stack protection levels: ${abis[i]} vs ${abis[i-1]}"
			failed=1;
			mismatch=1;
		    fi
		    let "i++"
		done

		if [ $mismatch -eq 0 ];
		then
		    if [ $verbose -eq 1 ];
		    then
			report "$file: -fstack-protect=${abis[0]}"
		    fi
		fi
	    fi
	fi
    fi

    rm -f $tmpfile
}

# Invoke main
main ${1+"$@"}
