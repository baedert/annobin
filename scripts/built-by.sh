#!/bin/bash

# Script to check which tools built the specified binaries.
#
# Created by Nick Clifton.  <nickc@redhat.com>
# Copyright (c) 2016-2018 Red Hat.
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
#   built-by [options] file(s)
#
# This script does not handle directories.  This is deliberate.
# It is intended that if recursion is needed then it will be
# invoked from find, like this:
#
#   find . -type f -exec built-by.sh {} \;

version=3.1

help ()
{
  # The following exec goop is so that we don't have to manually
  # redirect every message to stderr in this function.
  exec 4>&1    # save stdout fd to fd #4
  exec 1>&2    # redirect stdout to stderr

  cat <<__EOM__

This is a shell script to extract details of the
tool that was used to create the named files.

Usage: $prog {files|options}

  {options} are:
  -h        --help            Display this information.
  -v        --version         Report the version number of this script.
  -V        --verbose         Report on progress.
  -s        --silent          Produce no output, just an exit status.
  -q        --quiet           Do not include the script name in the output.
  -i        --ignore          Silently ignore files where the builder cannot be found.
  -r=<PATH> --readelf=<PATH>  Path to version of readelf to use to read notes.
  -t=<PATH> --tmpfile=<PATH>  Temporary file to use.
  --                          Stop accumulating options.

The information reported can be made conditional by using the following options:

            --tool=<NAME>     Only report binaries built by <NAME>
            --nottool=<NAME>  Skip binaries built by <NAME>
            --before=<DATE>   Only report binaries built before <DATE>
            --after=<DATE>    Only report binaries built after <DATE>
	    --minver=<VER>    Only report binaries built by version <VER> or higher
	    --maxver=<VER>    Only report binaries built by version <VER> or lower

  <NAME> is just a string, not a regular expression
  <DATE> format is YYYYMMDD.  For example: 20161230
  <VER> is a version string in the form V.V.V  For example: 6.1.2

The --before and --after options can be used together to specify a date
range which should be reported.  Similarly the --minver and --maxver
options can be used together to specify a version range.

__EOM__
  exec 1>&4   # Copy stdout fd back from temporary save fd, #4
}

main ()
{
    init
    
    parse_args ${1+"$@"}

    scan_files

    if [ $failed -ne 0 ];
    then
	exit 1
    else
	exit 0
    fi
}

report ()
{
    if [ $silent -ne 0 ];
    then
	return
    fi

    if [ $quiet -eq 0 ];
    then
	echo -n $prog": "
    fi
    
    echo ${1+"$@"}
}

fail ()
{
    report "Internal error: " ${1+"$@"}
    exit 1
}

verbose ()
{
    if [ $verb -ne 0 ]
    then
	report ${1+"$@"}
    fi
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
    quiet=0
    verb=0
    ignore_unknown=0
    scanner=readelf
    tmpfile=/dev/shm/built.by.delme
    tool=""
    nottool=""
    before=""
    after=""
    minver=""
    maxver=""
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
		verb=0;
		;;
	    -q | --quiet)
		quiet=1;
		;;
	    -V | --verbose)
		silent=0;
		verb=1;
		;;
	    -i | --ignore)
		ignore_unknown=1;
		;;
	    -r | --readelf)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs a program name"
		    else
			scanner=$1
		    fi
		else
		    scanner="$optarg"
		fi
		;;
	    -t | --tmpfile)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs a filename argument"
		    else
			tmpfile=$1
		    fi
		else
		    tmpfile="$optarg"
		fi
		;;
	    --tool)
		nottool=""
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			tool=$1
		    fi
		else
		    tool=$optarg
		fi
		;;
	    --nottool)
		tool=""
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			nottool=$1
		    fi
		else
		    nottool=$optarg
		fi
		;;
	    --before)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			before=$1
		    fi
		else
		    before=$optarg
		fi
		;;
	    --after)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			after=$1
		    fi
		else
		    after=$optarg
		fi
		;;
	    --minver)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			minver=$1
		    fi
		else
		    minver=$optarg
		fi
		;;
	    --maxver)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			maxver=$1
		    fi
		else
		    maxver=$optarg
		fi
		;;
	    --)
		shift
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

    if [ $num_files -gt 0 ];
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
	if [ $ignore_unknown -eq 0 ]; then
	    report "$file: file not found"
	    failed=1
	fi
	return
    fi
    
    if ! [ -f "$file" ]
    then
	if [ $ignore_unknown -eq 0 ]; then
	    report "$file: not an ordinary file"
	    failed=1
	fi
	return
    fi

    if ! [ -r "$file" ]
    then
	if [ $ignore_unknown -eq 0 ]; then
	    report "$file: not readable"
	    failed=1
	fi
	return
    fi

    file $file | grep --silent -e ELF
    if [ $? != 0 ];
    then
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: not an ELF format file"
	    failed=1
	fi
	return
    fi
    
    $scanner --wide --notes $file > $tmpfile 2>&1
    if [ $? != 0 ];
    then
	if [ $ignore_unknown -eq 0 ]; then
	    report "$file: scanner '$scanner' failed - see $tmpfile"
	    failed=1
	fi
	# Leave the tmpfile intact so that it can be examined by the user.
	return
    fi

    local -a builder
    local tool_index ver_index date_index tell=1

    grep --silent -e "\$<tool>" $tmpfile

    if [ $? == 0 ];
    then
	# Convert:
	#   $<tool>gcc 7.0.0 20161212 0x00000000 NT_GNU...
	# or
	#   GA$<tool>gcc 7.0.0 20161212 0x00000000 NT_GNU...
	# into:
	#   builder[0]=gcc
	#   builder[1]=7.0.0
	#   builder[2]=20161212

	tool_index=0
	ver_index=1
	date_index=2

	eval 'builder=($(grep -e tool $tmpfile | cut -d " " -f 3-5 | sort -u))'
	
	verbose "build notes contain: ${builder[*]}"
	
	if [ ${#builder[*]} -gt 3 ];
	then
	    report "$file: contains multiple, different creator notes"
	fi

	if [ ${#builder[*]} -lt 3 ];
	then
	    if [ $ignore_unknown -eq 0 ];
	    then
		report "$file: contains truncated creator notes"
		failed=1
	    fi
	    tell=0
	fi
	builder[0]=`echo ${builder[0]} | cut -d \> -f 2`
    else
	verbose "scan for build notes failed, trying debug information"

	# Try examining the debug information in case -grecord-gcc-switches has been used.

	# FIXME: If we have a new enough version of readelf we could add the
	# --debug-dump=follow-links option to cope with separate debug info files..

	$scanner --wide --debug-dump=info $file | grep -e DW_AT_producer > $tmpfile
	eval 'builder=($(grep -e GNU $tmpfile))'

	if [ ${#builder[*]} -ge 11 ];
	then
	    # FIXME: We should grep for the right strings, rather than using
	    # builtin knowledge of the format of the DW_AT_producer contents

	    verbose "DW_AT_producer contains: ${builder[*]}"

	    tool_index=7
	    ver_index=9
	    date_index=10
	    builder[7]="${builder[7]} ${builder[8]}"
	else
	    verbose "scan for debug information failed, trying .comment section"
	    
	    # Alright - last chance.  Check the .comment section
	    $scanner -p.comment $file > $tmpfile 2>&1
	    grep --silent -e "does not exist" $tmpfile

	    if [ $? != 0 ];
	    then
		eval 'builder=($(grep -e GNU $tmpfile))'

		verbose ".comment contains: ${builder[*]}"

		# FIXME: We are using assumed knowledge of the layout of the builder comment.
		if [ ${#builder[*]} -lt 5 ];
		then
		    if [ $ignore_unknown -eq 0 ]; then
			verbose "$file: could not parse .comment section"
			report "$file: creator unknown"
			failed=1
		    fi
		    tell=0
		fi
		tool_index=2
		ver_index=4
		date_index=5	
		builder[2]="${builder[2]} ${builder[3]}"
	    else
		if [ $ignore_unknown -eq 0 ]; then
		    report "$file: creator unknown"
		    failed=1
		fi
		tell=0
	    fi
	fi
    fi

    if [ $tell -eq 1 ];
    then
	if [ x$tool != x ];
	then
	    if [ "${builder[$tool_index]}" == $tool ];
	    then
		tell=0
	    fi
	fi
	if [ x$nottool != x ];
	then
	    if [ "${builder[$tool_index]}" == $nottool ];
	    then
		tell=0
	    fi
	fi
	if [ x$minver != x ];
	then
	    if [[ ${builder[$ver_index]} < $minver ]];
	    then
		tell=0
	    fi
	fi
	if [ x$maxver != x ];
	then
	    if [[ ${builder[$ver_index]} > $maxver ]];
	    then
		tell=0
	    fi
	fi
	if [ x$before != x ];
	then
	    if [ ${builder[$date_index]} -ge $before ];
	    then
		tell=0
	    fi
	fi
	if [ x$after != x ];
	then
	    if [ ${builder[$date_index]} -le $after ];
	    then
		tell=0
	    fi
	fi	
    fi
    
    if [ $tell -eq 1 ];
    then
	report "$file: created by: ${builder[$tool_index]} v${builder[$ver_index]} ${builder[$date_index]}"
    fi

    rm -f $tmpfile
}

# Invoke main
main ${1+"$@"}
