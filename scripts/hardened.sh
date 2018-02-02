#!/bin/bash

# Script to check for hardening options in annotated binaries
#
# Created by Nick Clifton.  <nickc@redhat.com>
# Copyright (c) 2017-2018 Red Hat.
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 3, or (at your
# option) any later version.
#
# It is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.


# Usage:
#   hardened.sh [switches] file(s)
#
# This script does not handle directories.  This is deliberate.
# It is intended that if recursion is needed then it will be
# invoked from find, like this:
#
#   find . -type f -exec hardened.sh {} \;

# To Do:
#    * Allow arguments to command line options to be separated from the
#      the option name by a space.  Eg: --readelf foobar

version=3.1

help ()
{
  # The following exec goop is so that we don't have to manually
  # redirect every message to stderr in this function.
  exec 4>&1    # save stdout fd to fd #4
  exec 1>&2    # redirect stdout to stderr

  cat <<__EOM__
This is a shell script to check that the given file(s) have been
built with the recommended hardening options.  These options are:

   -O2                      (or higher)
   -fstack-protector-strong
   -D_FORTIFY_SOURCE=2
   -Wl,-z,now
   -Wl,-z,relro

Plus for shared objects/libraries:

   -fPIC

Plus for executables (although on RHEL6 these should be omitted due to a kernel bug):

   -fPIE
   -Wl,-pie

Plus for RHEL-8:

   -D_GLIBCXX_ASSERTIONS
   -fstack-clash-protection
   -fcf-protection=full
   -mcet

Usage: $prog {files|options}

 {options} are:
  -h        --help             Display this information and exit.
  -v        --version          Report the version number of this script and exit.

  -q        --quiet            Do not include the script name in the output.
  -s        --silent           Produce no output, just an exit status.
  -V        --verbose          Report on progress.
  -u        --vulnerable       Only report files known to be vulnerable. [default]
  -n        --not-hardened     Report any file that is not proven to be hardened.
  -a        --all              Report the hardening status of all files.
 [The last one of these on the command line is used]. 

  -f=auto   --file-type=auto   Automatically distinguish libraries from executables. [default]
  -f=lib    --file-type=lib    Assume all files are shared libraries.
  -f=exec   --file-type=exec   Assume all files are executables.
  -f=obj    --filetype=obj     Assume all files are object files/archives.
 [The last one of these on the command line is used]. 

  -k=opt      --skip=opt       Skip check of optimization level
  -k=stack    --skip=stack     Skip check of stack-protector status
  -k=fort     --skip=fort      Skip check of fortify source status
  -k=now      --skip=now       Skip check of BIND_NOW status
  -k=relro    --skip=relro     Skip check of RELRO status
  -k=pic      --skip=pic       Skip check for PIC/PIE compilation.  (Good for RHEL-6 binaries)
  -k=operator --skip=operator  Skip check for operator[] range testing.
  -k=clash    --skip=clash     Skip check for stack clash protection.
  -k=cf       --skip=cf        Skip check for control flow protection.
  -k=cet      --skip-cet       Skip check for control flow enforcement technology.
 [These options stack]
  
  -i        --ignore-unknown   Silently skip any file that is not an ELF binary.

  -r=<PATH> --readelf=<PATH>   Path to version of readelf to use.
  -t=<PATH> --tmpfile=<PATH>   Temporary file to use.

  --                           Stop accumulating options.  Any text that follows this
                               option is assumed to be a file name, even if it starts
                               with a dash.
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
    if [ $report -eq 0 ];
    then
	return
    fi

    if [ $quiet -eq 0 ];
    then
	echo -n $prog": "
    fi
    
    echo ${1+"$@"}
}

ICE ()
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

maybe ()
{
    if [ $report -gt 1 ]
    then
	report "$file: MAYBE:" ${1+"$@"}
    fi

    vulnerable=1
}

fail ()
{
    if [ $report -gt 0 ]
    then
	report "$file: FAIL:" ${1+"$@"}
    fi

    vulnerable=1
}

pass ()
{
    if [ $report -gt 2 ]
    then
	report "$file: PASS:" ${1+"$@"}
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
    report=1 # Quad-state, 0=> report nothing, 1=> report known vulnerable, 2=> report not proven hardened, 3=> report all
    verb=0
    quiet=0
    filetype=auto

    skip_opt=0
    skip_stack=0
    skip_fortify=0
    skip_bind_now=0
    skip_relro=0
    skip_pic=0
    skip_operator=0
    skip_clash=0
    skip_cf=0
    skip_cet=0
    
    ignore_unknown=0
    scanner=readelf
    tmpfile=/dev/shm/hardened.delme
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
		report=0;
		verb=0;
		;;
	    -q | --quiet)
		quiet=1;
		;;
	    -V | --verbose)
		verb=1;
		;;
	    -u | --vulnerable)
		report=1;
		;;
	    -n | --not-hardened)
		report=2;
		;;
	    -a | --all)
		report=3;
		;;

	    -f | --file-type)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			ft=$1
		    fi
		else
		    ft=$optarg
		fi
		case "$ft" in
		    auto)
			filetype=auto
			;;
		    exec)
			filetype=exec
			;;
		    lib)
			filetype=library
			;;
		    obj)
			filetype=object
			;;
		    *)
			report "unknown argument to $optname: $ft"
			;;
		esac
		;;

	    -k | --skip)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
		    else
			sk=$1
		    fi
		else
		    sk=$optarg
		fi
		case "$sk" in
		    opt)
			skip_opt=1
			;;
		    stack)
			skip_stack=1
			;;
		    fort)
			skip_fortify=1
			;;
		    now)
			skip_bind_now=1
			;;
		    relro)
			skip_relro=1
			;;
		    pic)
			skip_pic=1;
			;;
		    operator)
			skip_operator=1;
			;;
		    clash)
			skip_clash=1;
			;;
		    cf)
			skip_cf=1;
			;;
		    cet)
			skip_cet=1;
			;;
		    *)
			report "unknown argument to $optname: $sk"
			;;
		esac
		;;
		
	    -r | --readelf)
		if test "x$optarg" = "x$optname" ;
		then
		    shift
		    if [ $# -eq 0 ]
		    then
			fail "$optname needs an argument"
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
			fail "$optname needs an argument"
		    else
			tmpfile=$1
		    fi
		else
		    tmpfile="$optarg"
		fi
		;;

	    -i | --ignore-unknown)
		ignore_unknown=1;
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
	ICE "scan_file called without an argument"
    fi
    if test "x$2" != "x" ;
    then
	ICE "scan_file called with too many arguments"
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
    if [ $? != 0 ];
    then
	if [ $ignore_unknown -eq 0 ];
	then
	    report "$file: not an ELF format file"
	    failed=1
	fi
	return
    fi

    $scanner --wide --notes --debug-dump=info --dynamic --segments $file > $tmpfile 2>&1
    if [ $? != 0 ];
    then
	report "scanner '$scanner' failed - see $tmpfile"
	failed=1
	# Leave the tmpfile intact so that it can be examined by the user.
	return
    fi

    grep -q -e "Unknown note" $tmpfile
    if [ $? == 0 ];
    then
	# The FORTIFY checks need fully parsed notes.
	# The other checks can use other sources of information.
	if [ $skip_fortify -eq 0 ];
	then
	    maybe "scanner '$scanner' did not recognise the build attribute notes "
	fi
    fi       

    grep -q -e "Gap in build notes" $tmpfile
    if [ $? == 0 ];
    then
	maybe "there are gaps in the build notes"
    fi       

    local -a hard
    local vulnerable=0

    if [ $skip_opt -eq 0 ];
    then
	check_optimization_level
    fi

    if [ $skip_stack -eq 0 ];
    then
	check_for_stack_protector
    fi

    if [ $skip_fortify -eq 0 ];
    then
	check_for_fortify
    fi
    
    # Do not check the bind_now or relro status of unlinked files.
    if [[ $filetype == exec || $filetype == lib	|| ( $filetype == auto && $file != *.o && $file != x*.a ) ]] ;
    then
	if [ $skip_bind_now -eq 0 ];
	then
	    check_for_bind_now
	fi
	
	if [ $skip_relro -eq 0 ];
	then
	    check_for_relro
	fi
    fi

    if [ $skip_pic -eq 0 ];
    then
	check_for_pie_or_pic
    fi

    if [ $skip_operator -eq 0 ];
    then
	check_operator_range
    fi

    if [ $skip_clash -eq 0 ];
    then
	check_stack_clash
    fi

    if [ $skip_cf -eq 0 ];
    then
	check_control_flow_protection
    fi

    # FIXME: This check should only be applied to x86_64 binaries...
    if [ $skip_cet -eq 0 ];
    then
	check_control_flow_enforcement_technology
    fi

    # If we found a vulnerable file then consider the check to have failed.
    if [ $vulnerable -gt 0 ];
    then
	failed=1
    fi
    
    rm -f $tmpfile
}

check_for_fortify ()
{
    # Turn:
    #   *FORTIFY:2           0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    # or:
    #   GA*FORTIFY:2         0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    # into:
    #   2
    
    eval 'hard=($(grep -e FORTIFY $tmpfile | grep OPEN | cut -f 2 -d ":" | cut -b 3-5 | sed -e "s/ff/-1/" | sort -u))'

    verbose "FORTIFY Info: ${hard[*]}"
    
    if [ ${#hard[*]} -lt 1 ];
    then
	# Or an old version of readelf is being used which does not recognise the fortify note...
	maybe "does not record _FORTIFY_SOURCE level"
    else
	# Check the value(s) to make sure that they are all >= 2.
	local i

	i=0;
	while [ $i -lt ${#hard[*]} ]
	do
	    if [ ${hard[i]} -lt 0 ];
	    then
		maybe "sources compiled with --save-temps do not record _FORTIFY_SOURCE level"
	    else
		if [[ ${hard[i]} -lt 2 ]];
		then
		    fail "insufficient value for -D_FORTIFY_SOURCE=${hard[i]}"
		else
		    pass "-D_FORTIFY_SOURCE=${hard[i]}"
		fi
	    fi
	    let "i++"
	done
    fi
}

check_for_stack_protector ()
{
    # Turn:
    #   *<stack prot>strong  0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    # or:
    #   GA*<stack prot>strong 0x00000000 NT_GNU_BUILD_ATTRIBUTE_OPEN
    # into:
    #   strong
    eval 'hard=($(grep -e "stack prot" $tmpfile | grep OPEN | cut -f 2 -d ">" | cut -f 1 -d " " | sort -u))'

    verbose "Stack Protection Info: ${hard[*]}"
    
    if [ ${#hard[*]} -lt 1 ];
    then
	# Stack protector note not recorded.  Try examining the debug
	# information in case -grecord-gcc-switches has been used.
	# Turn:
	#   <c> DW_AT_producer : (indirect string, offset: 0x0): GNU C11 6.3.1 20161221 (Red Hat 6.3.1-1) -fstack-proector-strong
	# into:
	#   strong
	eval hard=($(gawk 'BEGIN { FPAT = "-f[no-]*stack-protector[^ ]*" } /f/ { print substr ($1,19) ; }' $tmpfile | sort | uniq))

	verbose "DW_AT_producer stack records: ${hard[*]}"
    fi
  
    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record -fstack_protector setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "multiple, different, settings of -fstack-protector used"
	else
	    if test "x${hard[0]}" = "xstrong" ;
	    then
		pass "compiled with -fstack-protector-strong"
	    else
		fail "compiled with -fstack-protector-${hard[0]}"
	    fi
	fi
    fi

    # Also check to see if any individual functions have been compiled explicitly without stack protection.
    # Turn:
    #   *<stack prot>strong  0x00000000	NT_GNU_BUILD_ATTRIBUTE_FUNC
    #   GA*<stack prot>strong  0x00000000 NT_GNU_BUILD_ATTRIBUTE_FUNC
    # into:
    #   strong
    eval 'hard=($(grep -e "stack prot" $tmpfile | grep -e NT_GNU_BUILD_ATTRIBUTE_FUNC -e func | cut -f 2 -d ">" | cut -f 1 -d " " | sort -u))'

    verbose "Stack Prot Info: ${hard[*]}"

    if [ ${#hard[*]} -gt 0 ];
    then
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "contains functions compiled without -fstack-protector=strong"
	else
	    if test "x${hard[0]}" != "xstrong" ;
	    then
		fail "contains functions compiled with -fstack-protector-${hard[0]}"
	    fi
	fi
    fi
}

check_for_pie_or_pic ()
{
    # Turn:
    #   *<PIC>PIE            0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    #   GA*<PIC>PIE          0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    # into:
    #   PIE
    eval 'hard=($(grep -e "<PIC>" $tmpfile | grep OPEN | cut -f 2 -d ">" | cut -f 1 -d " " | sort -u))'

    verbose "PIC Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	# <PIC> note not recorded.  Try examining the debug information
	# in case -grecord-gcc-switches has been used.
	# Turn:
	#   <c> DW_AT_producer : (indirect string, offset: 0x0): GNU C11 6.3.1 20161221 (Red Hat 6.3.1-1) -g -O2 -fPIC
	# into:
	#   PIC
	eval hard=($(gawk 'BEGIN { FPAT = "-f[pP][iI][cCeE]" } /f/ { print substr ($1,3) ; }' $tmpfile | sort -u))

	verbose "DW_AT_producer records: ${hard[*]}"
    fi
  
    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record -fpic/-fpie setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "multiple, different, settings of -fpic/-fpie used"
	else
	    if [[ $filetype = lib || ( $filetype = auto && $file == *.so ) ]] ;
	    then
		if [[ "x${hard[0]}" -eq "xPIC" || "x${hard[0]}" -eq "xpic" ]] ;
		then
		    pass "compiled with -f${hard[0]}"
		else
		    fail "compiled with -f${hard[0]}"
		fi
	    else
		if [[ "x${hard[0]}" -eq "xPIE" || "x${hard[0]}" -eq "xpie" ]] ;
		then
		    pass "compiled with -f${hard[0]}"
		else
		    fail "compiled with -f${hard[0]}"
		fi
	    fi
	fi
    fi

    # FIXME: Do we need to check for individual functions compiled without PIE support ?
}

check_optimization_level ()
{
    # The bits in the GOW value encode the following information:
    #
    #   bits 0 -  2 : debug type (from enum debug_info_type)
    #   bit  3      : with GNU extensions
    #   bits 4 -  5 : debug level (from enum debug_info_levels)
    #   bits 6 -  8 : DWARF version level
    #   bits 9 - 10 : optimization level
    #   bit  11     : -Os
    #   bit  12     : -Ofast
    #   bit  13     : -Og
    #   bit  14     : -Wall
    #
    # For now all that we care about is the optimization level (bits 9,10)
    # so turn:
    #   *GOW:0x052b          0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    #   GA*GOW:0x052b        0x00000000	NT_GNU_BUILD_ATTRIBUTE_OPEN
    # into:
    #   0x052b
    eval 'hard=($(grep -e "GOW:" $tmpfile | grep OPEN | cut -f 2 -d ":" | cut -f 1 -d " " | sort -u))'

    verbose "Optimization Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	# GOW note not recorded.  Try examining the debug information
	# in case -grecord-gcc-switches has been used.
	# Turn:
	#   <c> DW_AT_producer : (indirect string, offset: 0x0): GNU C11 6.3.1 20161221 (Red Hat 6.3.1-1) -g -O2 -fPIC
	# into:
	#   2
	eval hard=($(gawk 'BEGIN { FPAT = "-O[0123]" } /O[0123]/ { print substr ($1,3,1) ; }' $tmpfile | sort -u))

	verbose "DW_AT_producer records: ${hard[*]}"

	if [ ${#hard[*]} -lt 1 ];
	then
	    maybe "does not record -O setting"
	else
	    local i

	    i=0;
	    while [ $i -lt ${#hard[*]} ]
	    do
		if [ ${hard[i]} -lt 2 ];
		then
		    fail "optimization level of -O${hard[i]} used"
		    break
		else
		    pass "optimization level of -O${hard[i]} used"
		fi
		let "i++"
	    done
	fi
    else
	local i

	i=0;
	while [ $i -lt ${#hard[*]} ]
	do
	    declare -i opt=$(((${hard[i]} & 0x600) >> 9))
	    if [ $opt -lt 2 ];
	    then
		fail "optimization level of -O$opt used"
		break
	    else
		pass "optimization level of -O$opt used"
	    fi
	    let "i++"
	done
    fi
}

check_for_bind_now ()
{
    # Look for the DT_BIND_NOW dynamic tag
    eval hard='($(grep -e BIND_NOW $tmpfile))'

    verbose "BIND_NOW tags: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	fail "-Wl,-z,now not used"
    else
	pass "-Wl,-z,now used"
    fi
}

check_for_relro ()
{
    # Look for the DT_BIND_NOW dynamic tag
    eval hard='($(grep -e GNU_RELRO $tmpfile))'

    verbose "GNU_RELRO tags: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	fail "-Wl,-z,relro not used"
    else
	pass "-Wl,-z,relro used"
    fi
}

check_operator_range ()
{
    # Turn:
    #   GA!GLIBCXX_ASSERTIONS:false  0x00000000	OPEN	    Applies to region from 0 to 0x3a
    # into:
    #   false
    eval 'hard=($(grep -e "ASSERTIONS" $tmpfile | cut -f 2 -d ":" | cut -f 1 -d " " | sort -u))'

    verbose "Operator Range Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record operator range test setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "some parts built without operator range checking"
	else
	    if [ "x${hard[0]}" == "xtrue" ];
	    then
		pass "compiled with operator range checking enabled"
	    else
		fail "compiled with operator range checking disabled"
	    fi
	fi
    fi
}

check_stack_clash ()
{
    # Turn:
    #   GA+stack_clash:true          0x00000000	OPEN	    Applies to region from 0 to 0x3a
    # into:
    #   true
    eval 'hard=($(grep -e "stack_clash" $tmpfile | cut -f 2 -d ":" | cut -f 1 -d " " | sort -u))'

    verbose "Stack Clash Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record stack clash protection setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "some parts built without stack clash protection enabled"
	else
	    if [ "x${hard[0]}" == "xtrue" ];
	    then
		pass "compiled with stack clash protection enabled"
	    else
		fail "compiled with stack clash protection disabled"
	    fi
	fi
    fi
}

check_control_flow_protection ()
{
    # Turn:
    #   GA*cf_protection:0x8          0x00000000	OPEN	    Applies to region from 0 to 0x3a
    # into:
    #   0x8
    eval 'hard=($(grep -e "cf_protection" $tmpfile | cut -f 2 -d ":" | cut -f 1 -d " " | sort -u))'

    verbose "Control Flow Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record control flow protection setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "some parts built with different settings for -fcf-protection"
	else
	    if [ "x${hard[0]}" == "x0x8" ];
	    then
		pass "compiled with -fcf-protection=full"
	    else
		if [ "x${hard[0]}" == "x0x7" ];
		then
		    fail "compiled with -fcf-protection=return"
		else
		    if [ "x${hard[0]}" == "x0x5" ];
		    then
			fail "compiled with -fcf-protection=branch"
		    else
			fail "compiled with unknown setting for -fcf-protection"
		    fi
		fi
	    fi
	fi
    fi
}

check_control_flow_enforcement_technology ()
{
    # Turn:
    #   GA*cet status:0x2020102          0x00000000	OPEN	    Applies to region from 0 to 0x3a
    # into:
    #   0x2020102
    eval 'hard=($(grep -e "cet status" $tmpfile | cut -f 2 -d ":" | cut -f 1 -d " " | sort -u))'

    verbose "CET Info: ${hard[*]}"

    if [ ${#hard[*]} -lt 1 ];
    then
	maybe "does not record control flow enforcement technology setting"
    else
	if [ ${#hard[*]} -gt 1 ];
	then
	    fail "some parts built different CET settings"
	else
	    if [ "x${hard[0]}" == "x0x2020102" ];
	    then
		pass "compiled with CET enabled"
	    else
		if [ "x${hard[0]}" == "x0x2020202" ];
		then
		    pass "compiled with CET enabled (and switch protection)"
		else
		    # FIXME: Tell the user exactly which bits were not enabled.
		    fail "compiled with CET disabled"
		fi
	    fi
	fi
    fi
}


# Invoke main
main ${1+"$@"}
