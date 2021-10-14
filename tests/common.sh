ANNOCHECK=${ANNOCHECK:-../../annocheck/annocheck}
CURL=${CURL:-curl}
DEBUGINFOD=${DEBUGINFOD:-debuginfod}
GAS=${GAS:-as}
GCC=${GCC:-gcc}
OBJCOPY=${OBJCOPY:-objcopy}
PLUGIN=${PLUGIN:-../../gcc-plugin/.libs/annobin.so}
READELF=${READELF:-readelf}
SS=${SS:-/usr/sbin/ss}
STRIP=${STRIP:-strip}

# TEST_NAME must be set before including this
# In theory we should use ${builddir} instead of "." in the path below, but builddir is not exported.
testdir="./tmp_$TEST_NAME"

stashed_srcdir=

start_test()
{
  rm -rf $testdir
  mkdir -p $testdir

  pushd $testdir

  stashed_srcdir=$srcdir
  if test "${srcdir:0:1}" != "/";
  then
    srcdir="../$srcdir"
  fi
}

end_test()
{
  popd # Back from $testdir
  srcdir=$stashed_srcdir
}
