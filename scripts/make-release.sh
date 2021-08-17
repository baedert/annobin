#!/bin/bash

version=`grep ANNOBIN_VERSION current/annobin-global.h | cut -f 3 -d ' '`
release=`echo $version | cut -b1`.`echo $version | cut -b2-3`

rm -fr annobin-$release annobin-gcc-plugin-$release annobin-$release.tar.xz annobin-gcc-plugin-$release.tar.xz

cp -r current annobin-$release
cd annobin-$release
rm -fr .git autom4te.cache
cd ..
tar cf - annobin-$release | xz -9 -c > annobin-$release.tar.xz
rm -fr annobin-$release

echo "Created: annobin-$release.tar.xz"

exit 0

cp -r current annobin-gcc-plugin-$release
cd annobin-gcc-plugin-$release
rm -fr .git autom4te.cache scripts annocheck tests clang-plugin llvm-plugin doc tests
sed --in-place -e 's/"$with_docs" != no/"$with_docs" == yes/' configure.ac
sed --in-place -e 's/"$with_tests" != no/"$with_tests" == yes/' configure.ac
sed --in-place -e 's/"$with_annocheck" != no/"$with_annocheck" == yes/' configure.ac
sed --in-place -e 's/if test "$with_docs" != no; then/if test "$with_docs" == yes; then/' configure
sed --in-place -e 's/if test "$with_tests" != no; then/if test "$with_tests" == yes; then/' configure
sed --in-place -e 's/if test "$with_annocheck" != no; then/if test "$with_annocheck" == yes; then/' configure
cd ..

tar cf - annobin-gcc-plugin-$release | xz -9 -c > annobin-gcc-plugin-$release.tar.xz
rm -fr annobin-gcc-plugin-$release

echo "Created: annobin-gcc-plugin-$release.tar.xz"
