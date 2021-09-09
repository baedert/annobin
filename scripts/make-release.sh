#!/bin/bash

version=`grep ANNOBIN_VERSION current/annobin-global.h | cut -f 3 -d ' '`
release=`echo $version | cut -b1`.`echo $version | cut -b2-3`

rm -fr annobin-$release annobin-gcc-plugin-$release annobin-$release.tar.xz annobin-gcc-plugin-$release.tar.xz

cp -r current annobin-$release
cd annobin-$release
rm -fr .git autom4te.cache

sleep 1
touch aclocal.m4 gcc-plugin/config.h.in
touch configure */configure Makefile.in */Makefile.in
touch doc/annobin.info

cd ..
tar cf - annobin-$release | xz -9 -c > annobin-$release.tar.xz
rm -fr annobin-$release

echo "Created: annobin-$release.tar.xz"

exit 0
