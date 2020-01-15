
LLVM_OPTIONS = \
  -D_GNU_SOURCE \
  -D__STDC_CONSTANT_MACROS \
  -D__STDC_FORMAT_MACROS \
  -D__STDC_LIMIT_MACROS \

PLUGIN_OPTIONS = \
  -shared \
  -fPIC

CC=clang
#READELF=readelf
READELF=/work/builds/binutils/current/x86_64-pc-linux-gnu/binutils/readelf

#STRIP=strip
STRIP=/work/builds/binutils/current/x86_64-pc-linux-gnu/binutils/strip-new

all: run-annobin

annobin.so: annobin.cpp
	clang++ $(LLVM_OPTIONS) $(PLUGIN_OPTIONS) $< -o $@

run-annobin: annobin.so
	$(CC) -fplugin=./annobin.so \
   -D_FORTIFY_SOURCE=2 -O2 \
   -Xclang -plugin-arg-annobin -Xclang verbose \
   -Xclang -plugin-arg-annobin -Xclang version \
   hello.c \
   -save-temps \
   -mtbm
	$(STRIP) --merge-notes a.out
	$(READELF) --wide --notes a.out

clean:
	rm -f annobin.so annobin.o hello.bc hello.i hello.o hello.s a.out
