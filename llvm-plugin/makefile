
LLVM_OPTIONS = \
  -D_GNU_SOURCE \
  -D__STDC_CONSTANT_MACROS \
  -D__STDC_FORMAT_MACROS \
  -D__STDC_LIMIT_MACROS \

PLUGIN_OPTIONS = \
  -shared \
  -fPIC

INCDIR = ..

all: run-test

annobin.so: annobin.cpp
	clang++ $(LLVM_OPTIONS) $(PLUGIN_OPTIONS) -I$(INCDIR) $< -o $@

#READELF=readelf
READELF=/work/builds/binutils/current/x86_64-pc-linux-gnu/binutils/readelf

#STRIP=strip
STRIP=/work/builds/binutils/current/x86_64-pc-linux-gnu/binutils/strip-new

CC=clang

# Note: enabling -fcf-protection results in this error from the linker:
#   /bin/ld: error: hello.o: <corrupt x86 feature size: 0x8>
# At least for Clang-7 on Fedora 29.

run-test: annobin.so test-clang test-go test-rust

test-clang:
	ANNOBIN_VERBOSE=true $(CC) \
   -Xclang -load -Xclang `pwd`/annobin.so \
   -D_FORTIFY_SOURCE=2 \
   -O2 \
   -g -grecord-gcc-switches \
   -fpic \
   -fcf-protection \
   -fstack-protector-strong \
   -fsanitize=safe-stack \
   -fsanitize=cfi-cast-strict \
   hello.c \
   -save-temps 
	$(STRIP) --merge-notes a.out
	$(READELF) --wide --notes hello.o

test-go:
	 go build hello.go

test-rust:
	rustc hello.rs

clean:
	rm -f annobin.so annobin.o hello.bc hello.i hello.o hello.s a.out hello

