

LLVM_OPTIONS = \
  -D_GNU_SOURCE \
  -D__STDC_CONSTANT_MACROS \
  -D__STDC_FORMAT_MACROS \
  -D__STDC_LIMIT_MACROS \

PLUGIN_OPTIONS = \
  -shared \
   -fPIC

all: run-annobin

PrintFunctionNames.so: PrintFunctionNames.cpp
	clang++ $(LLVM_OPTIONS) $(PLUGIN_OPTIONS) $< -o $@

run-it: PrintFunctionNames.so
	clang++ -fplugin=./PrintFunctionNames.so -Xclang -plugin -Xclang print-fns PrintFunctionNames.cpp 

annobin.so: annobin.cpp
	clang++ $(LLVM_OPTIONS) $(PLUGIN_OPTIONS) $< -o $@

run-annobin: annobin.so
	clang++ -fplugin=./annobin.so \
   -D_FORTIFY_SOURCE=2 -O2 \
   -Xclang -plugin-arg-annobin -Xclang verbose \
   -Xclang -plugin-arg-annobin -Xclang version \
   --compile annobin.cpp \
   -mtbm

clean:
	rm -f annobin.so PrintFunctionNames.so annobin.o

