all: oo.gcc oo.clang oo.gcc.fn2hash oo.clang.fn2hash

oo.gcc: ../src/oo.cpp
	g++ -g -O2 -o $@ $<
oo.clang: ../src/oo.cpp
	clang++ -g -O2 -o $@ $<

%.fn2hash: %
	$(PHAROS_DIR)/tools/fn2hash/fn2hash -j $@ $<
