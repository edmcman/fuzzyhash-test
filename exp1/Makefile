all: oo.gcc oo.clang

oo.gcc: ../src/oo.cpp
	g++ -g -O2 -o $@ $<
oo.clang: ../src/oo.cpp
	clang++ -g -O2 -o $@ $<
