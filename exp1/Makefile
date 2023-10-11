include ../make.include

all: oo.gcc oo.clang oo.fse oo.lzjd oo.gcc.fn2hash.csv oo.gcc.fn2hash.json oo.clang.fn2hash.csv oo.clang.fn2hash.json

oo.gcc: ../src/oo.cpp
	g++ -g -O2 -o $@ $<
oo.clang: ../src/oo.cpp
	clang++ -g -O2 -o $@ $<

oo.fse: oo.gcc.fn2hash.csv oo.clang.fn2hash.csv
	python $(PHAROS_DIR)/../tools/fn2hash/fse.py $^ > $@

oo.lzjd: oo.gcc.fn2hash.json oo.clang.fn2hash.json oo.gcc oo.clang
	python3 ../lzjd-script.py $^ > $@
