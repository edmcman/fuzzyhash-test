all: oo.o0 oo.o3 oo.o0.fn2hash oo.o3.fn2hash

oo.o0: ../src/oo.cpp
	g++ -g -O0 -o $@ $<
oo.o3: ../src/oo.cpp
	g++ -g -O3 -o $@ $<

%.fn2hash.json: %
	$(PHAROS_DIR)/tools/fn2hash/fn2hash -j $@ $<

%.fn2hash.csv: %
	$(PHAROS_DIR)/tools/fn2hash/fn2hash $< > $@
