all: oo.o0 oo.o3 oo.fse oo.lzjd oo.o0.fn2hash.csv oo.o0.fn2hash.json oo.o3.fn2hash.csv oo.o3.fn2hash.json

oo.o0: ../src/oo.cpp
	g++ -g -O0 -o $@ $<
oo.o3: ../src/oo.cpp
	g++ -g -O3 -o $@ $<

%.fn2hash.json: %
	$(PHAROS_DIR)/tools/fn2hash/fn2hash -j $@ $<

%.fn2hash.csv: %
	$(PHAROS_DIR)/tools/fn2hash/fn2hash $< > $@

oo.fse: oo.o0.fn2hash.csv oo.o3.fn2hash.csv
	python $(PHAROS_DIR)/../tools/fn2hash/fse.py $^ > $@

oo.lzjd: oo.o0.fn2hash.json oo.o3.fn2hash.json
	python3 ../lzjd-script.py $^ > $@