include ../make.include

all: oo.fse oo.lzjd

EXES = oo.o0 oo.o3
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

oo.o0: ../src/oo.cpp
	g++ -g -O0 -o $@ $<
oo.o3: ../src/oo.cpp
	g++ -g -O3 -o $@ $<

$(eval $(call add_comparison, oo, oo.o0, oo.o3))
