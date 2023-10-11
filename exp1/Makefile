include ../make.include

all: oo.fse oo.lzjd

EXES = oo.gcc oo.clang
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

oo.gcc: ../src/oo.cpp
	g++ -g -O2 -o $@ $<
oo.clang: ../src/oo.cpp
	clang++ -g -O2 -o $@ $<

$(eval $(call add_comparison, oo, oo.gcc, oo.clang))
