include ../make.include

all: oo.fse oo.lzjd oo.gcc.dis

EXES = oo.gcc oo2.gcc oo.clang
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

oo.gcc: ../src/oo.cpp
	g++ -g -O2 -o $@ $<
oo2.gcc: ../src/oo2.cpp
	g++ -g -O2 -o $@ $<
oo.clang: ../src/oo.cpp
	clang++ -g -O2 -o $@ $<

$(eval $(call add_comparison, oo, oo.gcc, oo.clang))
$(eval $(call add_comparison, oobasic, oo.gcc, oo2.gcc))