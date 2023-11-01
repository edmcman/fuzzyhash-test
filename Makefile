sub.%:
	make -j 16 -C $*

all: sub.exp1 sub.exp2 sub.exp3 sub.exp4
