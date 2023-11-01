include ../make.include

SSL = openssl-1.1.1w

# default target
all:
	@echo all

EXES = openssl.gcc openssl.clang openssl.O0 openssl.O1 openssl.O2 openssl.O3
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

openssl.gcc: openssl1.gcc
	cp $< $@
openssl.clang: openssl1.clang
	cp $< $@
openssl.O0: openssl2.O0
	cp $< $@
openssl.O1: openssl2.O1
	cp $< $@
openssl.O2: openssl2.O2
	cp $< $@
openssl.O3: openssl2.O3
	cp $< $@

# vary compiler
openssl1.%: $(SSL).tar.gz
	rm -rf $(SSL)
	tar -xvzf $(SSL).tar.gz
	cd $(SSL) && CC=$* CFLAGS="-g" ./config && nice make -j16
	cp $(SSL)/apps/openssl openssl1.$*

# vary -O
openssl2.%: $(SSL).tar.gz
	rm -rf $(SSL)
	tar -xvzf $(SSL).tar.gz
	cd $(SSL) && CFLAGS="-$* -g" ./config && nice make -j16
	cp $(SSL)/apps/openssl openssl2.$*

$(eval $(call add_comparison, openssl-bycompiler, openssl.gcc, openssl.clang))
$(eval $(call add_comparison, openssl-byopt-O0-O1, openssl.O0, openssl.O1))
$(eval $(call add_comparison, openssl-byopt-O0-O2, openssl.O0, openssl.O2))
$(eval $(call add_comparison, openssl-byopt-O0-O3, openssl.O0, openssl.O3))
$(eval $(call add_comparison, openssl-byopt-O1-O2, openssl.O1, openssl.O2))
$(eval $(call add_comparison, openssl-byopt-O1-O3, openssl.O1, openssl.O3))
$(eval $(call add_comparison, openssl-byopt-O2-O3, openssl.O2, openssl.O3))
