include ../make.include

SSL = openssl-1.1.1w

# default target
all:
	@echo all

EXES = openssl.gcc openssl.clang openssl.O0 openssl.O3
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

openssl.%: openssl1.%
	cp $< $@
openssl.%: openssl2.%
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
$(eval $(call add_comparison, openssl-byopt, openssl.o0, openssl.o3))
