include ../make.include

SSL1 = openssl-1.1.1w
SSL2 = openssl-1.0.2u

EXES = $(SSL1).bin $(SSL2).bin
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

$(eval $(call add_comparison, openssl, $(SSL1).bin, $(SSL2).bin))

$(SSL1).bin: $(SSL1).tar.gz
	rm -rf $(SSL1)
	tar -xvzf $(SSL1).tar.gz
	cd $(SSL1) && CC=$* CFLAGS="-g -O2" ./config && nice make -j16
	cp $(SSL1)/apps/openssl $@

$(SSL2).bin: $(SSL2).tar.gz
	rm -rf $(SSL2)
	tar -xvzf $(SSL2).tar.gz
	cd $(SSL2) && CC=$* CFLAGS="-g -O2" ./config && nice make -j16
	cp $(SSL2)/apps/openssl $@