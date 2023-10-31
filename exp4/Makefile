include ../make.include

SSL1 = openssl-1.1.1w
SSL2 = openssl-1.0.2u
SSL3 = openssl-1.1.1v

EXES = $(SSL1).bin $(SSL2).bin $(SSL3).bin
$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.0.2u, $(SSL1).bin, $(SSL2).bin))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.1.1v, $(SSL1).bin, $(SSL3).bin))


$(SSL1).bin: $(SSL1).tar.gz
	rm -rf $(SSL1)
	tar -xvzf $(SSL1).tar.gz
	cd $(SSL1) && ./config -g && nice make -j16
	cp $(SSL1)/apps/openssl $@

$(SSL2).bin: $(SSL2).tar.gz
	rm -rf $(SSL2)
	tar -xvzf $(SSL2).tar.gz
	cd $(SSL2) && ./config -g && nice make -j16
	cp $(SSL2)/apps/openssl $@

$(SSL3).bin: $(SSL3).tar.gz
	rm -rf $(SSL3)
	tar -xvzf $(SSL3).tar.gz
	cd $(SSL3) && ./config -g && nice make -j16
	cp $(SSL3)/apps/openssl $@
