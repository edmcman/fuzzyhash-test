include ../make.include

SSL102u = openssl-1.0.2u
SSL111 = openssl-1.1.1
SSL111q = openssl-1.1.1q
SSL111v = openssl-1.1.1v
SSL111w = openssl-1.1.1w

EXES = $(SSL102u).bin $(SSL111).bin $(SSL111q).bin $(SSL111v).bin $(SSL111w).bin

$(foreach EXE, $(EXES), $(eval $(call add_target, $(EXE))))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.1.1v, $(SSL111w).bin, $(SSL111v).bin))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.1.1q, $(SSL111w).bin, $(SSL111q).bin))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.1.1, $(SSL111w).bin, $(SSL111).bin))

$(eval $(call add_comparison, openssl-byversion-1.1.1w-vs-1.0.2u, $(SSL111w).bin, $(SSL102u).bin))


%.bin: %.tar.gz
	rm -rf $*
	tar -xvzf $*.tar.gz
	cd $* && ./config -g && nice make -j16
	cp $*/apps/openssl $@
