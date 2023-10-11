include ../make.include

SSL = openssl-1.1.1w

all: openssl.gcc openssl.clang openssl.O0 openssl.O3 openssl.gcc.fn2hash.csv openssl.gcc.fn2hash.json

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
