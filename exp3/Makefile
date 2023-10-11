SSL = openssl-1.1.1w

all: openssl1.gcc openssl1.clang openssl2.O0 openssl2.O3

# vary compiler
openssl1.%:
	rm -rf $(SSL)
	tar -xvzf $(SSL).tar.gz
	cd $(SSL) && CC=$* CFLAGS="-g" ./config && nice make -j16
	cp $(SSL)/apps/openssl openssl.$*

# vary -O
openssl2.%:
	rm -rf $(SSL)
	tar -xvzf $(SSL).tar.gz
	cd $(SSL) && CFLAGS="-$* -g" ./config && nice make -j16
	cp $(SSL)/apps/openssl openssl.$*
