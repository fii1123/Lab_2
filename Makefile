SCANFLOWD_SRC=src/scanflowd/
SAFE_FUNCTIONS_SRC=src/scanflowd/safe_functions.c
NET_FLOW_SRC=src/scanflowd/net_flow.c

all: scanflowd

scanflowd: $(SCANFLOWD_SRC)scanflowd.c $(SAFE_FUNCTIONS_SRC) $(NET_FLOW_SRC)
	$(CC) $(CFLAGS) -I/scanflowd -o $@ $^ -lrt -lpthread

clean:
	rm -f scanflowd

install: all
	install -d -m 0755 /usr/bin/
	install -m 0755 scanflowd /usr/bin/
	
uninstall:
	rm -rf $(addprefix /usr/bin/, scanflowd)

deb:
	dpkg-buildpackage -D

mrproper:
	dh_clean

.PHONY: all install uninstall deb mrproper