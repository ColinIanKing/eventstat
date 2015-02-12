VERSION=0.01.35

CFLAGS += -Wall -Wextra -DVERSION='"$(VERSION)"'

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

eventstat: eventstat.o
	$(CC) $(CFLAGS) $< -lm -o $@ $(LDFLAGS)

eventstat.8.gz: eventstat.8
	gzip -c $< > $@

dist:
	rm -rf eventstat-$(VERSION)
	mkdir eventstat-$(VERSION)
	cp -rp Makefile eventstat.c eventstat.8 COPYING eventstat-$(VERSION)
	tar -zcf eventstat-$(VERSION).tar.gz eventstat-$(VERSION)
	rm -rf eventstat-$(VERSION)

clean:
	rm -f eventstat eventstat.o eventstat.8.gz
	rm -f eventstat-$(VERSION).tar.gz

install: eventstat eventstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp eventstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp eventstat.8.gz ${DESTDIR}${MANDIR}
