CFLAGS += -Wall

VERSION=0.01.10

BINDIR=/usr/bin
MANDIR=/usr/share/man/man8

eventstat: eventstat.o
	$(CC) $< -lm -o $@

eventstat.8.gz: eventstat.8
	gzip -c $< > $@

dist:
	git archive --format=tar --prefix="eventstat-$(VERSION)/" V$(VERSION) | \
		gzip > eventstat-$(VERSION).tar.gz

clean:
	rm -f eventstat eventstat.o eventstat.8.gz
	rm -f eventstat-$(VERSION).tar.gz

install: eventstat eventstat.8.gz
	mkdir -p ${DESTDIR}${BINDIR}
	cp eventstat ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${MANDIR}
	cp eventstat.8.gz ${DESTDIR}${MANDIR}
