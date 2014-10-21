PANDOC?=	pandoc
INSTALL?=	/usr/bin/install
PREFIX?=	/usr/local

all:

man:	hpenc.1

hpenc.1:	hpenc.1.md
	$(PANDOC) -s -f markdown -t man -o hpenc.1 hpenc.1.md

install:	hpenc.1
	$(INSTALL) -m 0644 hpenc.1 $(DESTDIR)$(PREFIX)/share/man/man1/hpenc.1

clean:

.PHONY:	install clean
