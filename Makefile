SUBDIRS=	src

all: chacha-opt poly1305-opt subdirs

subdirs: chacha-opt/bin/chacha.lib poly1305-opt/bin/poly1305.lib
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir; \
	done

chacha-opt/bin/chacha.lib: chacha-opt-configure
	(cd chacha-opt ; make lib)

poly1305-opt/bin/poly1305.lib: poly1305-opt-configure
	(cd poly1305-opt ; make lib)

clean: chacha-opt-configure poly1305-opt-configure
	for dir in $(SUBDIRS) chacha-opt poly1305-opt ; do \
		$(MAKE) -C $$dir clean; \
	done

install:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir install; \
	done

chacha-opt-configure:
	(cd chacha-opt ; ./configure)

poly1305-opt-configure:
	(cd poly1305-opt ; ./configure)

.PHONY: subdirs clean install poly1305-opt-configure chacha-opt-configure