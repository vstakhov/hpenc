SUBDIRS=	src

all: subdirs

subdirs:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir; \
	done

clean:
	for dir in $(SUBDIRS) ; do \
		$(MAKE) -C $$dir clean; \
	done

install:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir install; \
	done

.PHONY: subdirs clean install
