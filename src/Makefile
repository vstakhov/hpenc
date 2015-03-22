COPTFLAGS?=	-O2
CFLAGS+=	-Wall -g -std=c99 $(COPTFLAGS)
CXXFLAGS+=	-Wall -std=c++11 -I../chacha-opt/app/include \
		-I../poly1305-opt/app/include -g $(COPTFLAGS)
CC?=	cc
CXX?=	c++
AR?=	ar
ARFLAGS?=	rcs
LIBS+=	-lcrypto
LDFLAGS+=	-L../poly1305-opt/bin/ -L../chacha-opt/bin/ -pthread
INSTALL?=	/usr/bin/install
PREFIX?=	/usr/local

DEPS=	aead.h \
	common.h \
	util.h \
	nonce.h \
	encrypt.h \
	decrypt.h \
	thread_pool.h
	
OBJS=	aead.o \
	util.o \
	main.o \
	nonce.o \
	kdf.o \
	encrypt.o \
	decrypt.o 
	
all: hpenc

hpenc: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJS) \
		../chacha-opt/bin/chacha.lib ../poly1305-opt/bin/poly1305.lib \
		-o hpenc $(LIBS)

aead.o: aead.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c aead.cc -o aead.o

util.o: util.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c util.cc -o util.o

main.o: main.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c main.cc -o main.o

nonce.o: nonce.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c nonce.cc -o nonce.o

kdf.o: kdf.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c kdf.cc -o kdf.o

encrypt.o: encrypt.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c encrypt.cc -o encrypt.o

decrypt.o: decrypt.cc $(DEPS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c decrypt.cc -o decrypt.o

clean:
	rm $(OBJS) hpenc || true

install: hpenc
	$(INSTALL) -m 0755 hpenc $(DESTDIR)$(PREFIX)/bin/hpenc

.PHONY: clean install
