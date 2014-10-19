CFLAGS?=	-Wall -O2 -g -std=c99
CXXFLAGS?=	-Wall -std=c++11 -I../sodium -g
CC?=	cc
CXX?=	c++
AR?=	ar
ARFLAGS?=	rcs
LIBS?=	-lcrypto -lsodium_contrib
LDFLAGS?=	-L../sodium

DEPS=	aead.h \
	common.h \
	util.h \
	nonce.h \
	encrypt.h
	
OBJS=	aead.o \
	util.o \
	main.o \
	nonce.o \
	kdf.o \
	encrypt.o
	
all: hpenc

hpenc: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o hpenc $(LIBS)

aead.o: aead.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c aead.cc -o aead.o

util.o: util.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c util.cc -o util.o

main.o: main.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c main.cc -o main.o

nonce.o: nonce.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c nonce.cc -o nonce.o

kdf.o: kdf.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c kdf.cc -o kdf.o

encrypt.o: encrypt.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c encrypt.cc -o encrypt.o

clean:
	rm $(OBJS) hpenc || true

.PHONY: clean