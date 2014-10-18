CFLAGS?=	-O2 -g -std=c99
CXXFLAGS?=	-std=c++11 -I../sodium -g
CC?=	cc
CXX?=	c++
AR?=	ar
ARFLAGS?=	rcs
LIBS?=	-lcrypto -lsodium_contrib
LDFLAGS?=	-L../sodium

DEPS=	aead.h \
	util.h
	
OBJS=	aead.o \
	util.o
	
all: hpenc

hpenc: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o hpenc $(LIBS)

aead.o: aead.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c aead.cc -o aead.o

util.o: util.cc $(DEPS)
	$(CXX) $(CXXFLAGS) -c util.cc -o util.o

clean:
	rm $(OBJS) hpenc || true

.PHONY: clean