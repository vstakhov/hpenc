COPTFLAGS?=	-O2
CFLAGS?=	-Wall -g -std=c99 $(COPTFLAGS)
CXXFLAGS?=	-Wall -std=c++11 -I../sodium -g $(COPTFLAGS)
CC?=	cc
CXX?=	c++
AR?=	ar
ARFLAGS?=	rcs

DEPS= chacha.h \
	crypto_onetimeauth_poly1305.h \
	crypto_stream_chacha20.h \
	crypto_verify_16.h \
	crypto_verify_32.h \
	crypto_verify_64.h \
	export.h \
	poly1305_donna32.h \
	poly1305_donna64.h \
	poly1305_donna.h

OBJS=	auth_poly1305_donna.o \
	onetimeauth_poly1305.o \
	stream_chacha20_api.o \
	stream_chacha20_ref.o \
	verify_16.o \
	verify_poly1305_donna.o
	
all: libsodium_contrib.a

libsodium_contrib.a: $(OBJS)
	$(AR) $(ARFLAGS) libsodium_contrib.a $(OBJS)
	
auth_poly1305_donna.o: auth_poly1305_donna.c $(DEPS)
	$(CC) $(CFLAGS) -c auth_poly1305_donna.c -o auth_poly1305_donna.o

onetimeauth_poly1305.o: onetimeauth_poly1305.c $(DEPS)
	$(CC) $(CFLAGS) -c onetimeauth_poly1305.c -o onetimeauth_poly1305.o
	
stream_chacha20_api.o: stream_chacha20_api.c $(DEPS)
	$(CC) $(CFLAGS) -c stream_chacha20_api.c -o stream_chacha20_api.o
	
stream_chacha20_ref.o: stream_chacha20_ref.c $(DEPS)
	$(CC) $(CFLAGS) -c stream_chacha20_ref.c -o stream_chacha20_ref.o
	
verify_16.o: verify_16.c $(DEPS)
	$(CC) $(CFLAGS) -c verify_16.c -o verify_16.o

verify_poly1305_donna.o: verify_poly1305_donna.c $(DEPS)
	$(CC) $(CFLAGS) -c verify_poly1305_donna.c -o verify_poly1305_donna.o
	
clean:
	rm $(OBJS) libsodium_contrib.a || true

.PHONY: clean