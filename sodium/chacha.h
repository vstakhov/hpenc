/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#include <sys/types.h>
#include <stddef.h>

struct chacha_ctx {
	unsigned input[16];
};

#define CHACHA_MINKEYLEN 	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

void chacha_keysetup(struct chacha_ctx *x, const unsigned char *k, unsigned int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const unsigned char *iv, const unsigned char *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const unsigned char *m,
    unsigned char *c, unsigned int bytes);

#endif	/* CHACHA_H */

