/*
** Copyright 2011-2013 pidh <github360@yahoo.co.jp>. All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
** THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
** PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
** CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
** SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
** OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
** OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
** ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/*>>Platform depends part*/
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define	MEMCPY	memcpy
#define	MEMSET	memset
#define	MALLOC	malloc
#define	FREE	free

/*<<Platform depends part*/
#include "comtypes.h"
#include "sha1.h"

#define	ROTL(n, w)	(((w) << (n)) | ((w) >> (32-(n))))
#define	GET4(p)		(((u4)((p)[0]) << 24) |\
				((u4)((p)[1]) << 16) |\
				((u4)((p)[2]) << 8) |\
				((u4)((p)[3]) << 0))
#define	STORE4(p, v)	do { *(p + 0) = v >> 24;\
				*(p + 1) = v >> 16;\
				*(p + 2) = v >> 8;\
				*(p + 3) = v >> 0;\
			} while(0)

#define	Ch(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define	Parity(x, y, z)	((x) ^ (y) ^ (z))
#define	Maj(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))


typedef struct {
	u4	H0, H1, H2, H3, H4;
	u4	W[80];
	u4	lenM;
	u4	total;		// specification violation, we can handle ont 2^32-1 bits length
	u1	M[512/8];
} SHA1_CTX;

static void
Hash(void *_ctx, u1 *M)
{
	SHA1_CTX *ctx = (SHA1_CTX *)_ctx;
	int	t;
	u4	a, b, c, d, e;
	u4	T;

	for(t = 0;t < 16;t++) {
		ctx->W[t] = GET4(M);
		M += 4;
	}

	for(;t < 80;t++)
		ctx->W[t] = ROTL(1, ctx->W[t-3] ^ ctx->W[t-8] ^ ctx->W[t-14] ^ ctx->W[t-16]);

	a = ctx->H0;
	b = ctx->H1;
	c = ctx->H2;
	d = ctx->H3;
	e = ctx->H4;

	for(t = 0;t < 20;t++) {
		T = ROTL(5, a) + Ch(b, c, d) + e + 0x5a827999/*K[t]*/ + ctx->W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
//		printf("%02d:%08x %08x %08x %08x %08x\n", t, a, b, c, d, e);
	}

	for(;t < 40;t++) {
		T = ROTL(5, a) + Parity(b, c, d) + e + 0x6ed9eba1/*K[t]*/ + ctx->W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
//		printf("%02d:%08x %08x %08x %08x %08x\n", t, a, b, c, d, e);
	}

	for(;t < 60;t++) {
		T = ROTL(5, a) + Maj(b, c, d) + e + 0x8f1bbcdc/*K[t]*/ + ctx->W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
//		printf("%02d:%08x %08x %08x %08x %08x\n", t, a, b, c, d, e);
	}

	for(;t < 80;t++) {
		T = ROTL(5, a) + Parity(b, c, d) + e + 0xca62c1d6/*K[t]*/ + ctx->W[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
//		printf("%02d:%08x %08x %08x %08x %08x\n", t, a, b, c, d, e);
	}

	ctx->H0 += a;
	ctx->H1 += b;
	ctx->H2 += c;
	ctx->H3 += d;
	ctx->H4 += e;
}

void *
SHA1_Init(void)
{
	SHA1_CTX *ctx;

	ctx = MALLOC(sizeof(SHA1_CTX));
	if(ctx == NULL)
		return(NULL);

	ctx->H0 = 0x67452301;
	ctx->H1 = 0xefcdab89;
	ctx->H2 = 0x98badcfe;
	ctx->H3 = 0x10325476;
	ctx->H4 = 0xc3d2e1f0;

	ctx->lenM = 0;
	ctx->total = 0;

	return((void *)ctx);
}

void
SHA1_Calc(void *_ctx, u1 *b, u4 len)
{
	SHA1_CTX *ctx = (SHA1_CTX *)_ctx;
	u4	lenM = ctx->lenM;

	ctx->total += len;
	if(lenM) {
		if(lenM + len < 64) {
			MEMCPY(ctx->M + lenM, b, len);
			ctx->lenM += len;
			return;
		}
		MEMCPY(ctx->M + lenM, b, 64 - lenM);
		Hash(ctx, ctx->M);
		b += 64 - lenM;
		len -= 64 - lenM;
		ctx->lenM = 0;
	}
	while(len >= 64) {
		Hash(ctx, b);
		b += 64;
		len -= 64;
	}
	if(len) {
		MEMCPY(ctx->M, b, len);
		ctx->lenM = len;
	}
}

void
SHA1_Finish(void *_ctx, u1 *digest)
{
	SHA1_CTX *ctx = (SHA1_CTX *)_ctx;
	u4	lenM = ctx->lenM;

	ctx->M[lenM] = 0x80;
	if(lenM > 64 - (1+8)) {
		if(lenM != (64-1)) {
			MEMSET(&ctx->M[lenM+1], 0, (64-1)-lenM);
			Hash(ctx, ctx->M);
		}
		MEMSET(ctx->M, 0, 64-4);
	}
	else
		MEMSET(&(ctx->M[lenM+1]), 0, (64-1-4)-lenM);

	STORE4(&ctx->M[64-4], ctx->total * 8);
	Hash(ctx, ctx->M);

	STORE4(digest+0, ctx->H0);
	STORE4(digest+4, ctx->H1);
	STORE4(digest+8, ctx->H2);
	STORE4(digest+12, ctx->H3);
	STORE4(digest+16, ctx->H4);

	FREE(_ctx);
}

