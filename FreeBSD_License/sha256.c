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
#include "sha256.h"

#define	ROTR(n, w)	(((w) >> (n)) | ((w) << (32-(n))))
#define	ROTL(n, w)	(((w) << (n)) | ((w) >> (32-(n))))

#define	GET4(p)		(((u4)((p)[0]) << 24) |\
				((u4)((p)[1]) << 16) |\
				((u4)((p)[2]) << 8) |\
				((u4)((p)[3]) << 0))
#define	STORE4(p, v)	do { *((p) + 0) = (v) >> 24;\
				*((p) + 1) = (v) >> 16;\
				*((p) + 2) = (v) >> 8;\
				*((p) + 3) = (v) >> 0;\
			} while(0)

#define	Ch(x, y, z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define	Parity(x, y, z)	((x) ^ (y) ^ (z))
#define	Maj(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define	Sigma0(x)	(ROTR(2, (x)) ^ ROTR(13, (x)) ^ ROTR(22, (x)))
#define	Sigma1(x)	(ROTR(6, (x)) ^ ROTR(11, (x)) ^ ROTR(25, (x)))
#define	SmallSigma0(x)	(ROTR(7, (x)) ^ ROTR(18, (x)) ^ ((x)>>3))
#define	SmallSigma1(x)	(ROTR(17, (x)) ^ ROTR(19, (x)) ^ ((x)>>10))

typedef struct {
	u4	H[8];
	u4	W[64];
	u4	lenM;
	u4	totalLow;
	u4	totalHigh;
	u1	M[512/8];
} SHA256_CTX;

static u4 K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
SHA256(void *_ctx, u1 *M)
{
	SHA256_CTX *ctx = (SHA256_CTX *)_ctx;
	int	t;
	u4	a, b, c, d, e, f, g, h;
	u4	T1, T2;

	for(t = 0;t < 16;t++) {
		ctx->W[t] = GET4(M);
		M += 4;
	}

	for(;t < 64;t++) {
		ctx->W[t] = SmallSigma1(ctx->W[t-2]) + ctx->W[t-7]
				+ SmallSigma0(ctx->W[t-15]) + ctx->W[t-16];
	}

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	for(t = 0;t < 64;t++) {
		T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + ctx->W[t];
		T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;
}

void *
SHA256_Init(void)
{
	SHA256_CTX *ctx;

	ctx = MALLOC(sizeof(SHA256_CTX));
	if(ctx == NULL)
		return(NULL);

	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;


	ctx->lenM = 0;
	ctx->totalLow = 0;
	ctx->totalHigh = 0;

	return((void *)ctx);
}

void
SHA256_Calc(void *_ctx, u1 *b, u4 len)
{
	SHA256_CTX *ctx = (SHA256_CTX *)_ctx;
	u4	lenM = ctx->lenM;

	ctx->totalLow += len;
	if(ctx->totalLow < len)
		ctx->totalHigh++;

	if(lenM) {
		if(lenM + len < 64) {
			MEMCPY(ctx->M + lenM, b, len);
			ctx->lenM += len;
			return;
		}
		MEMCPY(ctx->M + lenM, b, 64 - lenM);
		SHA256(ctx, ctx->M);
		b += 64 - lenM;
		len -= 64 - lenM;
		ctx->lenM = 0;
	}
	while(len >= 64) {
		SHA256(ctx, b);
		b += 64;
		len -= 64;
	}
	if(len) {
		MEMCPY(ctx->M, b, len);
		ctx->lenM = len;
	}
}

void
SHA256_Finish(void *_ctx, u1 *digest)
{
	SHA256_CTX *ctx = (SHA256_CTX *)_ctx;
	u4	lenM = ctx->lenM;
	int	i;

	ctx->M[lenM] = 0x80;
	if(lenM > 64 - (1+8)) {
		if(lenM != (64-1))
			MEMSET(&ctx->M[lenM+1], 0, (64-1)-lenM);
		SHA256(ctx, ctx->M);
		MEMSET(ctx->M, 0, 64-8);
	}
	else {
		if((64-1-8)-lenM)
			MEMSET(&(ctx->M[lenM+1]), 0, (64-1-8)-lenM);
	}

	STORE4(&ctx->M[64-8], (ctx->totalHigh << 3) | (ctx->totalLow >> (32-3)));
	STORE4(&ctx->M[64-4], ctx->totalLow << 3);
	SHA256(ctx, ctx->M);

	for(i = 0;i < 8;i++)
		STORE4(digest+i*4, ctx->H[i]);

	FREE(_ctx);
}

