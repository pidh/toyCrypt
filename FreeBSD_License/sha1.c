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
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
** TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
** OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
** WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
** ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
** THE POSSIBILITY OF SUCH DAMAGE.
*/
#define	TEST	/* enable selftest if defined */

/*>>Platform depends part*/
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

typedef	unsigned int	u4;
typedef	unsigned char	u1;
#define	MEMCPY	memcpy
#define	MEMSET	memset
#define	MALLOC	malloc
#define	FREE	free

/*<<Platform depends part*/

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
InitHash(void)
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
CalcHash(void *_ctx, u1 *b, u4 len)
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
FinishHash(void *_ctx, u1 *digest)
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

#if defined(TEST)
static void
test(u1 *data, u4 len, u1 *correct_digest)
{
	u1	digest[20];
	void	*ctx;
	int	i;

	ctx = InitHash();
	if(ctx == NULL) {
		printf("no memory\n");
		exit(1);
	}
	CalcHash(ctx, data, len);
	FinishHash(ctx, digest);

	if(memcmp(correct_digest, digest, 20)) {
		printf("correct is :");
		for(i = 0;i < 20;i++)
			printf("%02x ", correct_digest[i]);
		printf("\n");
		printf("result is :");
		for(i = 0;i < 20;i++)
			printf("%02x ", digest[i]);
		printf("\n");
	}
	else {
		printf("test passed: ");
		for(i = 0;i < 20;i++)
			printf("%02x ", digest[i]);
		printf("\n");
	}
}

static u1 test1_data[] = { 'a', 'b', 'c' };
static u1 test1_digest[] = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
static u1 test2_data[] = {
	'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
	'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i', 'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
	'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm', 'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
	'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'
};
static u1 test2_digest[] = { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };

static u1 test3_digest[] = { 0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f };


int
main(int ac, char *av[])
{
	char	*p;

	test(test1_data, sizeof(test1_data), test1_digest);
	test(test2_data, sizeof(test2_data), test2_digest);
	p = malloc(1000000);
	memset(p, 'a', 1000000);
	test(p, 1000000, test3_digest);
	free(p);

	return(0);
}
#endif
