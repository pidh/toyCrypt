/*
** Copyright 2011-2013 pidh <github360@yahoo.co.jp>. All rights reserved.
**
** Usage of the works is permitted provided that this instrument is retained
** with the works, so that any entity that uses the works is notified of
** this instrument.
**
** DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
**
*/
/*>>Platform depends part*/
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define	MEMCMP	memcmp
#define	MEMCPY	memcpy

#define	MALLOC	malloc
#define	FREE	free
/*<<Platform depends part*/
#include "comtypes.h"
#include "aes.h"

#define	RotWord(t)	(((t) >> 8) | ((t) << 24))
#define	SubWord(t)	((((u4)SBOX[((t) >> 0) & 0xff]) << 0) |\
				(((u4)SBOX[((t) >> 8) & 0xff]) << 8)|\
				(((u4)SBOX[((t) >> 16) & 0xff]) << 16)|\
				(((u4)SBOX[((t) >> 24) & 0xff]) << 24))
#if 1//may little endian
#define	MkWord(b0, b1, b2, b3)	((((u4)(b0)) << 0)|\
					(((u4)(b1)) << 8)|\
					(((u4)(b2)) << 16)|\
					(((u4)(b3)) << 24))
#else
#define	MkWord(b0, b1, b2, b3)	((((u4)(b0)) << 24)|\
					(((u4)(b1)) << 16)|\
					(((u4)(b2)) << 8)|\
					(((u4)(b3)) << 0))
#endif

typedef struct {
	char	Nr;
	u4	W[1];
} AES_CTX;

static u1 SBOX[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static u1 ISBOX[] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define	AddRoundKey(s, k)	do {\
					*((s) + 0) ^= *((k) + 0);\
					*((s) + 1) ^= *((k) + 1);\
					*((s) + 2) ^= *((k) + 2);\
					*((s) + 3) ^= *((k) + 3);\
				} while(0)

static void
SubBytes(u1 *s)
{
	int	i;

	for(i = 0;i < 16;i++) {
		*s = SBOX[*s];
		s++;
	}
}

static void
InvSubBytes(u1 *s)
{
	int	i;

	for(i = 0;i < 16;i++) {
		*s = ISBOX[*s];
		s++;
	}
}


static void
ShiftRows(u1 *s)
{
	u1	t;

	//r=1
	t = s[1];
	s[1] = s[5];
	s[5] = s[9];
	s[9] = s[13];
	s[13] = t;

	//r=2
	t = s[2];
	s[2] = s[10];
	s[10] = t;
	t = s[6];
	s[6] = s[14];
	s[14] = t;

	//r=3
	t = s[3];
	s[3] = s[15];
	s[15] = s[11];
	s[11] = s[7];
	s[7] = t;
}

static void
InvShiftRows(u1 *s)
{
	u1	t;

	//r=1
	t = s[1];
	s[1] = s[13];
	s[13] = s[9];
	s[9] = s[5];
	s[5] = t;

	//r=2
	t = s[2];
	s[2] = s[10];
	s[10] = t;
	t = s[6];
	s[6] = s[14];
	s[14] = t;

	//r=3
	t = s[3];
	s[3] = s[7];
	s[7] = s[11];
	s[11] = s[15];
	s[15] = t;
}

static u1
mulx2(b)
{
	if(b & 0x80)
		return((b << 1) ^ 0x1b);
	return(b << 1);
}

/* m must be less than 0x10 */
#define	mulx09(v)	mul4(v, 0x09)
#define	mulx0b(v)	mul4(v, 0x0b)
#define	mulx0d(v)	mul4(v, 0x0d)
#define	mulx0e(v)	mul4(v, 0x0e)

static u1
mul4(v, m)
{
	u1 sum = 0;
	int	i;
	for(i = 0;i < 4;i++) {
		if(sum & 0x80)
			sum = (sum << 1) ^ 0x1b;
		else
			sum = sum << 1;

		if(m & 0x8)
			sum ^= v;
		m <<= 1;
	}

	return(sum);
}



static void
MixColumns(u1 *s)
{
	int	i;
	u1	s0x2, s1x2, s2x2, s3x2, ssss;

	for(i = 0;i < 4;i++) {
		s0x2 = mulx2(s[0]);
		s1x2 = mulx2(s[1]);
		s2x2 = mulx2(s[2]);
		s3x2 = mulx2(s[3]);
		ssss = s[0] ^ s[1] ^ s[2] ^ s[3];

		s[0] ^= s0x2 ^ s1x2 ^ ssss;
		s[1] ^= s1x2 ^ s2x2 ^ ssss;
		s[2] ^= s2x2 ^ s3x2 ^ ssss;
		s[3] ^= s0x2 ^ s3x2 ^ ssss;
		s += 4;
	}
}

static void
InvMixColumns(u1 *s)
{
	int	i;
	u1	s0, s1, s2, s3;

	for(i = 0;i < 4;i++) {
		s0 = mulx0e(s[0]) ^ mulx0b(s[1]) ^ mulx0d(s[2]) ^ mulx09(s[3]);
		s1 = mulx09(s[0]) ^ mulx0e(s[1]) ^ mulx0b(s[2]) ^ mulx0d(s[3]);
		s2 = mulx0d(s[0]) ^ mulx09(s[1]) ^ mulx0e(s[2]) ^ mulx0b(s[3]);
		s3 = mulx0b(s[0]) ^ mulx0d(s[1]) ^ mulx09(s[2]) ^ mulx0e(s[3]);
		s[0] = s0;
		s[1] = s1;
		s[2] = s2;
		s[3] = s3;
		s += 4;
	}
}

void
AES_Cipher(void *_ctx, u1 *data)
{
	char	r;
	AES_CTX	*ctx = (AES_CTX *)_ctx;
	u4	*w = ctx->W;

	AddRoundKey((u4 *)data, w);
	w += 4;
	for(r = 1;r < ctx->Nr;r++) {
		SubBytes(data);
		ShiftRows(data);
		MixColumns(data);
		AddRoundKey((u4 *)data, w);

		w += 4;
	}

	SubBytes(data);
	ShiftRows(data);
	AddRoundKey((u4 *)data, w);
}

void
AES_InvCipher(void *_ctx, u1 *data)
{
	char	r;
	AES_CTX	*ctx = (AES_CTX *)_ctx;
	u4	*w = ctx->W;

	w = &w[ctx->Nr * Nb];
	AddRoundKey((u4 *)data, w);
	w -= 4;

	for(r = 1;r < ctx->Nr;r++) {
		InvShiftRows(data);
		InvSubBytes(data);
		AddRoundKey((u4 *)data, w);
		InvMixColumns(data);
		w -= 4;
	}

	InvShiftRows(data);
	InvSubBytes(data);
	AddRoundKey((u4 *)data, w);
}


void *
AES_Init(u1 *key, int Nk)
{
	AES_CTX	*ctx;
	char	Nr;
	u4	*w;
	static u1 Rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

	switch(Nk) {
	case 4:
		Nr = 10;
		break;
	case 6:
		Nr = 12;
		break;
	case 8:
		Nr = 14;
		break;
	}

	ctx = MALLOC(sizeof(AES_CTX) + sizeof(u4) * Nb * (Nr + 1) - sizeof(u4));
	if(ctx) {
		u4	temp;
		int	i;

		ctx->Nr = Nr;

		w = ctx->W;
		for(i = 0;i < Nk;i++)
			w[i] = MkWord(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);

		for(i = Nk;i < Nb * (Nr + 1);i++) {
			temp = w[i-1];
			if((i % Nk) == 0) {
				temp = RotWord(temp);
				temp = SubWord(temp);
				temp = temp ^ Rcon[i/Nk - 1];
			}
			else if(Nk > 6 && (i % Nk) == 4)
				temp = SubWord(temp);
			w[i] = w[i-Nk] ^ temp;
		}
	}
	return(ctx);
}

void
AES_Finish(void *ctx)
{
	FREE(ctx);
}

