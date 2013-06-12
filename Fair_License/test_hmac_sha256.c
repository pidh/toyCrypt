/*
** Copyright 2013 pidh <github360@yahoo.co.jp>. All rights reserved.
**
** Usage of the works is permitted provided that this instrument is retained
** with the works, so that any entity that uses the works is notified of
** this instrument.
**
** DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "comtypes.h"
#include "hmac_sha256.h"

static void
test(u1 *text, int text_len, u1 *key, int key_len, u1 *correct_digest)
{
	u1 digest[32];
	int i;

	if(HMAC_SHA256_Calc(text, text_len, key, key_len, digest)) {
		printf("some error\n");
		return;
	}

	if(memcmp(correct_digest, digest, 32)) {
		printf("correct is :");
		for(i = 0;i < 32;i++)
			printf("%02x ", correct_digest[i]);
		printf("\n");
		printf("result is :");
		for(i = 0;i < 32;i++)
			printf("%02x ", digest[i]);
		printf("\n");
	}
	else {
		printf("test passed: ");
		for(i = 0;i < 32;i++)
			printf("%02x ", digest[i]);
		printf("\n");
	}
}

static u1 text1[3] = {
	'a', 'b', 'c'
};
static u1 key1[32] = {
	      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20
};
static u1 digest1[32] = { 
	0xa2, 0x1b, 0x1f, 0x5d, 0x4c, 0xf4, 0xf7, 0x3a,
	0x4d, 0xd9, 0x39, 0x75, 0x0f, 0x7a, 0x06, 0x6a,
	0x7f, 0x98, 0xcc, 0x13, 0x1c, 0xb1, 0x6a, 0x66,
	0x92, 0x75, 0x90, 0x21, 0xcf, 0xab, 0x81, 0x81
};

static u1 text2[56] = {
	'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e',
	'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
	'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i',
	'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
	'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm',
	'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
	'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'
};
static u1 key2[32] = {
	      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20
};
static u1 digest2[] = { 
	0x10, 0x4f, 0xdc, 0x12, 0x57, 0x32, 0x8f, 0x08,
	0x18, 0x4b, 0xa7, 0x31, 0x31, 0xc5, 0x3c, 0xae,
	0xe6, 0x98, 0xe3, 0x61, 0x19, 0x42, 0x11, 0x49,
	0xea, 0x8c, 0x71, 0x24, 0x56, 0x69, 0x7d, 0x30
};

static u1 text3[112] = {
	'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e',
	'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
	'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i',
	'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
	'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm',
	'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
	'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q',
	'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e',
	'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
	'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i',
	'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
	'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm',
	'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
	'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'
};
static u1 key3[32] = {
	      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20
};
static u1 digest3[] = { 
	0x47, 0x03, 0x05, 0xfc, 0x7e, 0x40, 0xfe, 0x34,
	0xd3, 0xee, 0xb3, 0xe7, 0x73, 0xd9, 0x5a, 0xab,
	0x73, 0xac, 0xf0, 0xfd, 0x06, 0x04, 0x47, 0xa5,
	0xeb, 0x45, 0x95, 0xbf, 0x33, 0xa9, 0xd1, 0xa3
};

static u1 text4[8] = {
	0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
};
static u1 key4[32] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static u1 digest4[] = { 
	0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6,
	0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5,
	0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c,
	0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7
};

static u1 text5[28] = {
	'w', 'h', 'a', 't', ' ', 'd', 'o', ' ',
	'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
	'f', 'o', 'r', ' ', 'n', 'o', 't', 'h',
	'i', 'n', 'g', '?'
};
static u1 key5[4] = {
	'J', 'e', 'f', 'e'
};
static u1 digest5[] = {
	0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
	0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
	0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
	0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
};

static u1 text6[50] = {
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xdd, 0xdd
};
static u1 key6[32] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
static u1 digest6[] = {
	0xcd, 0xcb, 0x12, 0x20, 0xd1, 0xec, 0xcc, 0xea,
	0x91, 0xe5, 0x3a, 0xba, 0x30, 0x92, 0xf9, 0x62,
	0xe5, 0x49, 0xfe, 0x6c, 0xe9, 0xed, 0x7f, 0xdc,
	0x43, 0x19, 0x1f, 0xbd, 0xe4, 0x5c, 0x30, 0xb0
};

static u1 text7[50] = {
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
	0xcd, 0xcd
};
static u1 key7[37] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25
};
static u1 digest7[] = {
	0xd4, 0x63, 0x3c, 0x17, 0xf6, 0xfb, 0x8d, 0x74,
	0x4c, 0x66, 0xde, 0xe0, 0xf8, 0xf0, 0x74, 0x55,
	0x6e, 0xc4, 0xaf, 0x55, 0xef, 0x07, 0x99, 0x85,
	0x41, 0x46, 0x8e, 0xb4, 0x9b, 0xd2, 0xe9, 0x17
};

static u1 text8[20] = {
	'T', 'e', 's', 't', ' ', 'W', 'i', 't',
	'h', ' ', 'T', 'r', 'u', 'n', 'c', 'a',
	't', 'i', 'o', 'n'
};
static u1 key8[32] = {
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
};
static u1 digest8[] = {
	0x75, 0x46, 0xaf, 0x01, 0x84, 0x1f, 0xc0, 0x9b,
	0x1a, 0xb9, 0xc3, 0x74, 0x9a, 0x5f, 0x1c, 0x17,
	0xd4, 0xf5, 0x89, 0x66, 0x8a, 0x58, 0x7b, 0x27,
	0x00, 0xa9, 0xc9, 0x7c, 0x11, 0x93, 0xcf, 0x42
};

static u1 text9[54] = {
	'T', 'e', 's', 't', ' ', 'U', 's', 'i',
	'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e',
	'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B',
	'l', 'o', 'c', 'k', '-', 'S', 'i', 'z',
	'e', ' ', 'K', 'e', 'y', ' ', '-', ' ',
	'H', 'a', 's', 'h', ' ', 'K', 'e', 'y',
	' ', 'F', 'i', 'r', 's', 't'
};
static u1 key9[80] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
static u1 digest9[] = {
	0x69, 0x53, 0x02, 0x5e, 0xd9, 0x6f, 0x0c, 0x09,
	0xf8, 0x0a, 0x96, 0xf7, 0x8e, 0x65, 0x38, 0xdb,
	0xe2, 0xe7, 0xb8, 0x20, 0xe3, 0xdd, 0x97, 0x0e,
	0x7d, 0xdd, 0x39, 0x09, 0x1b, 0x32, 0x35, 0x2f
};

static u1 text10[73] = {
	'T', 'e', 's', 't', ' ', 'U', 's', 'i',
	'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e',
	'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B',
	'l', 'o', 'c', 'k', '-', 'S', 'i', 'z',
	'e', ' ', 'K', 'e', 'y', ' ', 'a', 'n',
	'd', ' ', 'L', 'a', 'r', 'g', 'e', 'r',
	' ', 'T', 'h', 'a', 'n', ' ', 'O', 'n',
	'e', ' ', 'B', 'l', 'o', 'c', 'k', '-',
	'S', 'i', 'z', 'e', ' ', 'D', 'a', 't',
	'a'
};
static u1 key10[80] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
static u1 digest10[] = {
	0x63, 0x55, 0xac, 0x22, 0xe8, 0x90, 0xd0, 0xa3,
	0xc8, 0x48, 0x1a, 0x5c, 0xa4, 0x82, 0x5b, 0xc8,
	0x84, 0xd3, 0xe7, 0xa1, 0xff, 0x98, 0xa2, 0xfc,
	0x2a, 0xc7, 0xd8, 0xe0, 0x64, 0xc3, 0xb2, 0xe6
};

int
main(int ac, char *av[])
{
	test(text1, sizeof(text1), key1, sizeof(key1), digest1);
	test(text2, sizeof(text2), key2, sizeof(key2), digest2);
	test(text3, sizeof(text3), key3, sizeof(key3), digest3);
	test(text4, sizeof(text4), key4, sizeof(key4), digest4);
	test(text5, sizeof(text5), key5, sizeof(key5), digest5);
	test(text6, sizeof(text6), key6, sizeof(key6), digest6);
	test(text7, sizeof(text7), key7, sizeof(key7), digest7);
	test(text8, sizeof(text8), key8, sizeof(key8), digest8);
	test(text9, sizeof(text9), key9, sizeof(key9), digest9);
	test(text10, sizeof(text10), key10, sizeof(key10), digest10);

	return(0);
}
