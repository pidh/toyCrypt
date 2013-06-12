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
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "comtypes.h"
#include "sha256.h"

static void
test(u1 *data, u4 len, u1 *correct_digest)
{
	u1	digest[32];
	void	*ctx;
	int	i;

	ctx = SHA256_Init();
	if(ctx == NULL) {
		printf("no memory\n");
		exit(1);
	}
	SHA256_Calc(ctx, data, len);
	SHA256_Finish(ctx, digest);

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

static u1 test1_data[] = { 'a', 'b', 'c' };
static u1 test1_digest[] = { 
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};
static u1 test2_data[] = {
	'a', 'b', 'c', 'd', 'b', 'c', 'd', 'e', 'c', 'd', 'e', 'f', 'd', 'e', 'f', 'g',
	'e', 'f', 'g', 'h', 'f', 'g', 'h', 'i', 'g', 'h', 'i', 'j', 'h', 'i', 'j', 'k',
	'i', 'j', 'k', 'l', 'j', 'k', 'l', 'm', 'k', 'l', 'm', 'n', 'l', 'm', 'n', 'o',
	'm', 'n', 'o', 'p', 'n', 'o', 'p', 'q'
};
static u1 test2_digest[] = {
		0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
		0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
		0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
		0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
};

static u1 test3_digest[] = {
		0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
		0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
		0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
		0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
};


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
