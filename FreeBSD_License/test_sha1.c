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
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "sha1.h"

static void
test(u1 *data, u4 len, u1 *correct_digest)
{
	u1	digest[20];
	void	*ctx;
	int	i;

	ctx = SHA1_Init();
	if(ctx == NULL) {
		printf("no memory\n");
		exit(1);
	}
	SHA1_Calc(ctx, data, len);
	SHA1_Finish(ctx, digest);

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
