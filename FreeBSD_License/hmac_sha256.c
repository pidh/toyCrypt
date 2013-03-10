/*
** Copyright 2013 pidh <github360@yahoo.co.jp>. All rights reserved.
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


void
HMAC_SHA256_Calc(u1 *text, int text_len, u1 *key, int key_len, u1 *digest)
{
	u1	tmp[32];	/* L=32 */
	u1	pad[64];
	void	*ctx;
	int	i;

	if(key_len > 64) {
		ctx = SHA256_Init();
		SHA256_Calc(ctx, key, key_len);
		SHA256_Finish(ctx, tmp);
		key = tmp;
		key_len = sizeof(tmp);
	}

	MEMSET(pad, 0x36, sizeof(pad));
	for(i = 0;i < key_len;i++)
		pad[i] ^= key[i];

	ctx = SHA256_Init();
	SHA256_Calc(ctx, pad, sizeof(pad));
	SHA256_Calc(ctx, text, text_len);
	SHA256_Finish(ctx, digest);

	for(i = 0;i < sizeof(pad);i++)
		pad[i] ^= 0x5c ^ 0x36;

	ctx = SHA256_Init();
	SHA256_Calc(ctx, pad, sizeof(pad));
	SHA256_Calc(ctx, digest, 32);
	SHA256_Finish(ctx, digest);
}
