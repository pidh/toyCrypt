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


int
HMAC_SHA256_Calc(const u1 *text, int text_len, const u1 *key, int key_len, u1 *digest)
{
	u1	tmp[32];	/* L=32 */
	u1	pad[64];
	void	*ctx;
	int	i;

	if(key_len > 64) {
		ctx = SHA256_Init();
		if(ctx == NULL)
			return(-1);
		SHA256_Calc(ctx, key, key_len);
		SHA256_Finish(ctx, tmp);
		key = tmp;
		key_len = sizeof(tmp);
	}

	MEMSET(pad, 0x36, sizeof(pad));
	for(i = 0;i < key_len;i++)
		pad[i] ^= key[i];

	ctx = SHA256_Init();
	if(ctx == NULL)
		return(-1);
	SHA256_Calc(ctx, pad, sizeof(pad));
	SHA256_Calc(ctx, text, text_len);
	SHA256_Finish(ctx, digest);

	for(i = 0;i < sizeof(pad);i++)
		pad[i] ^= 0x5c ^ 0x36;

	ctx = SHA256_Init();
	if(ctx == NULL)
		return(-1);
	SHA256_Calc(ctx, pad, sizeof(pad));
	SHA256_Calc(ctx, digest, 32);
	SHA256_Finish(ctx, digest);

	return(0);
}
