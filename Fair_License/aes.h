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
#ifndef __AES_H__
#define	__AES_H__

#define	Nb	4

void AES_Cipher(void *_ctx, u1 *data);
void AES_InvCipher(void *_ctx, u1 *data);
void *AES_Init(u1 *key, int Nk);
void AES_Finish(void *ctx);

#endif

