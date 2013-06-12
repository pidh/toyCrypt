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
#ifndef	__SHA256_H__
#define	__SHA256_H__

void SHA256_Calc(void *_ctx, const u1 *b, u4 len);
void *SHA256_Init(void);
void SHA256_Finish(void *_ctx, u1 *digest);

#endif

