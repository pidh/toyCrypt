#ifndef __AES_H__
#define	__AES_H__
/*>>Platform depends part*/

typedef	unsigned int	u4;
typedef	unsigned char	u1;

/*<<Platform depends part*/

#define	Nb	4

void AES_Cipher(void *_ctx, u1 *data);
void AES_InvCipher(void *_ctx, u1 *data);
void *AES_Init(u1 *key, int Nk);
void AES_Finish(void *ctx);

#endif

