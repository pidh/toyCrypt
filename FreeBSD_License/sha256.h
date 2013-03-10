#ifndef	__SHA256_H__
#define	__SHA256_H__

/*>>Platform depends part*/
typedef	unsigned int	u4;
typedef	unsigned char	u1;
/*<<Platform depends part*/

void SHA256_Calc(void *_ctx, u1 *b, u4 len);
void *SHA256_Init(void);
void SHA256_Finish(void *_ctx, u1 *digest);
#endif

