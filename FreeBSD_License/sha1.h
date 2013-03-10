#ifndef	__SHA1_H__
#define	__SHA1_H__

/*>>Platform depends part*/
typedef	unsigned int	u4;
typedef	unsigned char	u1;
/*<<Platform depends part*/

void SHA1_Calc(void *_ctx, u1 *b, u4 len);
void *SHA1_Init(void);
void SHA1_Finish(void *_ctx, u1 *digest);
#endif

