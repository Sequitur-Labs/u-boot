# ifndef __SM_FUNC_H__
# define __SM_FUNC_H__

#include <linux/types.h>

u32 tee_version(void);
void tee_final(void);

u32 tee_load(unsigned int tee_destaddr, /* where to place TEE in DDR: destination */
	     unsigned int tee_loadaddr, /* where TEE is loaded in DDR */
	     unsigned int tee_length,   /* size of TEE -bytes */
	     unsigned int tee_arg0,
	     unsigned int tee_arg1,
	     unsigned int tee_arg2);

u32 sli_decrypt(uint32_t comp_src,uint32_t comp_dst,uint32_t len,uint32_t keyselect);


#define GET_BLC 0
#define SET_BLC_MAX 1
#define DECREMENT_BLC 2
u32 blc_op(unsigned int op, unsigned int *value);

u32 handle_certs( uint32_t cert_addr );

# endif
