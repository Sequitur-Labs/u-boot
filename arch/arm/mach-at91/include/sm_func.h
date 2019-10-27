# ifndef __SM_FUNC_H__
# define __SM_FUNC_H__

u32 tee_version(void);
void tee_final(void);

u32 tee_load(unsigned int tee_destaddr, /* where to place TEE in DDR: destination */
	     unsigned int tee_loadaddr, /* where TEE is loaded in DDR */
	     unsigned int tee_length,   /* size of TEE -bytes */
	     unsigned int tee_arg0,
	     unsigned int tee_arg1,
	     unsigned int tee_arg2);

# endif
