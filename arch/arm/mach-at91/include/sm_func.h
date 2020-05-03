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

u32 sli_encrypt(uint32_t comp_src,uint32_t comp_dst,uint32_t len,uint32_t keyselect);
u32 sli_decrypt(uint32_t comp_src,uint32_t comp_dst);

//Verify the signature of the payload using the public key.
/*
 * Currently only ECDSA 256 is supported but the signature length and key length will
 * make it easier to be flexible in the future.
 *
 * 'alg' is ignored.
 *
 * Returns '0' if verification succeeds
 */
u32 sli_verify_signature(uint32_t payload, uint32_t pl_length, uint32_t signature, uint32_t sig_length, uint32_t pubkey, uint32_t pk_length, uint32_t alg);

u32 sli_prov(uint32_t addr,uint32_t len,uint32_t index);
u32 sli_get_provstage(void);
u32 sli_set_provstage(uint32_t addr,uint32_t len,uint32_t stage);
u32 sli_set_aeskey(uint32_t addr,uint32_t len);
u32 sli_renew_component(uint32_t addr,uint32_t len);

#define GET_BLC 0
#define SET_BLC_MAX 1
#define DECREMENT_BLC 2
u32 blc_op(unsigned int op, unsigned int *value);

#define CORETEE_SAVE_SLIP_TO_NVM 1
u32 handle_coretee_slips( uint32_t slip_id, uint32_t slip_addr, uint32_t size );

# endif
