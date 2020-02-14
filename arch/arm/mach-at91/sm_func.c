#ifdef CONFIG_CORETEE
typedef unsigned int u32;

# define M_FASTCALL         0x80000000
# define PM_BAD             0xffffffff
# define PM_OK              0

# define TEE_LOAD           (M_FASTCALL | 6)
# define SLI_DECRYPT        (M_FASTCALL | 7)
# define SLI_ENCRYPT		(M_FASTCALL | 8)


/*Need to sync up with CoreTEE OPTEE_SMC_FUNCID_*/
# define BLC_OP 				(M_FASTCALL | 15) /*Operations on Boot Loop Counter*/
# define HANDLE_CERTS_OP 		(M_FASTCALL | 16) /*Decrypt cert manifest and load values*/

# define M_FAST_PROV        (M_FASTCALL | 0x04000000)
# define SLI_GETPROVSTAGE   (M_FAST_PROV | 1)
# define SLI_SETPROVSTAGE   (M_FAST_PROV | 2)
# define SLI_SETAES         (M_FAST_PROV | 3)
# define SLI_RENEW_COMP     (M_FAST_PROV | 4)

# define FW_VERSION 0x8300010c
# define BSP_FINAL  0x8300010d

#include "sm_func.h"

# include <linux/arm-smccc.h>
static int peripheralManagementWrapper(unsigned long func, unsigned long a0, unsigned long a1, unsigned long a2,
				       unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
{
  struct arm_smccc_res res;
  arm_smccc_smc(func, a0, a1, a2, a3, 0, 0, 0, &res);
  return (int)res.a0;
}

u32 tee_version(void)
{
  int ret;
  ret = (unsigned int)peripheralManagementWrapper(FW_VERSION, 0, 0, 0,
						  0, 0, 0, 0);
  return (u32)ret;
}

void tee_final(void)
{
  int ret;
  ret = peripheralManagementWrapper(BSP_FINAL, 0, 0, 0,
				    0, 0, 0, 0);
  (void)ret;
}

u32 tee_load(unsigned int tee_destaddr, /* where to place TEE in DDR: destination */
	     unsigned int tee_loadaddr, /* where TEE is loaded in DDR */
	     unsigned int tee_length,   /* size of TEE -bytes */
	     unsigned int tee_arg0,
	     unsigned int tee_arg1,
	     unsigned int tee_arg2)
{
  int ret;
  ret = peripheralManagementWrapper(TEE_LOAD,
				    tee_destaddr,
				    tee_loadaddr,
				    tee_length,
				    tee_arg0,
				    tee_arg1,
				    tee_arg2,
				    0);
				    
  return ret;
}

uint32_t sli_encrypt(uint32_t comp_src,uint32_t comp_dst,uint32_t len,uint32_t keyselect)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_ENCRYPT,
																	comp_src,
																	comp_dst,
																	len,
																	keyselect,
																	0,0,0);
	return res;
}

uint32_t sli_decrypt(uint32_t comp_src,uint32_t comp_dst,uint32_t len,uint32_t keyselect)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_DECRYPT,
																	comp_src,
																	comp_dst,
																	len,
																	keyselect,
																	0,0,0);
	return res;
}


uint32_t sli_get_provstage(void)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_GETPROVSTAGE,
																	0,0,0,0,0,0,0);

	return res;
}

uint32_t sli_set_provstage(uint32_t addr,uint32_t len,uint32_t stage)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_SETPROVSTAGE,
																	addr,
																	len,
																	stage,
																	0,0,0,0);
	return res;
}


uint32_t sli_set_aeskey(uint32_t addr,uint32_t len)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_SETAES,
																	addr,
																	len,
																	0,0,0,0,0);
	return res;
}


uint32_t sli_renew_component(uint32_t addr,uint32_t len)
{
	uint32_t res=0;
	res=peripheralManagementWrapper(SLI_RENEW_COMP,
																	addr,
																	len,
																	0,0,0,0,0);
	return res;
}


uint32_t blc_op(uint32_t op, uint32_t *value){
	uint32_t tmp=*value;
	struct arm_smccc_res res;
	arm_smccc_smc(BLC_OP, op, tmp, 0, 0, 0, 0, 0, &res);
	*value = res.a2;
	return res.a0;
}

#define CERT_SLIP_ID 1
uint32_t handle_certs( uint32_t cert_addr ){
	struct arm_smccc_res res;
	printf("Calling handle cert at addr: 0x%08x\n", cert_addr);
	arm_smccc_smc(HANDLE_CERTS_OP, CERT_SLIP_ID, cert_addr, 0, 0, 0, 0, 0, &res);
	return res.a0;
}

#endif
