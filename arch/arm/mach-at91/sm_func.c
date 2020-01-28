#ifdef CONFIG_CORETEE
typedef unsigned int u32;

# define M_FASTCALL         0x80000000
# define PM_BAD             0xffffffff
# define PM_OK              0

# define TEE_LOAD           (M_FASTCALL | 6)
# define SLI_DECRYPT        (M_FASTCALL | 7)

# define FW_VERSION 0x8300010c
# define BSP_FINAL  0x8300010d

#include "sm_func.h"

# include <linux/arm-smccc.h>
static int peripheralManagementWrapper(unsigned long func, unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5, unsigned long a6)
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

#endif
