
#include <common.h>
#include <sm_func.h>

#include "sli/sli_io.h"
#include "sli/sli_control.h"

#include "sli/sli_prov.h"


#define PROV_STOP 0
#define PROV_RESTART 1

#define BS_STAGE   1  // 1 param
#define BS_AES     2  // 0 params
#define BS_COMP    3  // 0 params
#define CT_BLOB    10

#define MANGLE_NVMREAD_ERR       1
#define MANGLE_BS_ERR            2
#define MANGLE_NVMWRITE_ERR      3
#define MANGLE_UNKNOWN_PROC_ERR  4

#define BOOT_BINARY_ADDR 0x00000000
#define BOOT_BINARY_SIZE 0x00010000


//-----------------------------------------------
// private

static int mangleComponent(uint32_t addr,uint32_t len,int which, ...)
{
	int res=0;
	int nvmres=sli_nvm_read(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);

	va_list valist;
	va_start(valist,which);

	if (!nvmres)
	{
		switch (which)
		{
		case BS_STAGE:
			res=sli_set_provstage(SLI_SPL_SCRATCH,len,va_arg(valist,uint32_t));
			break;
		case BS_AES:
			res=sli_set_aeskey(SLI_SPL_SCRATCH,len);
			break;
		case BS_COMP:
			res=sli_renew_component(SLI_SPL_SCRATCH,len);
			break;
		case CT_BLOB:
		default:
			res=MANGLE_UNKNOWN_PROC_ERR;
		}
	}
	else
		res=MANGLE_NVMREAD_ERR;

	va_end(valist);

	if (!res)
	{
		nvmres=sli_nvm_write(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);
		if (nvmres)
			res=MANGLE_NVMWRITE_ERR;
	}
	
	return res;
}


static int setStage(int stage)
{
	return mangleComponent(BOOT_BINARY_ADDR,BOOT_BINARY_SIZE,BS_STAGE,stage);
}


static int updateAESKey(void)
{
	return mangleComponent(BOOT_BINARY_ADDR,BOOT_BINARY_SIZE,BS_AES);
}


// fuses
static int stage_1(void)
{
	int res=PROV_RESTART;
	int bsres=setStage(2);

	if (!bsres)
	{
	}
	else
		printf("Stage could not be set: %d\n",bsres);

	if (bsres)
		res=PROV_STOP;
	
	return res;
}

//diversify
static int stage_2(void)
{
	int res=PROV_RESTART;
	int bsres=0;

	bsres=updateAESKey();
	if (!bsres)
	{
		// diversify AES components

		// load coretee

		// diversify components

		// set next stage
		bsres=setStage(0);

		if (!bsres)
		{
		}
		else
			printf("Stage could not be set: %d\n",bsres);
	}
	else
		printf("Could not diversify AES key: %d\n",bsres);


	if (bsres)
		res=PROV_STOP;

	return res;
}



//-----------------------------------------------
// public

uint32_t getProvisioningStage(void)
{
	uint32_t res=sli_get_provstage();
	return res;
}


void do_provisioning(uint32_t stage)
{
	int stageres=PROV_STOP;
	printf("PROVISIONING STAGE: %d\n",stage);

	switch (stage)
	{
	case 1:
		stageres=stage_1();
		break;
	case 2:
		stageres=stage_2();
		break;
	}


	// no return
	switch (stageres)
	{
	case PROV_RESTART:
		sli_reset_board();
		break;
	case PROV_STOP:
	default:
		asm volatile("b .\n");
		break;
	}
}
