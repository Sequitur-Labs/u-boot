
#include <common.h>
#include <sm_func.h>

#include "sli/sli_io.h"
#include "sli/sli_control.h"

#include "sli/sli_prov.h"


#define PROV_STOP 0
#define PROV_RESTART 1

//-----------------------------------------------

static int rewrite_bootservices(uint32_t stage)
{
	int res=0;
	// load bootservices,
	int nvmres=sli_nvm_read(SLIDEV_DEFAULT,0x00000000,64*1024,(void*)SLI_SPL_SCRATCH);

	if (!nvmres)
	{
		uint32_t smres=sli_renew_bootservices(SLI_SPL_SCRATCH,64*1024,stage);
		if (!smres)
		{
			nvmres=sli_nvm_write(SLIDEV_DEFAULT,0x00000000,64*1024,(void*)SLI_SPL_SCRATCH);
			if (nvmres)
				printf("Could not write bootservices\n");
		}
		else
			printf("Could not renew bootservices\n");
	}
	else
		printf("Could not load bootservices\n");

	return res;
}


static int rewrite_bs_component(uint32_t addr,uint32_t len)
{
	int res=0;
	int nvmres=sli_nvm_read(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);

	if (!nvmres)
	{
		uint32_t smres=sli_renew_component(SLI_SPL_SCRATCH,len);
		if (!smres)
		{
			nvmres=sli_nvm_write(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);
			if (nvmres)
				printf("Could not write component\n");
		}
		else
			printf("Could not renew component\n");
	}
	else
		printf("Could not load component\n");
	
	return res;
}




// fuses
static int stage_1(void)
{
	int res=PROV_RESTART;
	int bsres=rewrite_bootservices(2);
	return res;
}

//diversify
static int stage_2(void)
{
	int res=PROV_RESTART;
	// diversify bootservices

	// load coretee

	// diversify components
	int bsres=rewrite_bootservices(0);

	return res;
}



//-----------------------------------------------

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
