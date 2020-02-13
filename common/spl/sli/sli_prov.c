
#include <common.h>
#include <sm_func.h>

#include "sli/sli_io.h"
#include "sli/sli_control.h"

#include "sli/sli_prov.h"
#include "sli/sli_manifest.h"
#include "sli/sli_component.h"

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



__attribute__((unused))
static void printBuffer(uint8_t* buffer,size_t size)
{
	int index;
	for (index=0;index<(int)size;index++)
	{
		printf("0x%02X ",((uint8_t*)buffer)[index]);
		if ((index+1)%8==0)
			printf("\n");
	}
	printf("\n");
}


//-----------------------------------------------
// private
#define DIRECT_LOAD     0
#define COMPONENT_LOAD  1
static int mangleComponent(uint32_t addr,uint32_t len,int which, ...)
{
	int res=0;
	int nvmres=0;
	int directflag=DIRECT_LOAD;

	if (len)
		nvmres=sli_nvm_read(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);
	else
	{
		len=loadComponentBuffer(addr,(void*)SLI_SPL_SCRATCH);
		nvmres=(len) ? 0 : 1;
		directflag=COMPONENT_LOAD;
	}

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
		switch (directflag)
		{
		case COMPONENT_LOAD:
			len=saveComponentBuffer(addr,(void*)SLI_SPL_SCRATCH);
			if (!len)
				res=MANGLE_NVMWRITE_ERR;
			break;
		case DIRECT_LOAD:
		default:
			nvmres=sli_nvm_write(SLIDEV_DEFAULT,addr,len,(void*)SLI_SPL_SCRATCH);
			if (nvmres)
				res=MANGLE_NVMWRITE_ERR;
			break;
		}
		

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
	int bsres=0;

	printf("Fusing...\n");

	bsres=setStage(2);
	
	if (!bsres)
		printf("Restarting for Provisioning Stage 2\n");
	else
		printf("Stage could not be set: %d\n",bsres);

	if (bsres)
		res=PROV_STOP;
	
	return res;
}


//diversify
#define DCOMP_ERR_OK      0
#define DCOMP_ERR_LAYOUT  100
#define DCOMP_ERR_ADDR    101
static int diversifyComponent(const char* plex,const char* component,const char* label)
{
	int res=DCOMP_ERR_OK;
	slip_t* layout=getComponentManifest();

	printf("Diversifying %s: ",label);

	if (layout)
	{
		char keyname[SLI_PARAM_NAME_SIZE];
		memset(keyname,0,SLI_PARAM_NAME_SIZE);
		strcpy(keyname,component);
		strcat(keyname,"_src");

		uint32_t addr=sli_entry_uint32_t(layout,plex,keyname);

		if (addr)
			res=mangleComponent(addr,0,BS_COMP);
		else
			res=DCOMP_ERR_ADDR;
	}
	else
		res=DCOMP_ERR_LAYOUT;

	printf("%s (%d)\n",(res) ? "FAILED" : "SUCCESS",res);
		
	return res;
}


static int stage_2(void)
{
	int res=PROV_RESTART;
	int bsres=0;

	bsres=updateAESKey();
	if (!bsres)
	{
		// diversify components

		// component index (CONFIG_COMPIDX_ADDR)
		printf("Diversifying Component Index: ");
		bsres=mangleComponent(CONFIG_COMPIDX_ADDR,0,BS_COMP);
		printf("%d\n",bsres);

		diversifyComponent(PLEX_ID_A_STR,"coretee","Plex A: CoreTEE");
		diversifyComponent(PLEX_ID_A_STR,"uboot","Plex A: U-Boot");
		diversifyComponent(PLEX_ID_A_STR,"linux","Plex A: Linux Kernel");
		diversifyComponent(PLEX_ID_A_STR,"dtb","Plex A: Device Tree Binary");
		diversifyComponent(PLEX_ID_A_STR,"initramfs","Plex A: initramfs");

		diversifyComponent(PLEX_ID_B_STR,"coretee","Plex B: CoreTEE");
		diversifyComponent(PLEX_ID_B_STR,"uboot","Plex B: U-Boot");
		diversifyComponent(PLEX_ID_B_STR,"linux","Plex B: Linux Kernel");
		diversifyComponent(PLEX_ID_B_STR,"dtb","Plex B: Device Tree Binary");
		
		//Certs are handled by Coretee.

		// set next stage
		bsres=setStage(0);
		if (!bsres)
			printf("Restarting for Production Boot\n");
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
	int opres=loadLayouts(CONFIG_COMPIDX_ADDR);

	if (!opres)
	{
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
	}
	else
		printf("PROVISIONING: Could not load layouts\n");


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
