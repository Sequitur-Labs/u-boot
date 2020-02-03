
#include <common.h>
#include <malloc.h>
#include <sm_func.h>

#include "sli/sli_io.h"
#include "sli/sli_manifest.h"
#include "sli/sli_component.h"



// set default device?
static int _device=SLIDEV_DEFAULT;



size_t getComponentSize(uint32_t addr)
{
	size_t res=0;
	sli_compsize_t headerbuffer;

	int iores=sli_nvm_read(_device,addr,sizeof(sli_compsize_t),&headerbuffer);

	if (!iores && headerbuffer.magic==SLICOMP_MAGIC)
		res=sizeof(sli_compsize_t)+headerbuffer.headersize+headerbuffer.payloadsize;
	
	return res;
}


size_t loadComponentBuffer(uint32_t addr,void* buffer)
{
	size_t res=0;
	int iores=0;

	res=getComponentSize(addr);

	if (buffer && res>0)
	{
		iores=sli_nvm_read(_device,addr,res,buffer);
		if (iores)
		{
			res=0;
			printf("Could not load raw param buffer\n");
		}
	}
	
	return res;
}


void* getComponent(uint32_t addr)
{
	void* res=0;
	size_t compsize=getComponentSize(addr);
	if (compsize)
	{
		res=memalign(4,compsize);
		compsize=loadComponentBuffer(addr,res);
		if (!compsize)
		{
			free(res);
			res=0;
		}
	}
	return res;
}


int decryptComponent(void* src,void* dst)
{
	int res=0;
	sli_compsize_t* compsize=(sli_compsize_t*)src;

	if (compsize->magic==SLICOMP_MAGIC)
	{
		sli_compheader_t* header=(sli_compheader_t*)((uint8_t*)src+sizeof(sli_compsize_t));
		uint8_t* payloadstart=(uint8_t*)((uint8_t*)header+compsize->headersize);

		// switch on encryption type

		switch (header->encryption)
		{
		case SLIENC_NONE:
			memmove(dst,payloadstart,compsize->payloadsize);
			break;
		case SLIENC_BOOTSERVICES_AES:
		case SLIENC_CORETEE_BLOB:
			// same fastcall - will automatically switch depending on whether coretee is loaded or not
			{
				uint32_t decres=sli_decrypt((uint32_t)payloadstart,(uint32_t)dst,compsize->payloadsize,header->keyselect);
				// interpret decres
				res=decres;
			}
			break;
		default:
			res=SLIENC_ERROR;
		}

	}

	return res;
}


// returns jump address from manifest
uint32_t component_setup(const char* plexid, const char* component, const char* title,size_t* imagesize)
{
	uint32_t res=0;
	slip_t* layout=getComponentManifest();
	char keyname[SLI_PARAM_NAME_SIZE];

#define SET_KEY_NAME(key) \
	memset(keyname, 0, SLI_PARAM_NAME_SIZE); \
	memcpy(keyname, component, strlen(component)); \
	memcpy(keyname+strlen(component), key, strlen(key));


	if (layout)
	{
		SET_KEY_NAME("_src");
		printf("Loading id: %s from component\n", keyname);
		uint32_t addr=sli_entry_uint32_t(layout,plexid,keyname);
		SET_KEY_NAME("_dst");
		uint32_t dest=sli_entry_uint32_t(layout,plexid,keyname);
		SET_KEY_NAME("_jump");
		uint32_t ramaddr=sli_entry_uint32_t(layout,plexid,keyname);

		if (addr && ramaddr && dest)
		{
			printf("Loading %s from 0x%08x to 0x%08x\n",title,addr,dest);

			size_t compsize=loadComponentBuffer(addr,(void*)dest);
			if (compsize)
			{
				int decres=decryptComponent((void*)ramaddr,(void*)dest);
				if (!decres)
				{
					if (imagesize!=0)
						*imagesize=compsize;
					res=ramaddr;
				}
				else
					printf("Could not decrypt %s: %d\n",title,decres);
			}
			else
				printf("Could not load %s from NVM\n",title);
		}
		else
			printf("Could not find %s layout\n",title);
	}
	else
		printf("Could not get plex layout\n");

	return res;
}

