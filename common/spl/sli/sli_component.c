
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
			printf("Could not load component buffer\n");
		}
	}
	
	return res;
}


size_t saveComponentBuffer(uint32_t addr,void* buffer)
{
	sli_compsize_t* headerbuffer=(sli_compsize_t*)buffer;
	size_t res=sizeof(sli_compsize_t)+headerbuffer->headersize+headerbuffer->payloadsize;

	int iores=sli_nvm_write(_device,addr,res,buffer);

	if (iores)
	{
		res=0;
		printf("Could not save component buffer\n");
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
	//printf("in decryptComponent  0x%08x:0x%08x  0x%08x\n",compsize,compsize->magic,SLICOMP_MAGIC);
	if (compsize->magic==SLICOMP_MAGIC)
	{
		sli_compheader_t* header=(sli_compheader_t*)((uint8_t*)src+sizeof(sli_compsize_t));
		uint8_t* payloadstart=(uint8_t*)((uint8_t*)header+compsize->headersize);

		/* printf("Payload size: %d\n", compsize->payloadsize); */
		/* printf("Header size: %d\n", compsize->headersize); */
		/* printf("Payload start: %d\n", (int)((void*)payloadstart-(void*)src)); */

		// switch on encryption type
		switch (header->encryption)
		{
		case SLIENC_NONE:
#ifdef CONFIG_SLI_ALLOW_PLAIN
			memmove(dst,payloadstart,compsize->payloadsize);
#else
			printf("PLAIN components not allowed\n");
			res=SLIENC_ERROR;
#endif
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
	else
	{
		printf("NO MAGIC  0x%08x:0x%08x  0x%08x\n",(unsigned int)compsize,compsize->magic,SLICOMP_MAGIC);
		res=SLIENC_ERROR;
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
		uint32_t addr=sli_entry_uint32_t(layout,plexid,keyname);
		SET_KEY_NAME("_dst");
		uint32_t dest=sli_entry_uint32_t(layout,plexid,keyname);
		SET_KEY_NAME("_jump");
		uint32_t ramaddr=sli_entry_uint32_t(layout,plexid,keyname);
		/*
		 * Helpful for debugging/seeing update changes.
		 * {
			SET_KEY_NAME("_version");
			slip_key_t *key = sli_findParam(layout, plexid, keyname);
			if (key)
			{
				char *version=sli_value_string(key);
				if(version){
					printf("Loading %s version %s...\n", component, version);
					free(version);
				}
			}
		}*/

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

int save_component(void *buffer, size_t size, uintptr_t nvmaddr, uint32_t encryptiontype, uint32_t keyselect){
	int res=0;
	sli_compsize_t compsize;
	sli_compheader_t compheader;
	void *final=NULL;
	void *p;

	compheader.encryption = encryptiontype;
	compheader.keyselect = keyselect;

	switch(compheader.encryption){
	case SLIENC_NONE:
		break;
	case SLIENC_BOOTSERVICES_AES:
	case SLIENC_CORETEE_BLOB:
		/*Encrypt buffer*/
		res = sli_encrypt((uint32_t)buffer, (uint32_t)buffer, size, keyselect);
		break;
	default:
		break;
	}

	compsize.magic=SLICOMP_MAGIC;
	compsize.headersize=sizeof(sli_compheader_t);
	compsize.payloadsize=size;

	final = malloc(sizeof(sli_compsize_t)+compsize.headersize+compsize.payloadsize);
	if(!final){
		printf("[%s] - Failed to allocate buffer to save to NVM!\n", __func__);
		return -1;
	}

	p=final;
	memcpy(p, &compsize, sizeof(sli_compsize_t));
	p+=sizeof(sli_compsize_t);
	memcpy(p, &compheader, sizeof(sli_compheader_t));
	p+=sizeof(sli_compheader_t);
	memcpy(p, buffer, size);

	printf("Calling nvm write [%lu]   %d bytes\n", nvmaddr, compsize.headersize+compsize.payloadsize);
	res = sli_nvm_write(_device, nvmaddr, (sizeof(sli_compsize_t)+compsize.headersize+compsize.payloadsize), final);

	free(final);

	printf("[%s] - Done\n", __func__);
	return res;
}
