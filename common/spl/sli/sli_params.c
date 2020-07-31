/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#include <common.h>
#include <linux/types.h>
#include <linux/string.h>
#include <asm/string.h>

#include "sli/sli_list.h"
#include "sli/sli_params.h"

#define ALIGNMENT_BYTES 8


static uint8_t MAGIC[8]={0x73,0x65,0x71,0x6c,0x61,0x62,0x73,0x00};

#define PARAM_PADDING(s) ((ALIGNMENT_BYTES-((s)%ALIGNMENT_BYTES))%ALIGNMENT_BYTES)

struct writedata
{
	uint8_t* ptr;
	uint32_t numentries;
	uint32_t totalbytes;
};
	
//-----------------------------------------------
// iterators
static int freeparam(entry_t* e,void* data)
{
	slip_key_t* key=(slip_key_t*)e->data;
	FREE(key);
	return 0;
}


static int findproc(entry_t* e,void* data)
{
	int res=0;
	slip_key_t* key=(slip_key_t*)e->data;
	char* compstr=(char*)data;
	if (!strcmp(key->key,compstr))
		res=1;
	return res;
}


static int sizeproc(entry_t* e,void* data)
{
	size_t* accumulator=(size_t*)data;
	slip_key_t* key=(slip_key_t*)e->data;

	*accumulator+=SLI_PARAM_NAME_SIZE; // name
	*accumulator+=sizeof(uint32_t); // type
	*accumulator+=sizeof(uint32_t); // size

	int padding=PARAM_PADDING(key->size);
	
	*accumulator+=key->size;
	*accumulator+=padding;

	return 0;
}


static int writeproc(entry_t* e,void* data)
{
	struct writedata* transfer=(struct writedata*)data;
	slip_key_t* key=(slip_key_t*)e->data;

	memset(transfer->ptr,0,SLI_PARAM_NAME_SIZE);
	strncpy((char*)transfer->ptr,key->key,strlen(key->key));
	transfer->ptr+=SLI_PARAM_NAME_SIZE;
	
	memcpy(transfer->ptr,&key->type,sizeof(uint32_t));
	transfer->ptr+=sizeof(uint32_t);

	memcpy(transfer->ptr,&key->size,sizeof(uint32_t));
	transfer->ptr+=sizeof(uint32_t);

	int padding=PARAM_PADDING(key->size);

	memset(transfer->ptr,0,key->size+padding);
	memcpy(transfer->ptr,key->value,key->size);

	transfer->ptr+=key->size+padding;
	transfer->numentries++;
	transfer->totalbytes+=(SLI_PARAM_NAME_SIZE+sizeof(uint32_t)+sizeof(uint32_t)+key->size+padding);

	return 0;
}


static int entryproc(entry_t* e,void* data)
{
	return (e->data==data);
}

/*
static char* strrchr(char* str,int character)
{
	char* res=0;
	char* ptr=str+(strlen(str)-1);
	do
	{
		if (*ptr==character)
		{
			res=ptr;
			break;
		}
		ptr--;
	}
	while (ptr>=str);
	return res;
}
*/

static int existproc(entry_t* e,void* data)
{
	char* section=(char*)e->data;
	char* newsection=(char*)data;

	int res=strcmp(section,newsection) ? 0 : 1;
	return res;
}


static int sectionproc(entry_t* e,void* data)
{
	list_t* seclist=(list_t*)data;
	slip_key_t* key=(slip_key_t*)e->data;

	char* testkey=(char*)MALLOC(strlen(key->key)+1);
	memset(testkey,0,strlen(key->key)+1);
	strncpy(testkey,key->key,strlen(key->key));

	char* point=strrchr(testkey,'_');

	if (point)
	{
		*point=0;
		entry_t* existing=searchList(seclist,0,existproc,testkey);
		if (!existing)
		{
			char* actual=(char*)MALLOC(strlen(testkey)+1);
			memset(actual,0,strlen(testkey)+1);
			strncpy(actual,testkey,strlen(testkey));
			appendEntry(seclist,actual);
		}
	}

	FREE(testkey);
	return 0;
}


static int freesectionproc(entry_t* e,void* data)
{
	char* section=(char*)e->data;
	FREE(section);
	return 0;
}

//-----------------------------------------------
// private
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
static void fillParams(slip_t* params)
{
	uint8_t* ptr=params->raw;
	uint8_t* end=ptr+params->size;

	while (ptr<end)
	{
		slip_key_t* key=(slip_key_t*)MALLOC(sizeof(slip_key_t));
		key->key=(char*)ptr;

		ptr+=SLI_PARAM_NAME_SIZE;
		
		key->type=*(uint32_t*)ptr;
		ptr+=sizeof(uint32_t);
		
		key->size=*(uint32_t*)ptr;
		ptr+=sizeof(uint32_t);

		key->value=(void*)ptr;

		int padding=PARAM_PADDING(key->size);

		ptr+=key->size+padding;

		appendEntry(params->params,key);
	}
}
#pragma GCC diagnostic pop


static size_t calculateSize(slip_t* params)
{
	size_t res=0;
	iterateList(params->params,0,sizeproc,&res);
	return res;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
static uint8_t* createBinaryParams(slip_t* params)
{
	uint8_t* res=0;
	slip_header_t* header=0;
	struct writedata transfer;
	size_t buffersize=calculateSize(params);

	res=(uint8_t*)MALLOC(sizeof(slip_header_t)+buffersize);
	if(!res){
		return NULL;
	}

	header=(slip_header_t*)res;

	memcpy(header->magic,MAGIC,8);
	header->numentries=42;
	header->size=buffersize;

	memset(&transfer,0,sizeof(struct writedata));
	transfer.ptr=res+sizeof(slip_header_t);

	iterateList(params->params,0,writeproc,&transfer);

	header->numentries=transfer.numentries;
	return res;
}
#pragma GCC diagnostic pop


static char* createKeyName(const char* section,const char* name)
{
	//int namelen=strlen(section)+strlen(name)+2;
	int clen = 0;
	char* res=(char*)MALLOC(SLI_PARAM_NAME_SIZE);
	char* ptr=res;
	memset(res,0,SLI_PARAM_NAME_SIZE);
	clen = strlen(section);
	if(clen > SLI_PARAM_NAME_SIZE)
		clen=SLI_PARAM_NAME_SIZE;
	strncpy(ptr,section,strlen(section));
	ptr=ptr+strlen(ptr);

	if(clen < SLI_PARAM_NAME_SIZE){
		strncpy(ptr,"_",1);
		ptr++;
		if(clen + 1 + strlen(name) > SLI_PARAM_NAME_SIZE)
			clen = SLI_PARAM_NAME_SIZE - clen - 1;
		else
			clen = strlen(name);

		strncpy(ptr,name,clen);
	}

	return res;
}


/*
static void v_print_buffer(void* buffer,int size)
{
	uint8_t* buf=(uint8_t*)buffer;
	for (int index=0;index<size;index++)
	{
		printf("%02x ",buf[index]);
		if ((index % 8)+1==0)
			printf("\n");
	}
	printf("\n");
}
//*/
//-----------------------------------------------
// public
slip_t* sli_loadSlip(void* where)
{
	slip_t* res=0;
	slip_header_t header;

	/*
	Header is defined here and the information is copied because
	we can't be guaranteed that the offset into the update
	package (ddr) will be properly aligned.
	*/
	memcpy(&header, (void*)where, sizeof(slip_header_t));

	/*
	puts("slip where: "); print_buffer(&where,sizeof(p_addr)); puts("\n");
	puts("header: \n"); print_buffer(header,sizeof(slip_header_t)); puts("\n");
	puts("header: \n"); print_buffer(header->magic,8); puts("\n");
	puts("MAGIC : \n"); print_buffer(MAGIC,8); puts("\n");
	//*/
	
	if (memcmp(header.magic,MAGIC,8)==0)
	{
		uint8_t* raw=(uint8_t*)MALLOC(header.size);
		memcpy(raw,(uint8_t*)(where+sizeof(slip_header_t)),header.size);
		res=sli_initParams(raw,header.size);
	}
	else
		printf("NO MAGIC\n");
	
	return res;
}


slip_t *sli_newSlip( void ){
	slip_t* res=(slip_t*)MALLOC(sizeof(slip_t));
	memset(res,0,sizeof(slip_t));

	res->raw=NULL;
	res->size=0;

	res->params=newList();

	return res;
}

slip_t* sli_initParams(uint8_t* raw,uint32_t size)
{
	slip_t* res=(slip_t*)MALLOC(sizeof(slip_t));
	memset(res,0,sizeof(slip_t));

	res->raw=raw;
	res->size=size;

	res->params=newList();

	fillParams(res);

	return res;
}


void sli_freeParams(slip_t* params)
{
	freeList(params->params,freeparam);
	FREE(params->raw);
	FREE(params);
}


slip_key_t* sli_findParam(slip_t* params,const char* section,const char* name)
{
	slip_key_t* res=0;
	char* keyname=createKeyName(section,name);

	entry_t* key=searchList(params->params,0,findproc,keyname);

	if (key)
		res=(slip_key_t*)key->data;
	
	FREE(keyname);
	return res;
}


void sli_deleteParamName(slip_t*params,const char* section,const char* name)
{
	slip_key_t* key=sli_findParam(params,section,name);
	if (key)
		sli_deleteParamKey(params,key);
}

void sli_deleteParamKey(slip_t* params,slip_key_t* key)
{
	entry_t* delentry=searchList(params->params,0,entryproc,key);
	if (delentry) {
		deleteEntry(params->params,delentry);
		FREE(delentry);
	}
}

void sli_addParam(slip_t* params,slip_key_t* key)
{
	appendEntry(params->params,key);
}

slip_key_t* sli_newParam(const char* section,const char* name,int type)
{
	slip_key_t* res=(slip_key_t*)MALLOC(sizeof(slip_key_t));
	char* keyname=createKeyName(section,name);
	memset(res,0,sizeof(slip_key_t));
	res->key=keyname;
	res->type=type;
	return res;
}


/*
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
void sli_writeParams(slip_t* params,uintptr_t dest)
{
	uint8_t* parambuffer=createBinaryParams(params);
	slip_header_t* header=(slip_header_t*)parambuffer;
	size_t totalsize=header->size+sizeof(slip_header_t);

	if (dest==0)
		dest=params->nvm;

#if (DEBUG_BUILD)
	debug("Saving SLIP to: ");
	print_buffer(&dest,sizeof(uintptr_t));
#endif

	// save_data(dest,parambuffer,totalsize);
	FREE(parambuffer);
}
#pragma GCC diagnostic pop
*/


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
uint8_t* sli_binaryParams(slip_t* params,int* size)
{
	uint8_t* parambuffer=createBinaryParams(params);
	slip_header_t* header=(slip_header_t*)parambuffer;
	size_t totalsize=header->size+sizeof(slip_header_t);

	*size=totalsize;
	return parambuffer;
}
#pragma GCC diagnostic pop



uint8_t* sli_binaryParamsAlign(slip_t* params,int* size,int align)
{
	int rawsize=0;
	uint8_t* parambuffer=sli_binaryParams(params,&rawsize);
	uint8_t* res=0;

	int alignedsize=(rawsize%align==0) ? rawsize : rawsize+(align-(rawsize%align));

	if (alignedsize!=rawsize)
	{
		res=(uint8_t*)malloc(alignedsize);
		memset(res,0,alignedsize);
		memcpy(res,parambuffer,rawsize);
		free(parambuffer);
	}
	else
		res=parambuffer;

	*size=alignedsize;
	return res;
}



list_t* sli_paramSections(slip_t* params)
{
	list_t* res=newList();
	iterateList(params->params,0,sectionproc,res);
	return res;
}


void sli_freeParamSections(list_t* sectionlist)
{
	freeList(sectionlist,freesectionproc);
}


#define INT_CONVENIENCE(TYPE,ID) TYPE sli_value_##TYPE(slip_key_t* key)	\
	{																																			\
		TYPE res=0;																													\
		if (key->type==ID)																									\
			memcpy(&res,key->value,key->size);																\
		return res;																													\
	}

INT_CONVENIENCE(uint8_t,TYPE_UINT8)
INT_CONVENIENCE(uint16_t,TYPE_UINT16)
INT_CONVENIENCE(uint32_t,TYPE_UINT32)
INT_CONVENIENCE(uint64_t,TYPE_UINT64)

/* INT_CONVENIENCE(int8_t,TYPE_INT8) */
/* INT_CONVENIENCE(int16_t,TYPE_INT16) */
/* INT_CONVENIENCE(int32_t,TYPE_INT32) */
/* INT_CONVENIENCE(int64_t,TYPE_INT64) */

#define ENTRY_CONVENIENCE(TYPE,ID) TYPE sli_entry_##TYPE(slip_t* slip,const char* section,const char* name)	\
	{																																			\
		TYPE res=0;																													\
		slip_key_t* key=sli_findParam(slip,section,name);											\
		if (key)																														\
		{																																		\
			if (key->type==ID)																								\
				memcpy(&res,key->value,key->size);															\
		}																																		\
		return res;																													\
	}

ENTRY_CONVENIENCE(uint8_t,TYPE_UINT8)
ENTRY_CONVENIENCE(uint16_t,TYPE_UINT16)
ENTRY_CONVENIENCE(uint32_t,TYPE_UINT32)
ENTRY_CONVENIENCE(uint64_t,TYPE_UINT64)










#define PTR_CONVENIENCE(LABEL,TYPE,ID) TYPE sli_value_##LABEL(slip_key_t* key) \
	{																																			\
		TYPE res=0;																													\
		if (key->type==ID)																									\
		{																																		\
			res=(TYPE)MALLOC(key->size);																			\
			memcpy(res,key->value,key->size);																	\
		}																																		\
		return res;																													\
}

PTR_CONVENIENCE(string,char*,TYPE_STRING)
PTR_CONVENIENCE(binary,uint8_t*,TYPE_BINARY)


//===============================================


// test
///*
#if (DEBUG_BUILD)
static char* TYPEARRAY[]={
	"unknown",
	"uint8",
	"uint16",
	"uint32",
	"uint64",
	"int8",
	"int16",
	"int32",
	"int64",
	"str",
	"bin",
	"file",
	0
};

static void printkey(slip_key_t* key)
{
	printf("Name: %s\n",key->key);
	printf("Type: %s\n",TYPEARRAY[key->type]);
	v_print_buffer(key->value,key->size);
	puts("\n");
}

static int printproc(entry_t* e,void* data)
{
	slip_key_t* key=(slip_key_t*)e->data;
	printkey(key);
	return 0;
}

void sli_testKey(slip_key_t* key)
{
	printkey(key);
}

void sli_testParams(slip_t* params)
{
	iterateList(params->params,0,printproc,0);
}

__attribute__((unused))
static void printsection(entry_t* e,void* data)
{
	char* section=(char*)e->data;
	puts(section);
	puts("\n");
}


//#include "sli_slip.h"
void sli_testParamProc()
{

	// get section
	/*
	slip_t* slip=get_slip(SLIP_COMPONENT);
	list_t* sections=sli_paramSections(slip);
	iterateList(sections,0,printsection,0);
	sli_freeParamSections(sections);
	*/
 
	
	// delete key
	/*
	slip_t* slip=get_slip(SLIP_COMPONENT);
	if (slip)
	{
		slip_key_t* addedkey=sli_findParam(slip,"coretee","added_0");
		if (addedkey)
		{
			puts("coretee:added_0 found... deleting...\n");
			sli_deleteParamKey(slip,addedkey);

			save_slip(SLIP_COMPONENT);
			
		}
		else
			puts("coretee:added_0 NOT FOUND\n");
	}
	else
		puts("Component SLIP not found\n");
	//*/
		
	// add new key
	/*
	slip_t* slip=get_slip(SLIP_COMPONENT);
	if (slip)
	{
		slip_key_t* key=sli_findParam(slip,"coretee","added_0");
		if (!key)
		{
			puts("coretee:added_0 does not exist:  adding...\n");

			// create new key <section>,<name>,<type>
			key=sli_newParam("coretee","added_0",TYPE_STRING);

			// this is just for demonstrative purposes...
			char* thing="this is a new thing";
			int thinglen=strlen(thing);

			char* newvalue=(char*)MALLOC(thinglen+1);
			memset(newvalue,0,thinglen+1);
			strncpy(newvalue,thing,thinglen);

			// set the size of the param in the key
			key->size=thinglen+1;
			// set the value pointer - don't free this...
			key->value=newvalue;

			sli_testKey(key);

			// add new key to SLIP
			sli_addParam(slip,key);

			// print SLIP
			sli_testParams(slip);

			// write SLIP back to QSPI
			save_slip(SLIP_COMPONENT);
		}
		else
		{
			puts("coretee:added_0 already exists...\n");
			sli_testKey(key);
		}
	}
	else
		puts("Component SLIP not found\n");
	//*/

		
	// find and modify key
	/*
	slip_t* slip=get_slip(SLIP_COMPONENT);
	if (slip)
	{
		slip_key_t* key=sli_findParam(slip,"coretee","added_0");
		if (key)
		{
			puts("coretee:added_0 FOUND!\n");
			puts((char*)key->value);
			puts("\n");

			puts("Modifying coretee test_0: womble\n");
			char* new_value=(char*)MALLOC(strlen("womble")+1);
			memset(new_value,0,strlen("womble")+1);
			strncpy(new_value,"womble",strlen("womble"));
			key->value=(void*)new_value;
			key->size=strlen("womble")+1;

			save_slip(SLIP_COMPONENT);
		}
		else
			debug("coretee:added_0 NOT FOUND\n");
	}
	else
		puts("Component SLIP not found\n");
	//*/

}
#endif
//*/


