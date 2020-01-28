#ifndef _SLI_COMPONENT_H
#define _SLI_COMPONENT_H

#include <linux/types.h>

#define SLICOMP_MAGIC 0x00494C53

#define SLIENC_NONE                 0
#define SLIENC_BOOTSERVICES_AES     1
#define SLIENC_CORETEE_BLOB         2


#define SLIENC_ERROR 1

typedef struct sli_compsize
{
	uint32_t magic;
	uint32_t headersize;
	uint32_t payloadsize;
} sli_compsize_t;


typedef struct sli_compheader
{
	uint32_t encryption;
	uint32_t keyselect;
} sli_compheader_t;


size_t getComponentSize(uint32_t addr);
size_t loadComponentBuffer(uint32_t addr,void* buffer);

void* getComponent(uint32_t addr);
int decryptComponent(void* src,void* dst);

uint32_t component_setup(const char* layoutentry,const char* title,size_t* imagesize);

#endif
