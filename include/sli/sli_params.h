/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#ifndef _SLI_PARAMS_H
#define _SLI_PARAMS_H

#include "sli_list.h"

//#define DEBUG_BUILD 1

#define TYPE_UNKNOWN 0

#define TYPE_UINT8   1
#define TYPE_UINT16  2
#define TYPE_UINT32  3
#define TYPE_UINT64  4

#define TYPE_INT8    5
#define TYPE_INT16   6
#define TYPE_INT32   7
#define TYPE_INT64   8

#define TYPE_STRING  9
#define TYPE_BINARY  10


typedef struct slip_header
{
	uint8_t magic[8];
	uint32_t numentries;
	uint32_t size;
} slip_header_t;


typedef struct slip_key
{
	char* key;
	uint32_t type;
	uint32_t size;
	void* value;
} slip_key_t;


typedef struct slip
{
	uint8_t* raw;
	uint32_t size;
	uintptr_t nvm;
	list_t* params;
} slip_t;


slip_t* sli_loadSlip(void* where);
slip_t *sli_newSlip(void);
slip_t* sli_initParams(uint8_t* raw,uint32_t size);
void sli_freeParams(slip_t* params);

slip_key_t* sli_findParam(slip_t* params,const char* section,const char* name);
void sli_deleteParamName(slip_t* params,const char* section,const char* name);
void sli_deleteParamKey(slip_t* params,slip_key_t* key);
void sli_addParam(slip_t* params,slip_key_t* key);
slip_key_t* sli_newParam(const char* section,const char* name,int type);
// void sli_writeParams(slip_t* params,uintptr_t dest);
uint8_t* sli_binaryParams(slip_t* params,int* size);
list_t* sli_paramSections(slip_t* params);
void sli_freeParamSections(list_t* sectionlist);

// value convenience functions
#define INT_CONVENIENCE_DECL(TYPE) TYPE sli_value_##TYPE(slip_key_t* key);

INT_CONVENIENCE_DECL(uint8_t)
INT_CONVENIENCE_DECL(uint16_t)
INT_CONVENIENCE_DECL(uint32_t)
INT_CONVENIENCE_DECL(uint64_t)

#define ENTRY_CONVENIENCE_DECL(TYPE) TYPE sli_entry_##TYPE(slip_t* slip,const char* section,const char*name);

ENTRY_CONVENIENCE_DECL(uint8_t)
ENTRY_CONVENIENCE_DECL(uint16_t)
ENTRY_CONVENIENCE_DECL(uint32_t)
ENTRY_CONVENIENCE_DECL(uint64_t)


#define PTR_CONVENIENCE_DECL(LABEL,TYPE) TYPE sli_value_##LABEL(slip_key_t* key);

PTR_CONVENIENCE_DECL(string,char*)
PTR_CONVENIENCE_DECL(binary,uint8_t*)


#if (DEBUG_BUILD)
void sli_testKey(slip_key_t* key);
void sli_testParams(slip_t* params);
void sli_testParamProc(void);
#else
#define sli_testKey(key)
#define sli_testParams(params)
#define sli_testParamProc(void)
#endif

#endif
