
#include <common.h>
#include <compiler.h>
#include <malloc.h>
#include <sm_func.h>
#include "sli/sli_params.h"
#include "sli/sli_component.h"
#include "sli/sli_manifest.h"


static slip_t* _component_slip=0;

//-----------------------------------------------
// static
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

int loadLayouts(uint32_t addr)
{
	// load compidx
	int res=0;

	void* compbuffer=getComponent(addr);

	if (compbuffer)
	{
		res=decryptComponent(compbuffer,compbuffer);
		if (!res && compbuffer)
		{
			_component_slip=sli_loadSlip(compbuffer);
			free(compbuffer);
			
			if (_component_slip)
			{
				_component_slip->nvm = addr;
				printf("Component layout loaded\n");
			}
			else
				printf("Could not load Component layout\n");
		}
		else
		{
			printf("Could not decrypt Component Index\n");
			free(compbuffer);
		}
	}
	else
		printf("Could not load Component Index\n");

	// testing
	/*
	printf("Component Layout\n");
	if (_component_slip)
		sli_testParams(_component_slip);
	else
		printf("    No component layout\n");

	for (int index=0;index<PLEX_NUM;index++)
	{
		printf("Layout %d\n",index);
		if (_layout[index])
			sli_testParams(_layout[index]);
		else
			printf("    No layout %d\n",index);
	}
	//*/

	return res;
}

int loadManifests()
{
	// load manifests
	int res=0;


	return res;
}

slip_t *getComponentManifest( void ){
	return _component_slip;
}




