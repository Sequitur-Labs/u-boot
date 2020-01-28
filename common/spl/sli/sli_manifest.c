
#include <common.h>
#include <compiler.h>
#include <malloc.h>
#include <sm_func.h>
#include "sli/sli_params.h"
#include "sli/sli_component.h"
#include "sli/sli_manifest.h"



#define PLEX_NUM 2

static slip_t* _component_slip=0;
static slip_t* _layout[PLEX_NUM]={0,0};


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


static void loadPlex(int plexindex,const char* plexname)
{
	//printf("Loading: %s\n",plexname);
	slip_key_t* plexkey=sli_findParam(_component_slip,"layout",plexname);
	if (plexkey)
	{
		uint32_t plexaddr=sli_value_uint32_t(plexkey);
		if (plexaddr)
		{
			void* rawplex=getComponent(plexaddr);

			if (rawplex)
			{
				int decres=decryptComponent(rawplex,rawplex);
				if (!decres && rawplex)
				{
					_layout[plexindex]=sli_loadSlip(rawplex);
					if (_layout[plexindex])
						printf("Plex %d layout loaded\n",plexindex);
					else
						printf("Could not load Plex %d layout\n",plexindex);
				}
				else
					printf("Could not decrypt plex manifest: %s\n",plexname);

				free(rawplex);
			}
			else
				printf("Could not load param buffer: %s\n",plexname);
		}
		else
			printf("Could not find plex address: %s\n",plexname);
	}
	else
		printf("Could not find layout entry: %s\n",plexname);
}


//-----------------------------------------------

int loadLayouts(uint32_t addr)
{
	// load compidx
	int res=0;

	printf("Loading layouts...\n");

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
				printf("Component layout loaded\n");
				loadPlex(0,"plex_a");
				loadPlex(1,"plex_b");
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


slip_t* getPlexLayout(int index)
{
	slip_t* res=0;
	if (index>=0 && index<PLEX_NUM)
		res=_layout[index];
	return res;
}



int loadManifests()
{
	// load manifests
	int res=0;


	return res;
}




