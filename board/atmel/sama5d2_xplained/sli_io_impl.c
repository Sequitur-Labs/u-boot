#include <common.h>
#include <compiler.h>
#include <spi_flash.h>

#include "sli/sli_io.h"


static struct spi_flash* _flash=0;

static int initDevice(int device)
{
	if (!_flash)
	{
		_flash=spi_flash_probe(CONFIG_SF_DEFAULT_BUS,
													 CONFIG_SF_DEFAULT_CS,
													 CONFIG_SF_DEFAULT_SPEED,
													 CONFIG_SF_DEFAULT_MODE);
	}
	return (_flash!=0);
}



//-----------------------------------------------
int sli_nvm_read(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	if (initDevice(device))
	{
		// ignoring device for now
		res=spi_flash_read(_flash,offset,len,buffer);
	}
	return res;
}


int sli_nvm_write(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	if (initDevice(device))
	{
		res=sli_nvm_erase(device,offset,len);
		if (!res)
		{
			// ignoring device now
			res=spi_flash_write(_flash,offset,len,buffer);
		}
	}
	return res;
}


int sli_nvm_erase(int device,size_t offset,size_t len)
{
	int res=-1;

	if (initDevice(device))
	{
		// upsize len to proper size
		res=spi_flash_erase(_flash,offset,len);
	}
	return res;
}
