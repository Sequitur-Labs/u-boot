#include <common.h>
#include <compiler.h>
#include <spi.h>
#include <spi_flash.h>
#include <dm/device-internal.h>

#include "sli/sli_io.h"


static struct spi_flash* _flash=0;

static int initDevice(int device)
{
	unsigned int bus = CONFIG_SF_DEFAULT_BUS;
	unsigned int cs = CONFIG_SF_DEFAULT_CS;
	unsigned int speed = CONFIG_SF_DEFAULT_SPEED;
	unsigned int mode = CONFIG_SF_DEFAULT_MODE;
	int ret=0;
#ifdef CONFIG_DM_SPI_FLASH
	struct udevice *new, *bus_dev;
	/* In DM mode defaults will be taken from DT */
	speed = 0, mode = 0;

	/* Remove the old device, otherwise probe will just be a nop */
	ret = spi_find_bus_and_cs(bus, cs, &bus_dev, &new);
	if (!ret) {
		device_remove(new, DM_REMOVE_NORMAL);
	}
	_flash = NULL;
	ret = spi_flash_probe_bus_cs(bus, cs, speed, mode, &new);
	if (ret) {
		printf("Failed to initialize SPI flash at %u:%u (error %d)\n",
		       bus, cs, ret);
		return 1;
	}

	_flash = dev_get_uclass_priv(new);
#else
	struct spi_flash *new;
	if (_flash)
		spi_flash_free(_flash);

	new = spi_flash_probe(bus, cs, speed, mode);
	_flash = new;

	if (!new) {
		printf("Failed to initialize SPI flash at %u:%u\n", bus, cs);
		return 1;
	}

	_flash = new;
#endif

	return (_flash != NULL);
}



//-----------------------------------------------
int sli_nvm_read(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	if (initDevice(device))
	{
		// ignoring device for now
		res=spi_flash_read(_flash,offset,len,buffer);
	} else {
		printf("Failed to initialize SPI device!!!\n");
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

#define SLI_SPI_ERASE_SIZE 0x10000
int sli_nvm_erase(int device,size_t offset,size_t len)
{
	int res=0;

	if (initDevice(device))
	{
		/*
		 * Can only erase SLI_SPI_ERASE_SIZE at a time on some boards
		 */
		uint32_t remaining = len;
		uint32_t erasestart = offset - (offset%SLI_SPI_ERASE_SIZE);
		while(res==0 && remaining > 0){
			//printf("Calling erase on: 0x%08x, size: 0x%08x\n", erasestart, SLI_SPI_ERASE_SIZE);
			res = spi_flash_erase(_flash, erasestart, SLI_SPI_ERASE_SIZE);
			if(remaining > SLI_SPI_ERASE_SIZE) {
				erasestart += SLI_SPI_ERASE_SIZE;
				remaining -= SLI_SPI_ERASE_SIZE;
			} else {
				remaining = 0;
			}
		}
	}
	return res;
}

