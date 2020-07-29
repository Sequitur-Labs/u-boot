#include <common.h>
#include <compiler.h>
#include <mmc.h>
#include <spi.h>
#include <spi_flash.h>
#include <dm/device-internal.h>

#include "sli/sli_io.h"


static struct spi_flash* _flash=0;

#define MMC_SLOTS 2
static struct mmc* _mmc[MMC_SLOTS];

#define MMC_BLOCK_SIZE 512



static int actual_device(int device)
{
	return (device==SLIDEV_DEFAULT) ? SLIDEV_QSPI : device;
}

static int device_select(int device)
{
	return actual_device(device)%10;
}


static int initMMC(int device)
{
	int mmcindex=(device/10)%10;

	if (mmcindex>=0 && mmcindex<MMC_SLOTS)
	{
		int mmcerr=mmc_initialize(0);
		if (!mmcerr)
		{
			_mmc[mmcindex]=find_mmc_device(mmcindex);
			if (_mmc[mmcindex])
			{
				mmcerr=mmc_init(_mmc[mmcindex]);
				if (mmcerr)
				{
					printf("Could not initialize MMC device: %d\n",mmcerr);
					_mmc[mmcindex]=0;
				}
			}
			else
				printf("No MMC device found at %d\n",mmcindex);
		}
		else
			printf("Failed to initialize MMC: %d\n",mmcerr);
	}
	else
		printf("MMC index out of range\n");

	return (_mmc[mmcindex]!=0);
}


static int initEMMC(int device)
{
	// does this exist on this board??
	int res=0;
	return res;
}


static int initFlash(int device)
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




// returns 0 for error, 1 for success
static int initDevice(int device)
{
	int res=0;
	// interpret device
	int devactual=actual_device(device);
	int devpart=devactual%10;
	switch (devpart)
	{
	case SLIDEV_SPI:
	case SLIDEV_QSPI:
		res=initFlash(devactual);
		break;
	case SLIDEV_MMC:
		res=initMMC(devactual);
		break;
	default:
		res=0;
	}

	return res;
}



static int sli_mmc_read(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	// check size is multiple of 512
	if (len%MMC_BLOCK_SIZE==0)
	{
		int mmcindex=(device/10)%10;
		int blocks=len/MMC_BLOCK_SIZE;

		if (_mmc[mmcindex])
		{
			int actualcount=blk_dread(mmc_get_blk_desc(_mmc[mmcindex]),offset,blocks,buffer);
			res=(actualcount==blocks) ? SLIDEV_ERR_OK : SLIDEV_ERR_READ;
			udelay(1000);
		}
		else
			printf("MMC: not initialized\n");
	}
	else
		res=SLIDEV_ERR_SIZE;
	
	return res;
}

//-----------------------------------------------
int sli_nvm_read(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	if (initDevice(device))
	{
		switch (device_select(device))
		{
		case SLIDEV_SPI:
		case SLIDEV_QSPI:
			res=spi_flash_read(_flash,offset,len,buffer);
			break;
		case SLIDEV_MMC:
			res=sli_mmc_read(device,offset,len,buffer);
			break;
		default:
			res=SLIDEV_ERR_NODEV;
		}
	}
	else
		printf("Failed to initialize device: %d\n",device);

	return res;
}


int sli_nvm_write(int device,size_t offset,size_t len,void* buffer)
{
	int res=-1;

	if (initDevice(device))
	{
		switch (device_select(device))
		{
		case SLIDEV_SPI:
		case SLIDEV_QSPI:
			res=sli_nvm_erase(device,offset,len);
			if (!res)
				res=spi_flash_write(_flash,offset,len,buffer);
			break;
		default:
			res=SLIDEV_ERR_NODEV;
		}
	}
	else
		printf("Failed to initialize device: %d\n",device);
	
	return res;
}

#define SLI_SPI_ERASE_SIZE 0x10000
int sli_nvm_erase(int device,size_t offset,size_t len)
{
	int res=0;

	if (initDevice(device))
	{
		switch (device_select(device))
		{
		case SLIDEV_SPI:
		case SLIDEV_QSPI:
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
			break;
		default:
			res=SLIDEV_ERR_NODEV;
		}
	}
	else
		printf ("Failed to initialize device: %d\n",device);
	
	return res;
}

