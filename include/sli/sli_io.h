#ifndef _SLI_IO_H
#define _SLI_IO_H

#include <linux/types.h>


#define SLIDEV_DEFAULT 0
#define SLIDEV_EMMC    1
#define SLIDEV_MMC     2
#define SLIDEV_QSPI    3
#define SLIDEV_SPI     4


#define SLIDEV_ERR     -1


int sli_nvm_read(int device,size_t offset,size_t len,void* buffer);
int sli_nvm_write(int device,size_t offset,size_t len,void* buffer);
int sli_nvm_erase(int device,size_t offset,size_t len);


#endif
