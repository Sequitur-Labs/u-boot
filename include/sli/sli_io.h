#ifndef _SLI_IO_H
#define _SLI_IO_H

#include <linux/types.h>


#define SLIDEV_DEFAULT 0
#define SLIDEV_EMMC    1
#define SLIDEV_MMC     2
#define SLIDEV_QSPI    3
#define SLIDEV_SPI     4

#define SLIDEV_ERR_OK            0
#define SLIDEV_ERR              -1
#define SLIDEV_ERR_NODEV        -2

#define SLIDEV_ERR_BLKALIGN     -3
#define SLIDEV_ERR_SIZE         -4
#define SLIDEV_ERR_READ         -5
#define SLIDEV_ERR_WRITE        -6
#define SLIDEV_ERR_ERASE        -7


int sli_nvm_read(int device,size_t offset,size_t len,void* buffer);
int sli_nvm_write(int device,size_t offset,size_t len,void* buffer);
int sli_nvm_erase(int device,size_t offset,size_t len);

int sli_nvm_protect(int device,size_t offset,size_t len,int flag);


#endif
