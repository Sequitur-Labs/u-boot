
#include <common.h>
#include <compiler.h>

#include "sli/sli_io.h"






//-----------------------------------------------
__attribute__((weak))
int sli_nvm_read(int device,size_t offset,size_t len,void* buffer)
{
	int res=SLIDEV_ERR;
	printf("sli_nvm_read - not implemented\n");
	return res;
}

__attribute__((weak))
int sli_nvm_write(int device,size_t offset,size_t len,void* buffer)	
{
	int res=SLIDEV_ERR;
	printf("sli_nvm_write - not implemented\n");
	return res;
}

__attribute__((weak))
int sli_nvm_erase(int device,size_t offset,size_t len)
{
	int res=SLIDEV_ERR;
	printf("sli_nvm_erase - not implemented\n");
	return res;
}
