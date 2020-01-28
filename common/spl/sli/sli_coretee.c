# if defined(CONFIG_CORETEE)

#include <common.h>
#include <sm_func.h>

#include "sli/sli_coretee.h"



//-----------------------------------------------
void coretee(uint32_t jump,size_t size)
{
	flush_dcache_range(jump,jump+size);
	
	printf("Invoking CoreTEE load...\n");
	tee_load(jump,
					 jump,
					 size,
					 0,
					 0,
					 0);

	/* #ifdef CONFIG_CORETEE_CRYPTO */
	/* 					/\* */
	/* 						initialize the SMC crypto interface */
	/* 					*\/ */
	/* 					//sliCryptoInit(NULL, 1024); */
	/* 					sliCryptoInit(addr, 1024);	/\* Use coretee copy location as buffer space *\/ */
	/* 					sliCryptoTerm(1); */
	/* #endif */

}

# endif /* CONFIG_CORETEE */
