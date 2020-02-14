#ifndef _SLI_MANIFESTS_H
#define _SLI_MANIFESTS_H


#include <compiler.h>
#include "sli/sli_params.h"

#define SLIP_ID_LAYOUT 0
#define SLIP_ID_CERTIFICATES 1

/*SPI Erase Size - 64KB*/
#define SLI_SLIP_MAX_SIZE 0x10000

int loadLayouts(uint32_t addr);
int loadManifests(void);

slip_t* getComponentManifest( void );


#endif
