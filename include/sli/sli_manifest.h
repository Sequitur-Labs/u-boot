#ifndef _SLI_MANIFESTS_H
#define _SLI_MANIFESTS_H


#include <compiler.h>
#include "sli/sli_params.h"

int loadLayouts(uint32_t addr);
int loadManifests(void);

slip_t* getPlexLayout(int index);


#endif
