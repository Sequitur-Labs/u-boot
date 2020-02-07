
#include <common.h>
#include <compiler.h>

#include "sli/sli_control.h"




//-----------------------------------------------
__attribute__((weak))
void sli_reset_board(void)
{
	printf("sli_reset_board - not implemented\n");
}

//-----------------------------------------------
__attribute__((weak))
void sli_setup_watchdog(void)
{
	printf("[%s] - not implemented\n", __func__);
}

//-----------------------------------------------
__attribute__((weak))
unsigned int sli_get_reset_cause(void)
{
	printf("[%s] - not implemented\n", __func__);
	return SLI_RC_UNKNOWN;
}
