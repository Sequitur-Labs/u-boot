#include <common.h>

#include <asm/io.h>

#include "mach/sama5d2.h"
#include "sli/sli_control.h"


void sli_reset_board(void)
{
	writel(0xA5000005,ATMEL_BASE_SYSC);
}
