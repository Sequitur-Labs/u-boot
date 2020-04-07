#include <common.h>
#include <asm/io.h>
#include <div64.h>

#include "mach/at91_wdt.h"
#include "mach/sama5d2.h"
#include "sli/sli_control.h"


void sli_reset_board(void)
{
	writel(0xA5000005,ATMEL_BASE_SYSC);
}

#ifdef CONFIG_CORETEE_WATCHDOG
/*
 * AT91SAM9 watchdog runs a 12bit counter @ 256Hz,
 * use this to convert a watchdog
 * value from seconds.
 */
#define WDT_SEC2TICKS(s)	(((s) << 8) - 1)
void sli_setup_watchdog( void ){
	u64 timeout;
	u32 ticks;
	u32 regval;

	printf("Setting watchdog\n");

	/* Calculate timeout in seconds and the resulting ticks */
	timeout = 50000;
	do_div(timeout, 1000);
	timeout = min_t(u64, timeout, WDT_MAX_TIMEOUT);
	ticks = WDT_SEC2TICKS(timeout);

	regval=10000;
	while(regval > 0) regval--;

	regval = readl(ATMEL_BASE_WDT + AT91_WDT_MR);
	printf("MR: 0x%08x\n", regval);
	printf("Ticks: 0x%08x\n", ticks);

	regval &= ~(AT91_WDT_MR_WDDIS);
	writel(regval, ATMEL_BASE_WDT + AT91_WDT_MR);

	regval=10000;
	while(regval > 0) regval--;

	/*
	 * All counting occurs at SLOW_CLOCK / 128 = 256 Hz
	 *
	 * Since WDV is a 12-bit counter, the maximum period is
	 * 4096 / 256 = 16 seconds.
	 */
	regval = AT91_WDT_MR_WDRSTEN	/* causes watchdog reset */
		| AT91_WDT_MR_WDDBGHLT		/* disabled in debug mode */
		| AT91_WDT_MR_WDD(0xfff)	/* restart at any time */
		| AT91_WDT_MR_WDV(ticks);	/* timer value */

	writel(regval, ATMEL_BASE_WDT + AT91_WDT_MR);

	regval=10000;
	while(regval > 0) regval--;

	printf("Restart watchdog\n");
	writel(AT91_WDT_CR_WDRSTT | AT91_WDT_CR_KEY, ATMEL_BASE_WDT + AT91_WDT_CR);

	printf("Done watchdog\n");
	return;
}
#endif

//-----------------------------------------------
//Reset Status Register
#define RST_SR_ADDR 0xF8048004
unsigned int sli_get_reset_cause(void)
{
	unsigned int regval=0;
	unsigned int reason;
	regval = readl(RST_SR_ADDR);
	reason = (regval & 0x0700)>>8;
	printf("Reset Cause: 0x%08x\n", reason);

	switch (reason) {
	case 0x00:
	case 0x01:
		return SLI_RC_POR;
	case 0x02:
		return SLI_RC_WDOG;
	case 0x03:
		/*Software Reset*/
	default:
		break;
	}
	return SLI_RC_UNKNOWN;
}
