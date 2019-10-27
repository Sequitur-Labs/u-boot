// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Atmel Corporation
 *		      Bo Shen <voice.shen@atmel.com>
 */

#include <common.h>
#include <asm/io.h>
#include <asm/arch/at91_common.h>
#include <asm/arch/at91_pit.h>
#include <asm/arch/at91_pmc.h>
#include <asm/arch/at91_rstc.h>
#include <asm/arch/at91_wdt.h>
#include <asm/arch/clk.h>
#include <spl.h>

static void switch_to_main_crystal_osc(void)
{
	struct at91_pmc *pmc = (struct at91_pmc *)ATMEL_BASE_PMC;
	u32 tmp;

	tmp = readl(&pmc->mor);
	tmp &= ~AT91_PMC_MOR_OSCOUNT(0xff);
	tmp &= ~AT91_PMC_MOR_KEY(0xff);
	tmp |= AT91_PMC_MOR_MOSCEN;
	tmp |= AT91_PMC_MOR_OSCOUNT(8);
	tmp |= AT91_PMC_MOR_KEY(0x37);
	writel(tmp, &pmc->mor);
	while (!(readl(&pmc->sr) & AT91_PMC_IXR_MOSCS))
		;

#if defined(CONFIG_SAMA5D2)
	/* Enable a measurement of the external oscillator */
	tmp = readl(&pmc->mcfr);
	tmp |= AT91_PMC_MCFR_CCSS_XTAL_OSC;
	tmp |= AT91_PMC_MCFR_RCMEAS;
	writel(tmp, &pmc->mcfr);

	while (!(readl(&pmc->mcfr) & AT91_PMC_MCFR_MAINRDY))
		;

	if (!(readl(&pmc->mcfr) & AT91_PMC_MCFR_MAINF_MASK))
		hang();
#endif

	tmp = readl(&pmc->mor);
	tmp &= ~AT91_PMC_MOR_OSCBYPASS;
	tmp &= ~AT91_PMC_MOR_KEY(0xff);
	tmp |= AT91_PMC_MOR_KEY(0x37);
	writel(tmp, &pmc->mor);

	tmp = readl(&pmc->mor);
	tmp |= AT91_PMC_MOR_MOSCSEL;
	tmp &= ~AT91_PMC_MOR_KEY(0xff);
	tmp |= AT91_PMC_MOR_KEY(0x37);
	writel(tmp, &pmc->mor);

	while (!(readl(&pmc->sr) & AT91_PMC_IXR_MOSCSELS))
		;

#if !defined(CONFIG_SAMA5D2)
	/* Wait until MAINRDY field is set to make sure main clock is stable */
	while (!(readl(&pmc->mcfr) & AT91_PMC_MAINRDY))
		;
#endif

#if !defined(CONFIG_SAMA5D4) && !defined(CONFIG_SAMA5D2)
	tmp = readl(&pmc->mor);
	tmp &= ~AT91_PMC_MOR_MOSCRCEN;
	tmp &= ~AT91_PMC_MOR_KEY(0xff);
	tmp |= AT91_PMC_MOR_KEY(0x37);
	writel(tmp, &pmc->mor);
#endif
}

__weak void matrix_init(void)
{
	/* This only be used for sama5d4 soc now */
}

__weak void redirect_int_from_saic_to_aic(void)
{
	/* This only be used for sama5d4 soc now */
}

/* empty stub to satisfy current lowlevel_init, can be removed any time */
void s_init(void)
{
}

# if defined(CONFIG_CORETEE)
# include <spi_flash.h>
# include <sm_func.h>

struct tee_image_info {
  const char *name;
  u8 os;
  u32 load_addr;
  u32 read_addr;
  u32 entry_point;
  u32 size;
  u32 flags;
};

static struct tee_image_info tee_image;

static void tee_parse_image_header(const struct image_header *header)
{
  u32 header_size = sizeof(struct image_header);

  if (image_get_magic(header) == IH_MAGIC) {
    tee_image.entry_point = image_get_ep(header);
    /* Load including the header */
    tee_image.load_addr = image_get_load(header);
    tee_image.size = image_get_data_size(header) +
      header_size;

    tee_image.read_addr = tee_image.load_addr - header_size;

    tee_image.os = image_get_os(header);
    tee_image.name = image_get_name(header);
    printf("%s(%d): tee: payload image: %.*s load addr: 0x%x read addr: 0x%x size: %d\n",
	   __func__, __LINE__,
	   (int)sizeof(tee_image.name), tee_image.name,
	   tee_image.load_addr, tee_image.read_addr, tee_image.size);
  }
}

# define CORETEE_FW_SPI_OFFSET 0x100000
# define TEE_LOAD              0x21000000

void coretee_setup(void)
{
  struct spi_flash *tee_flash;
  int ret;
  /* load tee from SPI. */
  void *addr;
  struct image_header *header;

  //asm volatile("b .\n");

  tee_flash = spi_flash_probe(CONFIG_SF_DEFAULT_BUS,
			      CONFIG_SF_DEFAULT_CS,
			      CONFIG_SF_DEFAULT_SPEED, CONFIG_SF_DEFAULT_MODE);

  if (!tee_flash) {
    printf("Unable to load CoreTEE from SF/SPI (skipped).\n");
    return;
  }

  addr = (void *)TEE_LOAD;

  /*
    read the header
  */
  ret = spi_flash_read(tee_flash, CORETEE_FW_SPI_OFFSET,
		       128, addr);

 //flush_dcache_range(CONFIG_CORETEE_FW_SPI_OFFSET, CONFIG_CORETEE_FW_SPI_OFFSET+128);

  header = (struct image_header *)addr;

  if (image_get_magic(header) != IH_MAGIC) {
    printf("CoreTEE image not found\n");
    goto fail;
  }

  tee_parse_image_header(header);

  ret = spi_flash_read(tee_flash, CORETEE_FW_SPI_OFFSET,
		       tee_image.size, (void *)tee_image.read_addr);

  printf("CoreTEE: %d bytes read [ret: %d]\n", tee_image.size, ret);

  memcpy(addr, (void *)tee_image.load_addr, tee_image.size);

  // clean dcache...
  flush_dcache_range(tee_image.read_addr, tee_image.read_addr + tee_image.size);

  tee_load(tee_image.entry_point,
	   tee_image.load_addr,
	   tee_image.size - sizeof(*header), // don't copy the header
	   0,
	   0,
	   0);



/*
  define TEST_SPI_FLASH_IO
  to test SPL/SPI driver.
*/
# ifdef TEST_SPI_FLASH_IO
  {
    uint32_t *tmp = (uint32_t *)tee_image.load_addr;
    uint32_t val = *tmp;

    spi_flash_erase(tee_flash, CONFIG_CORETEE_FW_SPI_OFFSET,
		    0x8d000);
    *tmp = 0xdeadbeef;
    spi_flash_write(tee_flash, CONFIG_CORETEE_FW_SPI_OFFSET,
		    tee_image.size, (void *)tmp);
    *tmp = val; /* restore */
  }
# endif

 fail:
  return;
}
# endif /* CONFIG_CORETEE */

void board_init_f(ulong dummy)
{
	int ret;

	switch_to_main_crystal_osc();

#if defined(CONFIG_SAMA5D2) && !defined(CONFIG_CORETEE)
	configure_2nd_sram_as_l2_cache();
#endif

#if !defined(CONFIG_AT91SAM9_WATCHDOG)
	/* disable watchdog */
	at91_disable_wdt();
#endif

	/* PMC configuration */
	at91_pmc_init();

	at91_clock_init(CONFIG_SYS_AT91_MAIN_CLOCK);

# ifndef CONFIG_CORETEE
	matrix_init();

	redirect_int_from_saic_to_aic();

# endif
	timer_init();

	board_early_init_f();

	mem_init();

	ret = spl_init();
	if (ret) {
		debug("spl_init() failed: %d\n", ret);
		hang();
	}

	preloader_console_init();

# ifdef CONFIG_CORETEE
	printf("BSp version: 0x%08x\n", tee_version());
        coretee_setup();
	printf("TEE version: 0x%08x\n", tee_version());
# endif
	
}
