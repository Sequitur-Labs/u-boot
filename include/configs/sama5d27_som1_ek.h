/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Configuration file for the SAMA5D27 SOM1 EK Board.
 *
 * Copyright (C) 2017 Microchip Corporation
 *		      Wenyou Yang <wenyou.yang@microchip.com>
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include "at91-sama5_common.h"

#undef CONFIG_SYS_AT91_MAIN_CLOCK
# ifndef CONFIG_HD96
#define CONFIG_SYS_AT91_MAIN_CLOCK      24000000 /* from 24 MHz crystal */
# else
#define CONFIG_SYS_AT91_MAIN_CLOCK      12000000 /* from 12 MHz crystal */
# endif

#define CONFIG_MISC_INIT_R

/* SDRAM */
#define CONFIG_NR_DRAM_BANKS		1
# ifdef CONFIG_CORETEE
#define CONFIG_SYS_SDRAM_BASE		0x21400000
#define CONFIG_SYS_SDRAM_SIZE		0x6c00000
# else
#define CONFIG_SYS_SDRAM_BASE		0x20000000
#define CONFIG_SYS_SDRAM_SIZE		0x8000000
# endif

#ifdef CONFIG_SPL_BUILD
#define CONFIG_SYS_INIT_SP_ADDR		0x218000
#else
#define CONFIG_SYS_INIT_SP_ADDR \
	(CONFIG_SYS_SDRAM_BASE + 16 * 1024 - GENERATED_GBL_DATA_SIZE)
#endif

# ifdef CONFIG_CORETEE
# define CONFIG_SYS_LOAD_ADDR           0x23000000 /* load address */
# else
#define CONFIG_SYS_LOAD_ADDR		0x22000000 /* load address */
# endif

/* SerialFlash */
#ifdef CONFIG_CMD_SF
#define CONFIG_SF_DEFAULT_BUS		0
#define CONFIG_SF_DEFAULT_CS		0
#define CONFIG_SF_DEFAULT_SPEED		30000000
#endif

/* NAND flash */
#undef CONFIG_CMD_NAND

/* SPI flash */
# ifndef CONFIG_CORETEE
#define CONFIG_SF_DEFAULT_SPEED		66000000
# endif

#undef CONFIG_BOOTCOMMAND
#ifdef CONFIG_SD_BOOT
/* u-boot env in sd/mmc card */
#define CONFIG_ENV_SIZE		0x4000
/* bootstrap + u-boot + env in sd card */
# ifdef CONFIG_HD96
#define CONFIG_BOOTCOMMAND	"mmc dev 1; fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x21000000 at91-sama5d27_som1_ek.dtb; " \
				"fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x22000000 zImage; " \
				"bootz 0x22000000 - 0x21000000"
#else
#define CONFIG_BOOTCOMMAND	"fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x21000000 at91-sama5d27_som1_ek.dtb; " \
				"fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x22000000 zImage; " \
				"bootz 0x22000000 - 0x21000000"
# endif
#endif

#ifdef CONFIG_QSPI_BOOT
#undef CONFIG_ENV_SPI_BUS
#undef CONFIG_ENV_SPI_CS
#define CONFIG_ENV_SPI_BUS		0
#define CONFIG_ENV_SPI_CS		0
#undef CONFIG_BOOTARGS
# ifdef CONFIG_HD96
#define CONFIG_BOOTARGS \
	"console=ttyS0,115200 earlyprintk root=/dev/mmcblk0p2 rw rootwait"
#else
#define CONFIG_BOOTARGS \
	"console=ttyS0,115200 earlyprintk root=/dev/mmcblk1p2 rw rootwait"
#endif
#endif

/* SPL */
#define CONFIG_SPL_TEXT_BASE		0x200000
#define CONFIG_SPL_MAX_SIZE		0x10000
# ifdef CONFIG_CORETEE
# define CONFIG_SPL_BSS_START_ADDR      0x22000000
# else
#define CONFIG_SPL_BSS_START_ADDR	0x20000000
# endif
#define CONFIG_SPL_BSS_MAX_SIZE		0x80000
# ifdef CONFIG_CORETEE
# define CONFIG_SYS_SPL_MALLOC_START    0x22080000
# else
#define CONFIG_SYS_SPL_MALLOC_START	0x20080000
# endif
#define CONFIG_SYS_SPL_MALLOC_SIZE	0x80000

#define CONFIG_SYS_MONITOR_LEN		(512 << 10)

#ifdef CONFIG_SD_BOOT
#define CONFIG_SYS_MMCSD_FS_BOOT_PARTITION	1
#define CONFIG_SPL_FS_LOAD_PAYLOAD_NAME		"u-boot.img"
#endif

#ifdef CONFIG_QSPI_BOOT
#define CONFIG_SYS_SPI_U_BOOT_OFFS	0x10000
#endif

#endif
