/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Configuration file for the SAMA5D2 Xplained Board.
 *
 * Copyright (C) 2015 Atmel Corporation
 *		      Wenyou Yang <wenyou.yang@atmel.com>
 */

#ifndef __CONFIG_H
#define __CONFIG_H

#include "at91-sama5_common.h"

#define CONFIG_MISC_INIT_R

/* SDRAM */
#define CONFIG_NR_DRAM_BANKS		1
# ifdef CONFIG_CORETEE                                                         
#define CONFIG_SYS_SDRAM_BASE           0x21400000                             
#define CONFIG_SYS_SDRAM_SIZE          0x1ec00000
# else
#define CONFIG_SYS_SDRAM_BASE           0x20000000
#define CONFIG_SYS_SDRAM_SIZE		0x20000000
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
# endif // CONFIG_CORETEE

#define SLI_SPL_SCRATCH 0x26000000
#define SLI_SPL_SCRATCH_SIZE 0x40000000


/* SerialFlash */
#ifdef CONFIG_CMD_SF
#define CONFIG_SF_DEFAULT_BUS		0
#define CONFIG_SF_DEFAULT_CS		0
#define CONFIG_SF_DEFAULT_SPEED		30000000
#endif

#ifdef CONFIG_SD_BOOT

/* bootstrap + u-boot + env in sd card */
#undef CONFIG_BOOTCOMMAND

#define CONFIG_BOOTCOMMAND	"fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x21000000 at91-sama5d2_xplained.dtb; " \
				"fatload mmc " CONFIG_ENV_FAT_DEVICE_AND_PART " 0x22000000 zImage; " \
				"bootz 0x22000000 - 0x21000000"

#elif CONFIG_SPI_BOOT

/* bootstrap + u-boot + env in sd card, but kernel + dtb in eMMC */
#undef CONFIG_BOOTCOMMAND

#define CONFIG_BOOTCOMMAND	"ext4load mmc 0:1 0x21000000 /boot/at91-sama5d2_xplained.dtb; " \
				"ext4load mmc 0:1 0x22000000 /boot/zImage; " \
				"bootz 0x22000000 - 0x21000000"

#endif

#ifdef CONFIG_QSPI_BOOT
#undef CONFIG_ENV_SPI_BUS
#undef CONFIG_ENV_SPI_CS
#undef CONFIG_BOOTCOMMAND
#define CONFIG_ENV_SPI_BUS		1
#define CONFIG_ENV_SPI_CS		0
#define CONFIG_BOOTCOMMAND              "sf probe 1:0; "				\
                                        "sf read 0x21000000 0x180000 0x80000; "		\
                                        "sf read 0x22000000 0x200000 0x600000; "	\
                                        "bootz 0x22000000 - 0x21000000"

#endif

/* SPL */
#define CONFIG_SPL_TEXT_BASE		0x200000
//#define CONFIG_SPL_MAX_SIZE		0x10000
#define CONFIG_SPL_MAX_SIZE		0x18000
# ifdef CONFIG_CORETEE
#define CONFIG_SPL_BSS_START_ADDR	0x25000000
# else
#define CONFIG_SPL_BSS_START_ADDR	0x20000000
# endif
//#define CONFIG_SPL_BSS_MAX_SIZE		0x80000
#define CONFIG_SPL_BSS_MAX_SIZE		0x00100000
# ifdef CONFIG_CORETEE
//#define CONFIG_SYS_SPL_MALLOC_START	0x22080000
#define CONFIG_SYS_SPL_MALLOC_START	0x25100000
# else
#define CONFIG_SYS_SPL_MALLOC_START	0x20080000
# endif
//#define CONFIG_SYS_SPL_MALLOC_SIZE	0x80000
#define CONFIG_SYS_SPL_MALLOC_SIZE	0x00800000

#define CONFIG_SYS_MONITOR_LEN		(512 << 10)

#ifdef CONFIG_SD_BOOT
#define CONFIG_SYS_MMCSD_FS_BOOT_PARTITION	1
#define CONFIG_SPL_FS_LOAD_PAYLOAD_NAME		"u-boot.img"

#elif CONFIG_SPI_BOOT
#define CONFIG_SYS_SPI_U_BOOT_OFFS	0x10000

#elif CONFIG_QSPI_BOOT
# define CONFIG_SYS_SPI_U_BOOT_OFFS     0x10000

#endif


#ifdef CONFIG_CORETEE
/*
 * The following values must hold the update package, the main payload then individual components.
 */
#undef CONFIG_UPDATE_PAYLOAD_ADDR
#undef CONFIG_UPDATE_CONTENT_ADDR
#undef CONFIG_UPDATE_COMPONENT_ADDR

#define CONFIG_UPDATE_PAYLOAD_ADDR 0x3E000000
#define CONFIG_UPDATE_CONTENT_ADDR 0x3EB00000
#define CONFIG_UPDATE_COMPONENT_ADDR 0x3F800000

#endif

#endif
