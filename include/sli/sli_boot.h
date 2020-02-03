/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/
#ifndef __seq_boot_h__
#define __seq_boot_h__

#define SLI_BOOT_COMPONENT_DDR_BASE 0x60000000
#define SLI_BOOT_VERSION_LENGTH 128

/*
 * Enable this macro to copy kernel and fdt from MMC to DDR,
 * then properly relocated once u-boot is up.
 */
//#define SLI_LOAD_KERNEL_VIA_SLIPS

typedef struct seq_boot_component_info_t {
	char version[SLI_BOOT_VERSION_LENGTH];
	uintptr_t nvsaddr;
	size_t nvslength;
	uintptr_t ramaddr;
	size_t ramlength;
	uint32_t status;
} seq_boot_component_info;

typedef struct seq_boot_filesystem_info_t {
	char version[SLI_BOOT_VERSION_LENGTH];
	uint32_t partition;
	uint32_t status;
} seq_boot_filesystem_info;

typedef struct seq_boot_plex_info_t {
	char model[SLI_BOOT_VERSION_LENGTH];
	char build[SLI_BOOT_VERSION_LENGTH];
	seq_boot_component_info atf;
	seq_boot_component_info coretee;
	seq_boot_component_info uboot;
	seq_boot_component_info kernel;
	seq_boot_component_info fdt;
	seq_boot_filesystem_info rootfs;
	seq_boot_filesystem_info rwfs;
	seq_boot_filesystem_info appfs;
} seq_boot_plex_info;


void reset_with_watchdog( void );

/*
 * Loads the plex manifest.
 *  - If 'plexa' does not equal 0 then load the 'A' plex.
 *  - If 'plexa' equals 0 then load the 'B' plex.
 */
int load_plex_manifest( uint8_t plexa );

/*
 * Returns the current plex. This can be NULL if the manifests have not been loaded yet.
 */
seq_boot_plex_info* sli_get_current_plex( void );

/*
 * Returns the CoreTEE destination address in DDR
 * from the 'current' manifest or -1 if the manifest has not been loaded.
 */
uintptr_t sli_get_coretee_dest_addr( void );

/*
 * Returns the u-boot address in eMMC
 * from the 'current' manifest or -1 if the manifest has not been loaded.
 */
uintptr_t sli_get_uboot_nvm_sector( void );

#endif
