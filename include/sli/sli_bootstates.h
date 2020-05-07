/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#ifndef __sli_bootstates_h__
#define __sli_bootstates_h__

//Boot states.
#define BLC_MAX 5
#define BLC_MMC_OFFSET 0x06

//BLC and Error codes stored in SNVS_LPGPR
#define BLC_MASK 		0xF 		/*Boot loop counter. 	Bits 0-3*/

#define SPL_UPDT_SHIFT	8						/*SPL Update happening - Bits 8-11*/
#define SPL_UPDT_MASK   (0xF << SPL_UPDT_SHIFT)

#define SPL_ERR_SHIFT	12
#define CT_ERR_SHIFT	16
#define UB_ERR_SHIFT	20
#define LX_ERR_SHIFT	24
#define FS_ERR_SHIFT	28
#define SPL_ERR_MASK 	(0xF << SPL_ERR_SHIFT)	/*SPL error				Bits 12-15*/
#define CT_ERR_MASK  	(0xF << CT_ERR_SHIFT)	/*CoreTEE error			Bits 16-19*/
#define UB_ERR_MASK  	(0xF << UB_ERR_SHIFT)	/*U-Boot error			Bits 20-23*/
#define LX_ERR_MASK  	(0xF << LX_ERR_SHIFT)	/*Linux Kernel error	Bits 24-27*/
#define FS_ERR_MASK 	(0xF << FS_ERR_SHIFT)	/*File system error		Bits 28-31*/

#define BLC_ZERO (1 << 16);

#define CORETEE_TZDRAM_SLIP_BASE (0xFDE00000) /*Where the slips are copied to. 2MB Below CoreTEE*/
#define CORETEE_TZDRAM_SLIP_SIZE (0x200000)

//Boot states stored in QSPI (Offset defined in compidx.conf)
#define BS_ACTIVATE (1<<0)
#define BS_UPDATE (1<<1)
#define BS_B_VALID (1<<2)
#define BS_A_VALID (1<<3)
#define BS_A_PRIMARY (1 << 4)
#define BS_MATURE (1<<5)

/*
 * We use the Secure Watchdog to reset the board.
 * This clears the SNVS registers, which is where we stored the value
 * of '*_updating'. We need to move it to NVM. The BootStates work.
 */
#define BS_SPL_UPDATING (1<<6)
#define BS_BOOT_UPDATING (1<<7)


#define PLEX_A_ID 1 /*Value of BS_A_PRIMARY bit*/
#define PLEX_B_ID 0

#define CHECK_STATE(s, x) ((s & x)==x)
#define CLEAR_STATE(s,x) (s &= ~x)
#define SET_STATE(s,x) (s |= x);

/* Where the boot state logic starts. */
void run_boot_start( void );

/*Check the boot state based on value passed in.*/
void boot_state_start( uint32_t stateval );

/*Update the state values*/
void update_boot_state( uint32_t state_val );

/*Read the state values from NVM*/
uint32_t read_boot_state_values( void );

/*Load the 'A' manifest if plexa is 'non-zero' else, load plex 'B'*/
int load_plex_manifest( uint8_t plexa );

#endif
