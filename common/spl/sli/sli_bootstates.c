#include <common.h>
#include <memalign.h>
#include <asm/io.h>

#include <sm_func.h>
#include <sli/sli_io.h>
#include <sli/sli_params.h>
#include <sli/sli_update.h>
#include <sli/sli_component.h>
#include <sli/sli_manifest.h>
#include "sli/sli_coretee.h"

#ifdef CONFIG_SPL_SLIENCRYPTEDBOOT
#include <sli_keys.h>
int blob_decap(u8*,u8*,u8*,u32);
#endif

#include <sli/sli_bootstates.h>

static int _device=SLIDEV_DEFAULT;

//Internal Declarations
uint8_t str2byte(const char p, uint8_t base);
void hex2bytes(const char *p, uint8_t *b, int count);
char * byteToHex( uint8_t byte );
void outputData( uint8_t *data, uint32_t len);

uint8_t str2byte(const char p, uint8_t base) {
  if ((base == 8) && (p>='0') && (p<='7'))
    return p - '0';
  else if ((base == 10) && (p>='0') && (p<='9'))
    return p - '0';
  else if (base == 16) {
    if ((p>='0') && (p<='9'))
      return p - '0';
    else if ((p>='a') && (p<='f'))
      return p - 'a' + 10;
    else if ((p>='A') && (p<='F'))
      return p - 'A' + 10;
    else
      return 0xff;
  } else
    return 0xff;
}

void hex2bytes(const char *p, uint8_t *b, int count) {
  int i, i_max = (count+1)>>1;
  for (i = 0; i < i_max; i++) {
    if ((i == 0) && (count & 0x1)) {
      p--;  /* Odd number of characters, so pretend there is a leading '0' */
      b[0] = str2byte(p[1], 16);
    } else
      b[i] = (str2byte(p[2*i], 16)<<4) + str2byte(p[2*i+1], 16);
  }
}

char * byteToHex( uint8_t byte ){
  static const char * hex = "0123456789ABCDEF";
  static char hexstr[2];
  memset(hexstr, 0, 2);

  hexstr[0] = hex[(byte>>4) & 0xF];
  hexstr[1] =   hex[ byte & 0xF];
  return hexstr;
}

void outputData( uint8_t *data, uint32_t len){
  static char buffer[512];
  unsigned long bx=0;
  uint32_t i=0;
  memset(buffer, 0, 512);
  for(i = 0; i < len; i++){
	  memcpy(buffer+bx*2, byteToHex(data[i]), 2);
	  bx++;
	  if(bx == 16){
		//printf("[%d]  %s\n", (i/16), buffer);
		printf("%s\n", buffer);
		memset(buffer, 0, 512);
		bx=0;
	  }
  }
  if(bx != 0){
	  //printf("[%d]  %s\n\n", (i/16), buffer);
	  printf("%s\n", buffer);
  }
}



//#define RUN_UPDATE

static void jump_to_uboot(uint32_t entry)
{
	typedef void __noreturn (*uboot_entry_t)(void);
	uboot_entry_t ue=(uboot_entry_t)entry;

	printf("Invoking U-Boot: 0x%08x\n",entry);

	ue();

	// should not return from here
	printf("U-Boot load FAILED\n");
}

void load_coretee( uint8_t plexid ){
	size_t coretee_size=0;
	uint32_t coretee_jump=component_setup(plexid == PLEX_A_ID ? PLEX_ID_A_STR : PLEX_ID_B_STR , "coretee","CoreTEE",&coretee_size);
	if (coretee_jump && coretee_size)
		coretee(coretee_jump,coretee_size);
	//Should return non-secure
}

void load_certs( void ){
	slip_t *slip = getComponentManifest();
	if(!slip){
		return;
	}
	uint32_t cert_nvm = sli_entry_uint32_t( slip, "p13n", "certs_src" );
	uint32_t cert_ddr = sli_entry_uint32_t( slip, "p13n", "certs_dst" );
	loadComponentBuffer( cert_nvm, (void*)cert_ddr );

	handle_certs( cert_ddr );
}

void load_plex_components( uint8_t plexid ){
	//First load coretee
	load_coretee( plexid );

	//Now that CoreTEE is up, send it the certs
	load_certs( );

#ifdef SLI_LOAD_KERNEL_VIA_SLIPS
	//If we need to install kernel & fdt from SPL
	fdt_setup( current_plex );
	kernel_setup( current_plex );
#endif

	// u-boot
	uint32_t uboot_jump=component_setup(plexid == PLEX_A_ID ? PLEX_ID_A_STR : PLEX_ID_B_STR,"uboot","U-Boot",0);
	if (uboot_jump)
		jump_to_uboot(uboot_jump);
}

void setup_components( void ){
	size_t coretee_size=0;
	uint32_t coretee_jump=component_setup(PLEX_ID_A_STR, "coretee","CoreTEE",&coretee_size);
	if (coretee_jump && coretee_size)
		coretee(coretee_jump,coretee_size);

	// u-boot
	uint32_t uboot_jump=component_setup(PLEX_ID_A_STR,"uboot","U-Boot",0);
	if (uboot_jump)
		jump_to_uboot(uboot_jump);
}
/* CONFIG_CORETEE_FW_IN_MMC */

//BLC = Boot Loop Counter
uint8_t get_blc( void ){
	unsigned int val;
	blc_op(GET_BLC, &val);
	return (uint8_t)(val & 0xFF);
}

void set_blc_max( void ){
	unsigned int val=0;
	blc_op(SET_BLC_MAX, &val);
}

void decrement_blc(void){
	unsigned int val=0;
	blc_op(DECREMENT_BLC, &val);
}

void check_bricked(unsigned int por, uint32_t state){
	uint32_t blc = 0;

	//printf("[%s] - Calling get_blc\n", __func__);
	blc = get_blc();
	if(blc == 0)
		state |= BLC_ZERO;
	//printf("[%s] BLC: %d\n", __func__, blc);

	/*
	 * If POR then we don't care about BLC just the validity of the plex or possible actions.
	 * If BLC doesn't equal zero then we can't be bricked yet.
	 * If BLC == 0 then if we have any valid plex or any action we are not bricked.
	 */
	//printf("Check bricked. por/blc %d    state: %x    check value: %x\n", (por || blc==0), state, (BS_ACTIVATE | BS_UPDATE | BS_B_VALID | BS_A_VALID));
	if((por || blc==0) && ((state & (BS_ACTIVATE | BS_UPDATE | BS_B_VALID | BS_A_VALID )) == 0)){
		//Bricked!!!!!
		printf("Bricked!!!\n");

		//printf("BUT NOT HALTING!!! CONTINUE\n");
		while(1){}
	}
}

//Reset Status Register
#define RST_SR_ADDR 0xF8048004
/*
  Return reset-status string
*/
static char *get_reset_cause(void)
{
	unsigned int regval=0;
	unsigned int reason;
	regval = readl(RST_SR_ADDR);
	reason = (regval & 0x0700)>>8;
	printf("Reset Cause: 0x%08x\n", reason);

	switch (reason) {
	case 0x00:
	case 0x01:
	case 0x02:
		return "POR";
	case 0x03:
	    return "WDOG";
	default:
		return "unknown reset";
	}
}

void check_startup_registers(void){
	char buffer[64];
	char *cause = get_reset_cause();
	uint32_t state = 0;
	state = (read_boot_state_values() & 0xFF);

	sprintf(buffer, "Reset reason: %s\nState: 0x%02x\n", cause, state);
	puts(buffer);

	if(strcmp(cause, "POR")==0){
		//This is a power on reset. Set BLC to max.
		check_bricked(1, state);
		set_blc_max();
	}
}

/*
 *
 */
void activate_plex( uint8_t plexid, uint32_t stateval ){
	CLEAR_STATE(stateval, BS_ACTIVATE);

	if(plexid == PLEX_A_ID) {
		SET_STATE(stateval, BS_A_PRIMARY);
	}
	else {
		CLEAR_STATE(stateval, BS_A_PRIMARY);
	}

	//Save cleared 'activate' flag back to SPI.
	update_boot_state(stateval);

	//Cycle through again.
	set_blc_max();
	boot_state_start( stateval );
}

/*
 *
 */
void update_plex( uint8_t plexid, uint32_t stateval ){
	int res=0;
	unsigned int mdoyle_todo_unused_warning_implement_manifest_change;

	//int index = (plexid == PLEX_A_ID) ? SLIP_PLEX_A : SLIP_PLEX_B;
	//uintptr_t ddr_dest;
	//uint8_t *binaryparams = 0;
	//int paramsize = 0;
	CLEAR_STATE(stateval, BS_UPDATE);

	printf("Running update against plexID: %s\n", (plexid==0) ? "B" : "A");
	res = run_update( plexid );
#ifdef RUN_UPDATE
	printf("Result of run_update: %d\n", res);
	while(1){}
#endif
	if(res){
		//Update failed. Clear activate state
		char msg[]="Failed to run update. Clearing activate\n";
		printf(msg);
		CLEAR_STATE(stateval, BS_ACTIVATE);
		update_boot_state(stateval);
		boot_state_start( stateval );
		return;
	}

	//Save updated plex information to DDR for CoreTEE
	/*ddr_dest = CORETEE_TZDRAM_SLIP_BASE + SLIPSIZE*index;
	binaryparams = sli_binaryParams( get_slip(index), &paramsize);
	memcpy((void*)ddr_dest, binaryparams, paramsize);
	free(binaryparams);*/

	if(plexid == PLEX_A_ID) {
		SET_STATE(stateval, BS_A_VALID);
	}
	else {
		SET_STATE(stateval, BS_B_VALID);
	}

	//If activating then we'll save the boot state after clearing the activate flag.
	//If not activating then we'll need to save the boot state with the cleared update flag.
	if(CHECK_STATE(stateval, BS_ACTIVATE)){
		printf("[SLI] - Activate plex set. Activating non-primary plex\n");
		//Activate 'other' plex
		activate_plex(plexid, stateval);
	} else {
		//Save cleared 'update' flag back to SPI.
		update_boot_state(stateval);

		//Cycle through again.
		set_blc_max();
		boot_state_start( stateval );
	}
}

void invalidate_plex( uint8_t plexa, uint32_t stateval ){
	/*
	 * Invalidate the current plex (set valid to false).
	 * Switch to other plex.
	 * 'Brick' if both plexes are invalid and no actions.
	 */
	CLEAR_STATE(stateval, (plexa ? BS_A_VALID : BS_B_VALID) );
	if(plexa) {
		CLEAR_STATE(stateval, BS_A_PRIMARY);
	} else {
		SET_STATE(stateval, BS_A_PRIMARY);
	}

	//Save new plex and invalid state back to SPI
	update_boot_state(stateval);

	//Check to make sure at least one of the plexes is 'valid', or updateable
	check_bricked(0, stateval);

	//Cycle through again on other plex. If/When BLC hits zero then we are bricked/
	set_blc_max();
	boot_state_start(stateval);
}

/*
 * Write state_val to SPI flash at address SPI_STATE_ADDR
 */
void update_boot_state( uint32_t state_val ){
	int res=0;
	slip_t* layout=getComponentManifest();
	if(!layout){
		printf("Component layout slip not found\n");
		return;
	}

	uint32_t addr=sli_entry_uint32_t(layout,"p13n","bsv");

	printf("Setting boot state to: 0x%02x at addr: 0x%08x\n", (state_val & 0xFF), addr);
	res = sli_nvm_write(_device, addr, sizeof(uint32_t), &state_val);
	if(res){
		printf("Failed to save boot state!!!\n");
	}
	printf("Successfully updated Boot State\n");
}


uint32_t read_boot_state_values( void ){
	slip_t* layout=getComponentManifest();
	uint32_t bsv=0;
	if(!layout){
		printf("Component layout slip not found\n");
		return 0;
	}

	uint32_t addr=sli_entry_uint32_t(layout,"p13n","bsv");
	int iores=sli_nvm_read(_device,addr,sizeof(uint32_t),&bsv);

	return bsv;
}

void check_boot_state(uint32_t stateval){
	uint32_t blc=0;
	uint8_t aisprimary;

#ifdef RUN_UPDATE
	printf("Calling update_plex\n");
	update_plex(PLEX_B_ID, stateval);
#endif

	printf("[%s] - Stateval: 0x%02x\n", __func__, stateval & 0xFF);

	//Are we bricked?
	check_bricked(0, stateval);

	blc = get_blc();
	printf("[%s] - BLC: %d\n", __func__, blc);

	aisprimary = CHECK_STATE(stateval, BS_A_PRIMARY);

	/*
		* When checking the 'states' the actions update and activate are the most important, with
		* update being done before activate (if set).
		*
		* The 'bricked' state was already checked but if blc has been decremented to 0 then
		* we need to invalidate the current plex and test the states again.
		*
		* If all those tests pass then we can proceed with a normal boot.
	*/
    if( CHECK_STATE(stateval, BS_UPDATE) ){
    	printf("[SLI] - Update plex set. Updating non-primary plex\n");
        //Update 'other' plex
        update_plex(!aisprimary, stateval);
    } else if( CHECK_STATE(stateval, BS_ACTIVATE) ){
        printf("[SLI] - Activate plex set. Activating non-primary plex\n");
        //Activate 'other' plex
        activate_plex(!aisprimary, stateval);
    } else if(blc==0){
        //set current plex valid to false. Check boot states again.
        printf("[SLI] - Invalidate plex: blc = %d,  a primary %d   stateval: %x\n", blc, aisprimary, stateval);
        invalidate_plex(aisprimary, stateval);
    } else {
        load_plex_components( aisprimary );
    }
}

void boot_state_start( uint32_t stateval ){
	//Always decrement boot counter.
	decrement_blc();

	//Determine boot state
	check_boot_state(stateval);
}

#if 0
static uint32_t get_slip_offset( int index ){
	char *name=NULL;
	if(index == 0) return 0;

	return index * (SLIPSIZE/SLI_MMC_BLOCK_SIZE);

	/*name=getSlipName(index);
	if (name)
	{
		uintptr_t address=getSubSlipAddress(name);
		// printf("[%s] NVM:   %ld\n", __func__, address);
		return address - CORETEE_COMPONENT_DATA_OFFSET;
	} else
		return -1;*/
}


static uint8_t AESMAGIC[8]={'a','e','s','s','l','i','p',0x00};

typedef struct cryptslip
{
	uint8_t magic[8];
	uint32_t size;
} cryptslip_t;

static uint8_t* getAESSlipKey(int index,size_t* size)
{
	uint8_t* key=0;

	switch (index)
	{
	case SLIP_KEYRING:
		{
			slip_t* oemslip=get_slip(SLIP_OEM);
			if (oemslip)
			{
				slip_key_t* aeskey=sli_findParam(oemslip,"crypt","ringkey");
				if (aeskey)
				{
					key=(uint8_t*)malloc_cache_aligned(aeskey->size);
					memcpy(key,aeskey->value,aeskey->size);
					*size=aeskey->size;
				}
			}
		}
		break;
	case SLIP_CERTS:
		{
			slip_t* seqslip=get_slip(SLIP_SEQ);
			if (seqslip)
			{
				slip_key_t* aeskey=sli_findParam(seqslip,"crypt","certkey");
				if (aeskey)
				{
					key=(uint8_t*)malloc_cache_aligned(aeskey->size);
					memcpy(key,aeskey->value,aeskey->size);
					*size=aeskey->size;
				}
			}
		}
		break;
	}

	return key;
}

static void manage_slip(int index,uintptr_t* address){
	uintptr_t ddr_dest=0;
	int ret=0;

	uint32_t slip_offset=get_slip_offset(index)*SLI_MMC_BLOCK_SIZE;

	printf("Slip offset for index[%d] is : %d\n", index, slip_offset);

	switch (index)
	{
	case SLIP_CERTS:
	case SLIP_KEYRING: // *** NOTE THAT THIS DEPENDS ON the OEM_SLIP existing
		{
			uint8_t* ebuffer;
			printf("Processing AES slip [%d]\n",index);
			
			ddr_dest = CORETEE_TZDRAM_SLIP_BASE + slip_offset;

			// load from mmc
			ebuffer=(uint8_t*)malloc_cache_aligned(SLIPSIZE);
			printf("Read AES blob 0x%08lx to 0x%08lx\n",*address,ddr_dest);
			ret=sli_mmc_read(*address,SLIPSIZE,ebuffer);
			if (!ret)
			{
				// check ebuffer for aesmagic header
				cryptslip_t* cheader=(cryptslip_t*)ebuffer;
				if (!memcmp(cheader->magic,AESMAGIC,sizeof(AESMAGIC)))
				{
					int cryptres=0;
					size_t keysize=0;
					uint8_t* key=getAESSlipKey(index,&keysize);
					size_t buffersize=cheader->size;

					if (key)
					{
						// this overwrites the header! Do not use cheader after this point
						memmove(ebuffer,ebuffer+sizeof(cryptslip_t),SLIPSIZE-sizeof(cryptslip_t));

						cryptres=decAesCtr(key,keysize,ebuffer,(uint8_t*)ddr_dest,buffersize);
						printf("AES slip decryption result: %d\n",cryptres);

						free(key);
					}
					else
						printf("AES slip could not be decrypted (missing key)\n");
				}
				else
				{
					printf("AES slip in plain\n");
					memcpy((void*)ddr_dest,ebuffer,SLIPSIZE);
				}
			}
			else
			{
				printf("FAILED to read AES blob header: %d\n",ret);
				*address=0;
				return; // ** NOTE - thie will leak a SLIPSIZE buffer!!!
			}

			free(ebuffer);
		}
		break;
	default:
		{
#ifdef CONFIG_SPL_SLIENCRYPTEDBOOT
			uint8_t* ebuffer;
			uint8_t* rnd=(uint8_t*)malloc_cache_aligned(32);
			memset(rnd,0,32);
			select_otpmk();
			ddr_dest = CORETEE_TZDRAM_SLIP_BASE + slip_offset;

			ebuffer=(uint8_t*)malloc_cache_aligned(SLIPSIZE);

			printf("Read blob 0x%08lx to 0x%08lx\n", *address, ddr_dest);
			ret=sli_mmc_read(*address,SLIPSIZE,ebuffer);
			if (!ret)
			{
				blobheader_t header;
				memcpy(&header,ebuffer,sizeof(blobheader_t));
				//printf("totalsize: 0x%x   payloadsize: 0x%x\n",header.totalsize,header.payloadsize);
				memmove(ebuffer,ebuffer+sizeof(blobheader_t),header.totalsize-sizeof(blobheader_t));

				ret=blob_decap((u8*)rnd,(u8*)ebuffer,(u8*)ddr_dest,header.payloadsize);
				if (ret)
				{
					printf("FAILED to decrypt blob for index[%d] : %d\n",index,ret);
					*address=0;
					return;
				}
			}
			else
			{
				printf("FAILED to read blob header for index[%d] : %d\n",index,ret);
				*address=0;
				return; // ** NOTE - thie will leak a SLIPSIZE buffer!!!
			}

			free(ebuffer);
			free(rnd);
#else
			//SLI - no decrypting yet, just copy.
			ddr_dest = CORETEE_TZDRAM_SLIP_BASE + slip_offset;

			/*
				Copy the entire SLIP
			*/
			printf("Copying SLIP from [%ld]-0x%08lx to 0x%08lx\n", *address, *address, ddr_dest);
			ret = sli_mmc_read(*address, SLIPSIZE, (void*)ddr_dest);
			if(ret) {
				printf("FAILED to load component information for index[%d] from MMC\n", index);
				printf("Error: 0x%08x\n", ret);
				*address = 0;
				return;
			}
#endif
		} // default
	} // switch
	
	
	*address = ddr_dest;
}

#endif

/*Watchdog Section*/
#ifdef CONFIG_CORETEE_WATCHDOG

/*
 * AT91SAM9 watchdog runs a 12bit counter @ 256Hz,
 * use this to convert a watchdog
 * value from seconds.
 */
#define WDT_SEC2TICKS(s)	(((s) << 8) - 1)
static void setup_watchdog( void ){
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

//#define BOOT_THROUGH
void run_boot_start( void ){
	uint32_t stateval=0;
	uint32_t res=0;

	//Set the watchdog
	/*
	 * NOTE
	 * For testing the fail over boot set the timeout to a shorter value
	 * and have u-boot stop at the command prompt.
	 */
#ifdef CONFIG_CORETEE_WATCHDOG
	setup_watchdog();
#endif
	// layout configuration
#ifdef CONFIG_COMPIDX_ADDR
	res = loadLayouts(CONFIG_COMPIDX_ADDR);
#endif

#ifdef BOOT_THROUGH
	load_plex_components( 1 ); /*1 for plex A*/
#endif

	//Check power on reset
	check_startup_registers();

	stateval = (read_boot_state_values() & 0xFF);
	printf("Starting boot with state: 0x%02x\n\n", stateval);

	//Go to start of state decisions.
	boot_state_start(stateval);

	//Shouldn't reach here...
	printf("End of [%s]\n", __func__);
	while(1){
		static int count=0;
		udelay(10000);
		printf(".");
		if(count % 30 == 0)
			printf("\n");
		count++;
	};
}
