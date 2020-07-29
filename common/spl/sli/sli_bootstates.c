#include <common.h>
#include <memalign.h>
#include <asm/io.h>

#include <sm_func.h>
#include <sli/sli_io.h>
#include <sli/sli_params.h>
#include <sli/sli_update.h>
#include <sli/sli_component.h>
#include <sli/sli_manifest.h>
#include <sli/sli_coretee.h>
#include <sli/sli_control.h>

#ifdef CONFIG_SPL_SLIENCRYPTEDBOOT
#include <sli_keys.h>
int blob_decap(u8*,u8*,u8*,u32);
#endif

#include <sli/sli_bootstates.h>

static int _device=SLIDEV_DEFAULT;


static char * byteToHex( uint8_t byte ){
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

//-----------------------------------------------
// BOOT SEQUENCE
static void jump_to_uboot(uint32_t entry)
{
	typedef void __noreturn (*uboot_entry_t)(void);
	uboot_entry_t ue=(uboot_entry_t)entry;

	printf("Invoking U-Boot: 0x%08x\n",entry);

	ue();
}

static void load_coretee( uint8_t plexid ){
	size_t coretee_size=0;
	uint32_t coretee_jump=component_setup(plexid == PLEX_A_ID ? PLEX_ID_A_STR : PLEX_ID_B_STR , "coretee","CoreTEE",&coretee_size);
	//Error checking done in 'component_setup'

	if (coretee_jump && coretee_size)
		coretee(coretee_jump,coretee_size);
	//Should return non-secure
}

static void load_coretee_slips( void ){
	slip_t *slip = getComponentManifest();
	uint32_t res=0;
	if(!slip){
		return;
	}
	uint32_t cert_nvm = sli_entry_uint32_t( slip, "p13n", "certs_src" );
	uint32_t ddr = sli_entry_uint32_t( slip, "p13n", "certs_dst" );//+0x20000000;

	printf("Copying layout and cert SLIPs to [0x%08x]\n", ddr);

	/*
	 * Must send component layout first
	 */
#ifdef CONFIG_COMPIDX_ADDR
	//ddr location can be reused.
	loadComponentBuffer(CONFIG_COMPIDX_ADDR, (void*)ddr);
	res = handle_coretee_slips( SLIP_ID_LAYOUT, ddr, SLI_SLIP_MAX_SIZE );
#endif

	loadComponentBuffer( cert_nvm, (void*)ddr );
	res = handle_coretee_slips( SLIP_ID_CERTIFICATES, ddr, SLI_SLIP_MAX_SIZE );
	if(res == CORETEE_SAVE_SLIP_TO_NVM){
		printf("Cert slip has been changed by CoreTEE. Save back to NVM\n");
		sli_compsize_t *cs = (sli_compsize_t*)ddr;
		sli_nvm_write(SLIDEV_DEFAULT, cert_nvm, (sizeof(sli_compsize_t)+cs->headersize+cs->payloadsize), (void*)ddr);
	}
}

static void load_plex_components( uint8_t plexid ){
	char* idstr=(plexid==PLEX_A_ID) ? PLEX_ID_A_STR : PLEX_ID_B_STR;
	
	// u-boot
	uint32_t uboot_jump=component_setup(idstr,"uboot","U-Boot",0);

	// linux
	///*
	component_setup(idstr,"linux","Linux kernel",0);
	component_setup(idstr,"dtb","Device Tree Binary",0);
	//component_setup(idstr,"initramfs","initramfs",0);
	//*/

	// Load coretee last
	load_coretee(plexid);

	//Now that CoreTEE is up, send it the slips
	load_coretee_slips();

	// finally jump to u-boot
	if (uboot_jump)
		jump_to_uboot(uboot_jump);
}

//-----------------------------------------------

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

void check_startup_registers(void){
	char buffer[64];
	unsigned int cause = sli_get_reset_cause();
	uint32_t state = 0;
	state = (read_boot_state_values() & 0xFF);

	sprintf(buffer, "Reset reason: %d\nState: 0x%02x\n", cause, state);
	puts(buffer);

	if(cause == SLI_RC_POR){
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

	CLEAR_STATE(stateval, BS_UPDATE);

#ifdef CONFIG_CORETEE_PLEX_A_ONLY
	/*
	 * Force the update plex to be Plex A
	 */
	plexid=1;
#endif

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

	CLEAR_STATE(stateval, (BS_SPL_UPDATING | BS_BOOT_UPDATING));

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
	sli_nvm_read(_device,addr,sizeof(uint32_t),&bsv);

#ifdef CONFIG_CORETEE_PLEX_A_ONLY
	/*
	 * Force the state:
	 *   - Plex A Primary
	 *   - Plex B INVALID
	 *   - Clear ACTIVATE
	 */
	SET_STATE(bsv, BS_A_PRIMARY);
	CLEAR_STATE(bsv, BS_B_VALID);
	CLEAR_STATE(bsv, BS_ACTIVATE);
#endif

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
	// removing since only one plex
	//decrement_blc();

	//Determine boot state
	check_boot_state(stateval);
}


#ifndef CONFIG_CORETEE_WATCHDOG
void at91_disable_wdt(void);
#endif

//#define BOOT_THROUGH
void run_boot_start( void ){
	uint32_t stateval=0;

	//Set the watchdog
	/*
	 * NOTE
	 * For testing the fail over boot set the timeout to a shorter value
	 * and have u-boot stop at the command prompt.
	 */
#ifdef CONFIG_CORETEE_WATCHDOG
	sli_setup_watchdog();
#else
	/* disable watchdog */
	printf("WATCHDOG IS NOT ENABLED\n");
	at91_disable_wdt();
#endif
	// layout configuration
#ifdef CONFIG_COMPIDX_ADDR
	loadLayouts(CONFIG_COMPIDX_ADDR);
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

	while (1) {};
}
