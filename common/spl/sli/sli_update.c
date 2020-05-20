/*================================================
Copyright © 2016-2019 Sequitur Labs Inc. All rights reserved.

The information and software contained in this package is proprietary property of
Sequitur Labs Incorporated. Any reproduction, use or disclosure, in whole
or in part, of this software, including any attempt to obtain a
human-readable version of this software, without the express, prior
written consent of Sequitur Labs Inc. is forbidden.
================================================*/

#include <common.h>
#include <inttypes.h>
#include <command.h>
#include <memalign.h>
#include <asm/io.h>

#include <sm_func.h>

#include <sli/sli_io.h>
#include <sli/sli_params.h>
#include <sli/sli_manifest.h>
#include <sli/sli_component.h>
#include <sli/sli_bootstates.h>
#include <sli/sli_control.h>

#define SLI_RUN_UPDATE
#ifdef SLI_RUN_UPDATE

#define RUN_ECC_VERIFY

#include <sli/asn1/asn1.h>

#include <sli/sli_update.h>

#define SLI_BOOT_UPDATE_ADDR 0x00 /*Address in NVM*/
#define SLI_BOOT_COMPONENT_STR "boot"
#define SLI_SPL_COMPONENT_STR "spl"
#define VECTOR_SIX_OFFSET 0x14
#define AES_CMAC_SIZE 16
#define SLI_PAD_ALIGN 16

#define P(val) (void*)(val)

extern void outputData( uint8_t *data, uint32_t len);

//#define USE_UPDATE_MMC
#ifdef USE_UPDATE_MMC
static struct mmc * update_mmc=NULL;
#endif

static int _device=SLIDEV_DEFAULT;

/*
 * Have to assume ECC256 for keys and signatures.
 */
#define ECC_KEYVAL_SIZE 32
static uint8_t* _seqoem_X=0;
static uint8_t* _seqoem_Y=0;

uint32_t parseECCKeyNode( dernode *key ){
	//ECC public key
	//Key should be
	//Sequence
	//	Sequence
	//	  ecPublicKey OID
	//	  ecCurveID
	//	BitString
	uint32_t res = -1;
	dernode* ecpoint=asn1_getChild(key,1);

	if (ecpoint)
	{
		if (ecpoint->tag==3)
		{
			uint8_t* pointbuffer=(uint8_t*)ecpoint->content;
			// we only handle regular packing, not compressed or hybrid
			if (pointbuffer[1]==0x04)
			{
				_seqoem_X=malloc(ECC_KEYVAL_SIZE);
				_seqoem_Y=malloc(ECC_KEYVAL_SIZE);
				memcpy(_seqoem_X,&pointbuffer[2],ECC_KEYVAL_SIZE);
				memcpy(_seqoem_Y,&pointbuffer[2+ECC_KEYVAL_SIZE],ECC_KEYVAL_SIZE);
				res = 0;
			} else {
				//printf("ECC Point is not correctly formatted\n");
				res = -1;
			}
		} else {
			//printf("Failed to parse DER point TAG for OEM internal\n");
			res = -1;
		}
	} else {
		//printf("Failed to parse ECC Key for attributes\n");
		res = -1;
	}
	return res;
}

#ifdef RUN_ECC_VERIFY
static slip_t *load_cert_slip( void ){
	slip_t *slip = getComponentManifest();
	slip_t *cert_slip = NULL;
	int res=0;
	if(!slip){
		return NULL;
	}
	uint32_t cert_nvm = sli_entry_uint32_t( slip, "p13n", "certs_src" );
	uint32_t ddr = sli_entry_uint32_t( slip, "p13n", "certs_dst" );//+0x20000000;
	uint32_t plain = ddr + 0x10000; /*64KB, slip size*/

	loadComponentBuffer(cert_nvm, (void*)ddr);

	//Decrypt
	res = sli_decrypt(ddr, plain);
	if(res){
		printf("Failed to debug certificate slip\n");
		return NULL;
	}

	cert_slip = sli_loadSlip((void*)plain);
	printf("Certificate slip: %p\n", cert_slip);

	return cert_slip;
}

int get_oem_public_key(uint8_t *oempk, size_t pksize){
	int res=0;
	int index=6;
	dernode *parent=NULL, *cert=NULL, *version=NULL;
	slip_t *cert_slip = load_cert_slip();
	slip_key_t *key=NULL;

	if(!cert_slip){
		printf("Unable to load certificate slip\n");
		return -1;
	}

	key=sli_findParam(cert_slip,"oem","oem.root.cert");

	if(!key || key->size == 0){
		printf("Failed to load OEM CERT. Unable to verify update.\n");
		res = -1;
		goto done;
	}

	//printf("Root Cert\n");
	//outputData(key->value, key->size);

	res = asn1_parseDER(&parent, key->value, key->size);
	if(res){
		//printf("Failed to parse the root cert\n");
		res = -1;
		goto done;
	}

	cert = asn1_getChild(parent, 0);
	version = asn1_getChild(cert, 0);

	if(version->tag == 0x0 && version->cls == 2 && version->composition == 1){
		index = 6;
	} else  {
		index = 5;
	}

	res = parseECCKeyNode(asn1_getChild(cert, index));
	if(res){
		//printf("Failed to parse OEM cert for public key\n");
		goto done;
	}

	if(pksize < (ECC_KEYVAL_SIZE * 2)){
		//printf("Need a larger buffer for OEM PK\n");
		goto done;
	}

	memcpy(oempk, _seqoem_X, ECC_KEYVAL_SIZE);
	memcpy(oempk+ECC_KEYVAL_SIZE, _seqoem_Y, ECC_KEYVAL_SIZE);

	free(_seqoem_X); _seqoem_X = NULL;
	free(_seqoem_Y); _seqoem_Y = NULL;

done:
	if(key){
		free(key);
	}

	if(cert_slip){
		free(cert_slip);
	}

	if(parent){
		asn1_freeTree(parent, AP_FREENODEONLY);
	}
	return res;
}

#define EC_POINT_SIZE 32
static uint32_t extract_ec_signature(uint8_t* sigbuffer,size_t sigbuffersize,dernode* signode)
{
	uint32_t res=-1;
	dernode *r_node=NULL, *s_node=NULL;
	if(!sigbuffer || !signode ||  asn1_getChildCount(signode) != 2){
		printf("Failed to get ECC Signature\n");
		return res;
	}

	// ec signature = sequence with two ints
	r_node=asn1_getChild(signode,0);
	s_node=asn1_getChild(signode,1);

	if (r_node && s_node)
	{
		uint8_t* r_int=r_node->content;
		size_t r_intsize=r_node->length;

		uint8_t* s_int=s_node->content;
		size_t s_intsize=s_node->length;

		if (r_intsize > EC_POINT_SIZE && r_int[0]==0x0)
		{
			r_int+=1;
			r_intsize-=1;
		}

		if (s_intsize > EC_POINT_SIZE && s_int[0]==0x0)
		{
			s_int+=1;
			s_intsize-=1;
		}

		memset(sigbuffer, 0, sigbuffersize);
		memcpy(sigbuffer,r_int,r_intsize);
		memcpy(sigbuffer+EC_POINT_SIZE,s_int,s_intsize);
		res=0;
	}
	else
		res=-1;

	return res;
}


int verify_update(dernode *signode, dernode *plnode){
	int res=0;
	uint8_t *oempk=NULL, *sigbuff=NULL;
	size_t siglength = EC_POINT_SIZE*2;
	size_t pksize = EC_POINT_SIZE*2;

	oempk = malloc(pksize);
	sigbuff = malloc(siglength);
	if(!oempk || !sigbuff){
		printf("Memory allocation error\n");
		return -1;
	}

	memset(oempk, 0, pksize);
	memset(sigbuff, 0, siglength);

	res = get_oem_public_key(oempk, pksize);
	if(res){
		printf("Failed to extract public key");
		goto done;
	}

	//printf("Public Key\n");
	//outputData(oempk, pksize);

	//Need to hash the payload.
	//Check alignment because we don't have a lot of 'malloc' space to use.
	memcpy((void*)CONFIG_UPDATE_CONTENT_ADDR, plnode->content, plnode->length);

	if((res = extract_ec_signature(sigbuff, siglength, signode)) != 0){
		printf("Failed to extract EC signature from node\n");
		goto done;
	}

	//printf("Update package signature for debugging!!!!\n");
	//outputData(sigbuff, siglength);

	res = (int)sli_verify_signature(CONFIG_UPDATE_CONTENT_ADDR, plnode->length, (uint32_t)sigbuff, siglength, (uint32_t)oempk, pksize, 0);

done:
	if(oempk) free(oempk);
	if(sigbuff) free(sigbuff);
	return res;
}
#endif /*RUN_ECC_VERIFY*/

/*After provisioning this header sits in front of the blobs*/
typedef struct blobheader
{
	uint32_t totalsize;
	uint32_t payloadsize;
} blobheader_t;

#define USE_BOOTSTATE_FOR_SPL
static int get_updated_flags( uint32_t flag ){
#ifdef USE_BOOTSTATE_FOR_SPL
	uint32_t state = read_boot_state_values();
	return CHECK_STATE(state, flag);
#else
	print("Alternative update flag not implemented.\n");
#endif
}

static void set_updated_flags( uint32_t flag ){
#ifdef USE_BOOTSTATE_FOR_SPL
	uint32_t state = read_boot_state_values();
	SET_STATE(state, flag);
	update_boot_state(state);
#else
	print("Alternative update flag not implemented.\n");
#endif
}

static void clear_updated_flags( void ){
#ifdef USE_BOOTSTATE_FOR_SPL

	uint32_t state = read_boot_state_values();
	CLEAR_STATE(state, (BS_SPL_UPDATING | BS_BOOT_UPDATING));
	printf("Clearing update SPL flag\n");
	update_boot_state(state);

#else
	print("Alternative update flag not implemented.\n");
#endif
}

uintptr_t handle_update_encryption(uintptr_t updateoffset, uint32_t size, int flag){
	uintptr_t componentaddr = CONFIG_UPDATE_COMPONENT_ADDR;
	uint8_t *buffer = (uint8_t*)componentaddr;
	uint32_t res=0;
	sli_compsize_t *compsize=NULL;
	sli_compheader_t *compheader=NULL;

	//copy component from update package.
	memmove(buffer, (void*)updateoffset, size);
	
	compsize = (sli_compsize_t*)buffer;
	compheader = (sli_compheader_t*)(buffer + sizeof(sli_compsize_t));
	if(compsize->magic != SLICOMP_MAGIC){
		printf("IC\n");
		return 0;
	}

	if( flag == BS_BOOT_UPDATING ){
		//Choose to re-encrypt (secure boot) or not (dev).
		uint32_t vecsize=0;
		uint32_t flags = (compheader->encryption == SLIENC_NONE) ? 0 : SLI_FLAG_ENCRYPT_WITH_CIP;
		uint8_t *plain = malloc(size);

		if(!plain){
			printf("Out of memory!\n");
			return 0;
		}

		//Pass boot.sle to bootservices to decrypt into 'plain'.
		res = sli_decrypt((uint32_t)componentaddr, (uint32_t)plain);

		//Pad vector size to 16. add 16.
		memmove(&vecsize,plain+VECTOR_SIX_OFFSET,4);
		vecsize += (SLI_PAD_ALIGN-(vecsize%SLI_PAD_ALIGN));
		vecsize += AES_CMAC_SIZE;
		memcpy(plain+VECTOR_SIX_OFFSET, &vecsize, 4);

		//Copy back to the buffer to reencrypt
		memcpy(buffer, (void*)plain, size);
		res = sli_prov((uint32_t)buffer, size, flags);

		free(plain);
	}
	else if(compheader->encryption == SLIENC_NONE) {
		// Nothing to do. 'buffer' is componentaddr;
		printf("Plain - Nothing to be done.\n");
	} else if(compheader->encryption == SLIENC_BOOTSERVICES_AES || compheader->encryption == SLIENC_LICENCE) {
		//Decrypt and re-encrypt
		printf("Diversifying...\n");
		res = sli_renew_component((uint32_t)buffer, size);
		if(res){
			printf("Renew failed!\n");
			res=-1;
			goto done;
		}
		//Diversified component now at 'buffer' (componentaddr).
	} else {
		//Not implemented...
		printf("Encryption type not supported\n");
		res=-1;
	}

done:
	printf("[%s] - Done: 0x%08x\n", __func__, res);
	if(res){
		return 0;
	}

	return componentaddr;
}

int encap_and_save_manifest( slip_t *slip ){
	int bres=-1;
	int slipsize=0;

	if (slip) {
		if(loadComponentBuffer(CONFIG_COMPIDX_ADDR, (void*)CONFIG_UPDATE_COMPONENT_ADDR) != 0){
			uint8_t* parambuffer=NULL;
			sli_compheader_t *compheader = (sli_compheader_t*)(CONFIG_UPDATE_COMPONENT_ADDR + sizeof(sli_compsize_t));
			parambuffer=sli_binaryParams(slip,&slipsize);
			if(parambuffer){
				bres = save_component( parambuffer, slipsize, slip->nvm, compheader->encryption, compheader->keyselect);
				free(parambuffer);
			} else {
				printf("Out of memory\n");
			}
		}
	}
	
	return bres;
}

#define NUM_COMPONENT_NAMES 4
static char* component_names[NUM_COMPONENT_NAMES]={
		"coretee",
		"uboot",
		"linux",
		"dtb"
};

#define NUM_KEY_NAMES 3
static char *component_key_names[NUM_KEY_NAMES]={
		"_dst",
		"_jump",
		"_version"
};

static char *key_names[NUM_KEY_NAMES]={
		"dest",
		"jump",
		"version"
};

//0 means the same, 1 means different.
int is_key_different( slip_key_t *oldkey, slip_key_t *newkey){
	if(!newkey || !oldkey)
		return 0; //Can't compare, assume the same
	if(newkey->size != oldkey->size){
		return 1;
	}
	if(newkey->type != oldkey->type) {
		return 1;
	}

	if(newkey->type == TYPE_STRING){
		return strncmp(newkey->value, oldkey->value, newkey->size); /*Sizes are the same*/
	} else if( newkey->type == TYPE_BINARY ){
		return 1; //Assume different??
	} else if( newkey->type == TYPE_UINT32 ){
		uint32_t ok, nk;
		memcpy(&ok, oldkey->value, sizeof(uint32_t));
		memcpy(&nk, newkey->value, sizeof(uint32_t));
		return (nk!=ok);
	}

	return 0; /*Made it where we can't compare. Assume the same, skip...*/
}

void update_keys( slip_t *layout, uint8_t plexid, slip_t *update, const char* component ){
	int i=0;
	char keystr[SLI_PARAM_NAME_SIZE];
	char plexstr[16];
	slip_key_t *oldkey=NULL;
	slip_key_t *newkey=NULL;

	memset(plexstr, 0, 16);
	memcpy(plexstr, ((plexid == PLEX_A_ID) ? PLEX_ID_A_STR : PLEX_ID_B_STR), strlen(PLEX_ID_A_STR));


	for(i=0; i<NUM_KEY_NAMES; i++){
		memset(keystr, 0, SLI_PARAM_NAME_SIZE);
		memcpy(keystr, component, strlen(component));
		memcpy(keystr+strlen(component), component_key_names[i], strlen(component_key_names[i]));
		oldkey = sli_findParam(layout, plexstr, keystr);
		newkey = sli_findParam(update, component, key_names[i]);

		if( is_key_different( oldkey, newkey ) ){
			//Need to replace key with allocated value or else the key just points to 'raw' in the SLIP
			//printf("Updating[%s] value: %s\n", component, key_names[i]);
			slip_key_t *key = sli_newParam(plexstr, keystr, newkey->type);
			key->value = MALLOC(newkey->size);
			key->size = newkey->size;
			memcpy(key->value, newkey->value, newkey->size);

			//Delete the old key memory and it's place in the SLIP
			sli_deleteParamKey(layout, oldkey);

			//This will update the value in the SLIP and will be saved back to NVM.
			sli_addParam(layout, key);
		}
	}
}


int update_component( slip_t *layout, uint8_t plexid, slip_t *update, uint32_t uaddr, const char* component ){
	int res=0, flag=0;
	uint32_t offset;
	uint32_t size=0;
	uintptr_t nvmdest=0;
	uintptr_t ddraddr=0;
	uintptr_t compaddr=uaddr;

	//Get destination in MMC from plex manifest
	char key[SLI_PARAM_NAME_SIZE];
	memset(key, 0, SLI_PARAM_NAME_SIZE);
	memcpy(key, component, strlen(component));
	memcpy(key+strlen(component), "_src", 4);

	if(strcmp(component, SLI_SPL_COMPONENT_STR)==0){
		flag = BS_SPL_UPDATING;
	} else if (strcmp(component, SLI_BOOT_COMPONENT_STR)==0){
		flag = BS_BOOT_UPDATING;
	} else {
		flag = 0;
	}

	size = sli_entry_uint32_t(update, component, "size");
	if(size==0) {
		//printf("Unable to find component[%s] in update manifest\n", component);
		return 0; /*No component info found*/
	}

	offset = sli_entry_uint32_t(update, component, "update_addr");

	/*Address of component within update payload*/
	compaddr += offset;

	printf("New component[%s] at update offset 0x%08x, size: 0x%x blocks.\n", component, offset, size);

	//Verify this is the correct component.
	//Compare against update package input files.
	//outputData((uint8_t*)compaddr, 32);

	//Deblob and reblob the component.
	ddraddr = handle_update_encryption(compaddr, size, flag);
	if(ddraddr == 0){
		printf("Failed blob operation in update.");
		return -1;
	}

	if(flag != 0){
		nvmdest = (flag == BS_SPL_UPDATING) ? sli_entry_uint32_t(layout, "spl", key) : SLI_BOOT_UPDATE_ADDR;
		printf("Updating - Copying [%d bytes] to NVM address: %" PRIxPTR "\n", size, nvmdest);
		sli_nvm_write(_device, nvmdest, size, (uint8_t*)ddraddr);
		set_updated_flags(flag);
		printf("Component is updated. Resetting...\n");
		sli_reset_board();
		while(1){ udelay(1000); }
	} else {

		nvmdest = sli_entry_uint32_t(layout, (plexid == PLEX_A_ID) ? PLEX_ID_A_STR : PLEX_ID_B_STR, key);
		if(!nvmdest){
			printf("Key[%s] not found\n", key);
			return -1;
		}

		//Copy blob back to NVM.
		printf("Copying component to NVM from: 0x%08lx to %" PRIxPTR " numbytes: %d\n", ddraddr, nvmdest, size);
		res = sli_nvm_write(_device, nvmdest, size, (void*)ddraddr);
		if(res){
			printf("FAILED TO WRITE TO NVM!!!\n");
		} else {
			//Update the keys
			update_keys(layout, plexid, update, component);
	 	}
	}

	return res;
}

int update_components( slip_t *update, uintptr_t componentaddr, size_t length, slip_t *layout, uint8_t plexid ){
	int res=0;
	int i=0;

	printf("Update manifest found. BOOT[%d] SPL[%d].\n",
			get_updated_flags(BS_BOOT_UPDATING), get_updated_flags(BS_SPL_UPDATING));


	//First check to see if the BOOT binary needs to be updated.
	if( sli_findParam( update, SLI_BOOT_COMPONENT_STR, "size") && !get_updated_flags(BS_BOOT_UPDATING)){
		update_component(layout, plexid, update, componentaddr, SLI_BOOT_COMPONENT_STR);
	} else if( sli_findParam( update, SLI_SPL_COMPONENT_STR, "size") && !get_updated_flags(BS_SPL_UPDATING)){
		//Then check to see if SPL needs to be updated.
		update_component(layout, plexid, update, componentaddr, SLI_SPL_COMPONENT_STR);
	} else {
		clear_updated_flags();
		printf("Continuing...\n");
	}

	for(i=0; i<NUM_COMPONENT_NAMES && res==0; i++){
		res = update_component(layout, plexid, update, componentaddr, component_names[i]);
	}

	//Save plex manifest back to MMC
	if(!res){
		printf("Saving manifest back to NVM: 0x%08lx\n", layout->nvm);
		res = encap_and_save_manifest(layout);
	} else {
		printf("Failed to update components. Exiting Update\n");
	}

	return res;
}

slip_t * get_update_manifest( uintptr_t ddr, size_t length ){
	slip_t *slip = NULL;
	slip = sli_loadSlip( (void*)ddr );
	return slip;
}

/*
void output_key( slip_t *plex, const char *component, const char *keyname ){
	slip_key_t *key = sli_findParam(plex,component,keyname);
	if(!key){
		printf("Failed to load key[%s] for component[%s]\n", keyname, component);
	}

	if(key->type < 8){
		uint32_t res=(uint32_t)sli_value_uint32_t(key);
		printf("[%s] : 0x%08x\n", keyname, res);
	} else if (key->type == 8){
		printf("[%s] : %s\n", keyname, (char*)key->value);
	}
}

void output_component( slip_t *plex, const char *component ){
	int i=0;

	printf("COMPONENT: %s\n", component);
	for(i=0; i<NUM_KEY_NAMES; i++){
		output_key(plex, component, key_names[i]);
	}
}

void test_manifest( int plexid ){
	uintptr_t addr = plexid == PLEX_A_ID ? 0x3C0000 : 0x3D0000;
	slip_t * plex = NULL;
	int i =0;

	manage_slip2(0, &addr);

	plex = sli_loadSlipMem(addr);

	if(!plex){
		printf("Failed to load plex after update\n");
	}

	printf("PLEX FOR ID: %d\n", plexid);
	for(i=0; i<NUM_COMPONENT_NAMES; i++){
		output_component( plex, component_names[i] );
		printf("\n");
	}
}*/

int verify_and_run_update( uintptr_t ddr_uaddr, size_t length, slip_t *layout, uint8_t plexid ){
	int res=0;
	dernode *parent=0;
	dernode *algnode, *signode, *plnode;
	slip_t *updateslip;

	res = asn1_parseDER(&parent, (uint8_t*)ddr_uaddr, length);
	if(res){
		printf("Failed to parse DER update package\n");
		return -1;
	}

	//Update DER consists of
	//parent_node
	//  SHA algorithm node
	//  Signature node
	//	Payload node
	algnode = asn1_getChild(parent, 0);
	signode = asn1_getChild(parent, 1);
	plnode = asn1_getChild(parent, 2);

	if(!algnode || !signode || !plnode ){
		printf("Failed to get child components of update payload.\n\t[%p] [%p] [%p]\n", algnode, signode, plnode);
		asn1_freeTree(parent, AP_FREENODEONLY);
		return -1;
	}

	//Verify against oem public key
#ifdef RUN_ECC_VERIFY
	res = verify_update(signode, plnode);
#else
	res = 0;
#endif

	if(res){
		printf("Verify failed!!!\n");
		return res;
	}

	//Verified so lets look at the update manifest.
	//Payload consists of:
#define UPDATE_MANIFEST_SIZE 4096
	//	Update Manifest - 4096 Bytes
	//	Update Components
	if((updateslip = get_update_manifest((uintptr_t)plnode->content, UPDATE_MANIFEST_SIZE)) == NULL){
		printf("Failed to parse update manifest from DDR\n");
		return -1;
	}

	printf("Updating components. Manifest: 0x%08x   plnode->content: %p\n", UPDATE_MANIFEST_SIZE, plnode->content);
	if((res = update_components( updateslip, (uintptr_t)(plnode->content)+UPDATE_MANIFEST_SIZE, plnode->length-UPDATE_MANIFEST_SIZE, layout, plexid )) != 0){
		printf("Failed to update components\n");
		goto done;
	}

done:
	if(updateslip)
		sli_freeParams(updateslip);
	asn1_freeTree(parent, AP_FREENODEONLY);
	printf("Done update\n");
	return res;
}

int copy_update_to_ddr( uintptr_t *mmc_uaddr, size_t *plsize ){
	dernode *parent=0;
	uint32_t offset = (uint32_t)(*mmc_uaddr);
	size_t length;
	uint8_t * update=NULL;
	int res=0;

#ifdef USE_UPDATE_MMC
	if(!update_mmc){
		printf("Failed to create the MMC device object for UPDATE\n");
	}

	//Just get the header. 512 is the MMC block size and the minimum size to copy
	printf("Copying update from block offset 0x%08lx   to   DDR: 0x%08x\n", addr, CONFIG_UPDATE_PAYLOAD_ADDR);
	sli_mmc_read_dev( update_mmc, offset, SLI_MMC_BLOCK_SIZE, (void*)CONFIG_UPDATE_PAYLOAD_ADDR);

	update = (uint8_t*)CONFIG_UPDATE_PAYLOAD_ADDR;

	parent = asn1_parseSingleNode(update, SLI_MMC_BLOCK_SIZE);
	if(!parent){
		printf("Failed to get parse update package!\n");
		return -1;
	}

	length = parent->rawlength;
	*plsize = length;

	printf("Total update size: %d  %d\n", parent->rawlength, parent->length);

	//Copy the whole update payload to DDR
	sli_mmc_read_dev( update_mmc, offset, length, (void*)CONFIG_UPDATE_PAYLOAD_ADDR );
#else
	//Just get the header. 512 is the MMC block size and the minimum size to copy
	printf("Copying update from block offset[%d] 0x%08x   to   DDR: 0x%08x\n", offset, offset, CONFIG_UPDATE_PAYLOAD_ADDR);
	sli_nvm_read(_device, offset, 512, (void*)CONFIG_UPDATE_PAYLOAD_ADDR);

	update = (uint8_t*)CONFIG_UPDATE_PAYLOAD_ADDR;

	printf("Update payload\n");
	outputData(update, 32);

	parent = asn1_parseSingleNode(update, 512);
	if(!parent){
		printf("Failed to get parse update package!\n");
		return -1;
	}

	length = parent->rawlength;
	*plsize = length;

	printf("Total update size: %zu  %zu\n", parent->rawlength, parent->length);

	//Copy the whole update payload to DDR
	sli_nvm_read(_device, offset, length, (void*)CONFIG_UPDATE_PAYLOAD_ADDR );

#endif
	*mmc_uaddr = CONFIG_UPDATE_PAYLOAD_ADDR;
	return res;
}

int run_update( unsigned int plexid ){
	int res=0;
	uintptr_t uaddr=0;
#ifdef USE_UPDATE_MMC
	uint32_t update_part;
	uint32_t update_access;
	uint32_t update_ack;
#endif

	size_t plsize=0;
	slip_t *component=NULL;

	//Get the update manifest address from main component manifest.
	component = getComponentManifest();
	if(!component){
		printf("No component manifest found during update\n");
		return -1;
	}

	/*
	 * Read where the update payload is stored from the compidx manifest.
	 */
	uaddr = sli_entry_uint32_t(component, "p13n", "update");
#ifdef USE_UPDATE_MMC
	update_part = get_keyval_uint32(component, "p13n", "update_part");
	update_access = get_keyval_uint32(component, "p13n", "update_access");
	update_ack = get_keyval_uint32(component, "p13n", "update_ack");

	update_mmc = sli_get_mmc( update_ack, update_part, update_access );
	if(!update_mmc){
		printf("Failed to get the MMC device for the update payload\n");
		return -1;
	}
#endif

	printf("Update at addr: 0x%08lx. Copying to DDR\n", uaddr);
	if((res = copy_update_to_ddr( &uaddr, &plsize )) != 0){
		printf("Failed to copy the update to DDR\n");
		goto done;
	}

	if((res = verify_and_run_update( uaddr, plsize, component, plexid )) != 0){
		printf("Failed to run update\n");
		goto done;
	}

	//test_manifest( plexid );
	clear_updated_flags();

	//Successfully ran update
	//uaddr is set to the DDR location of the update payload in 'copy_update_to_ddr'.
	memset((void*)uaddr, 0, plsize);
done:
	return res;
}

#else
int run_update(unsigned int plexid){
	printf("Update is not implemented yet. Returning success\n");
	return 0;
}
#endif
