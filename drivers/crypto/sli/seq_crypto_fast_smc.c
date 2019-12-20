#include <common.h>
#include <malloc.h>
#include <sli_crypto.h>
#include "seq_crypto_fast_smc.h"

/*
 * N.B. We don't allocate the op buffer anymore, to keep it inside the
 * mapped region of memory.  So, we don't need to free it either.
 */

static void* _calloc(size_t size) {
	//return calloc(1, size);
	void *a = sliGetOpBuf();
	if (a) memset(a, 0, size);
	return a;
}

seq_smc_op_t* newOpHash(unsigned int alg) {
	seq_smc_op_t* op;
	size_t opLen = sizeof(seq_smc_op_t);

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_HASH;
		op->ctrl.bits.ALG = alg;
	}

	return op;
}

size_t opHashLen(seq_smc_op_t *op) {
	return sizeof(seq_smc_op_t);
}

void freeOpHash(seq_smc_op_t *op) {
	size_t opLen = sizeof(seq_smc_op_t);
	memset(op, 0, opLen);
	//free(op);
}

seq_smc_op_mac_t* newOpMac(unsigned int alg,
                           const uint8_t *key, size_t keyLen) {
	seq_smc_op_mac_t* op;
	size_t opLen = sizeof(seq_smc_op_mac_t) + keyLen;

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_MAC;
		op->ctrl.bits.ALG = alg;
		op->ctrl.bits.KEY_TYPE = SEQ_SMC_KEY_TYPE_HMAC;
		op->keyPos = 0;
		op->keyLen = keyLen;
		memcpy(op->arr+op->keyPos, key, keyLen);
	}

	return op;
}

size_t opMacLen(seq_smc_op_mac_t *op) {
	return sizeof(seq_smc_op_mac_t) + op->keyLen;
}

void freeOpMac(seq_smc_op_mac_t *op) {
	memset(op, 0, opMacLen(op));
	//free(op);
}

seq_smc_op_cipher_t* newOpCipher(unsigned int alg,
                                 const uint8_t *key, size_t keyLen,
                                 const uint8_t *iv, size_t ivLen,
                                 int encrypt) {
	seq_smc_op_cipher_t* op;
	size_t opLen = sizeof(seq_smc_op_cipher_t) + keyLen + ivLen;

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_CIPHER;
		op->ctrl.bits.ALG = alg;
		op->ctrl.bits.KEY_TYPE = SEQ_SMC_KEY_TYPE_AES;
		op->ctrl.bits.ENC = (encrypt) ? 1 : 0;
		op->keyPos = 0;
		op->keyLen = keyLen;
		memcpy(op->arr+op->keyPos, key, keyLen);
		op->ivPos = op->keyPos + op->keyLen;
		if (alg == SEQ_SMC_ALG_AES_ECB)
			op->ivLen = 0;
		else {
			if (iv && ivLen) {
				op->ivLen = ivLen;
				memcpy(op->arr+op->ivPos, iv, ivLen);
			} else {	/* Automatically provide an IV of 0's */
				op->ivLen = 16;
				memset(op->arr+op->ivPos, 0, op->ivLen);
			}
		}
	}

	return op;
}

size_t opCipherLen(seq_smc_op_cipher_t *op) {
	return sizeof(seq_smc_op_cipher_t) + op->keyLen + op->ivLen;
}

void freeOpCipher(seq_smc_op_cipher_t *op) {
	memset(op, 0, opCipherLen(op));
	//free(op);
}

seq_smc_op_ae_t* newOpAe(unsigned int alg,
                         const uint8_t *key, size_t keyLen,
                         const uint8_t *nonce, size_t nonceLen,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *tag, size_t tagLen,
                         int encrypt) {
	seq_smc_op_ae_t* op;
	size_t opLen = sizeof(seq_smc_op_ae_t) + keyLen + nonceLen + aadLen + tagLen;

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_AE;
		op->ctrl.bits.ALG = alg;
		op->ctrl.bits.KEY_TYPE = SEQ_SMC_KEY_TYPE_AES;
		op->ctrl.bits.ENC = (encrypt) ? 1 : 0;
		op->keyPos = 0;
		op->keyLen = keyLen;
		memcpy(op->arr+op->keyPos, key, keyLen);
		op->noncePos = op->keyPos + op->keyLen;
		op->nonceLen = nonceLen;
		memcpy(op->arr+op->noncePos, nonce, nonceLen);
		op->aadPos = op->noncePos + op->nonceLen;
		op->aadLen = aadLen;
		memcpy(op->arr+op->aadPos, aad, aadLen);
		op->tagPos = op->aadPos + op->aadLen;
		op->tagLen = tagLen;
		memcpy(op->arr+op->tagPos, tag, tagLen);
	}

	return op;
}

size_t opAeLen(seq_smc_op_ae_t *op) {
	return sizeof(seq_smc_op_ae_t) + op->keyLen + op->nonceLen +
               op->aadLen + op->tagLen;
}

void copyTagOpAe(seq_smc_op_ae_t *op, uint8_t *tag) {
	memcpy(tag, op->arr+op->tagPos, op->tagLen);
}

void freeOpAe(seq_smc_op_ae_t *op) {
	memset(op, 0, opAeLen(op));
	//free(op);
}

seq_smc_op_blob_t* newOpBlob(const uint8_t *keyMod, size_t keyModLen,
                             int encrypt) {
	seq_smc_op_blob_t* op;
	size_t opLen = sizeof(seq_smc_op_blob_t) + keyModLen;

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_BLOB;
		op->ctrl.bits.ALG = SEQ_SMC_ALG_BLOB;
		op->ctrl.bits.ENC = (encrypt) ? 1 : 0;
		op->keyModPos = 0;
		op->keyModLen = keyModLen;
		memcpy(op->arr+op->keyModPos, keyMod, keyModLen);
	}

	return op;
}

size_t opBlobLen(seq_smc_op_blob_t *op) {
	return sizeof(seq_smc_op_blob_t) + op->keyModLen;
}

void freeOpBlob(seq_smc_op_blob_t *op) {
	memset(op, 0, opBlobLen(op));
	//free(op);
}

seq_smc_op_t* newOpRng() {
	seq_smc_op_t* op;
	size_t opLen = sizeof(seq_smc_op_t);

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_RNG;
		op->ctrl.bits.ALG = SEQ_SMC_ALG_RNG;
	}

	return op;
}

size_t opRngLen(seq_smc_op_t *op) {
	return sizeof(seq_smc_op_t);
}

void freeOpRng(seq_smc_op_t *op) {
	memset(op, 0, opRngLen(op));
	//free(op);
}

seq_smc_op_t* newOpMasterDev() {
	seq_smc_op_t* op;
	size_t opLen = sizeof(seq_smc_op_t);

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_MASTER_DEV;
	}

	return op;
}

size_t opMasterDevLen(seq_smc_op_t *op) {
	return sizeof(seq_smc_op_t);
}

void freeOpMasterDev(seq_smc_op_t *op) {
	memset(op, 0, opMasterDevLen(op));
	//free(op);
}

seq_smc_op_t* newOpMasterProv() {
	seq_smc_op_t* op;
	size_t opLen = sizeof(seq_smc_op_t);

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_MASTER_PROV;
	}

	return op;
}

size_t opMasterProvLen(seq_smc_op_t *op) {
	return sizeof(seq_smc_op_t);
}

void freeOpMasterProv(seq_smc_op_t *op) {
	memset(op, 0, opMasterProvLen(op));
	//free(op);
}

seq_smc_op_t* newOpGenProv() {
	seq_smc_op_t* op;
	size_t opLen = sizeof(seq_smc_op_t);

	if ((op = _calloc(opLen))) {
		op->ctrl.bits.FUNC = SEQ_SMC_FUNC_GEN_PROV;
	}

	return op;
}

size_t opGenProvLen(seq_smc_op_t *op) {
	return sizeof(seq_smc_op_t);
}

void freeOpGenProv(seq_smc_op_t *op) {
	memset(op, 0, opGenProvLen(op));
	//free(op);
}
