#include <common.h>
#include <memalign.h>
#include <linux/arm-smccc.h>
#include <sli_crypto.h>
#include "seq_crypto_fast_smc.h"

/* Set this to run the test suite during initialization
 * (should normally be disabled). */
#ifndef SLI_SMC_TEST
  #define SLI_SMC_TEST 0
#endif

/*
 * We allocate a region of memory for the input, output and op buffers,
 * so that it can be mapped in the TEE.  Data will be copied into and
 * out of these buffers if necessary, but it would probably be more
 * efficient if it was supplied in the buffers to the crypto calls.
 */
static uint8_t *_smc_bufs = NULL;
static uint8_t *_smc_in = NULL;
static uint8_t *_smc_out = NULL;
static uint8_t *_smc_op = NULL;
static size_t _smc_max_buf_len = 0;
static int _smc_bufs_allocated = 0;

#define SMC_CRYPTO 0x8300010e

/*
 * Hash functions
 */

static int hash(unsigned int alg, const uint8_t *in, size_t inLen,
                uint8_t *out, size_t *outLen) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if (inLen > _smc_max_buf_len)
		return SEQ_SMC_ERROR_SHORT_BUFFER;

	if (in != _smc_in)
		memcpy(_smc_in, in, inLen);

	if ((op = newOpHash(alg))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, *outLen,
		              (unsigned long)_smc_in, inLen, (unsigned long)op, opHashLen(op),
		              &res);
		*outLen = res.a3;
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, *outLen);

		freeOpHash(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliHashSha1(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {
	return hash(SEQ_SMC_ALG_HASH_SHA1, in, inLen, out, outLen);
}

int sliHashSha224(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {
	return hash(SEQ_SMC_ALG_HASH_SHA224, in, inLen, out, outLen);
}

int sliHashSha256(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {
	return hash(SEQ_SMC_ALG_HASH_SHA256, in, inLen, out, outLen);
}

int sliHashSha384(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {
	return hash(SEQ_SMC_ALG_HASH_SHA384, in, inLen, out, outLen);
}

int sliHashSha512(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {
	return hash(SEQ_SMC_ALG_HASH_SHA512, in, inLen, out, outLen);
}

/*
 * Mac functions
 */

static int hmac(unsigned int alg, const uint8_t *key, size_t keyLen,
                const uint8_t *in, size_t inLen,
                uint8_t *out, size_t *outLen) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_mac_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	if (inLen > _smc_max_buf_len)
		return SEQ_SMC_ERROR_SHORT_BUFFER;

	if (in != _smc_in)
		memcpy(_smc_in, in, inLen);

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpMac(alg, key, keyLen))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, *outLen,
		              (unsigned long)_smc_in, inLen, (unsigned long)op, opMacLen(op),
		              &res);
		*outLen = res.a3;
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, *outLen);

		freeOpMac(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliHmacSha1(const uint8_t *key, size_t keyLen,
                const uint8_t *in, size_t inLen,
                uint8_t *out, size_t *outLen) {
	return hmac(SEQ_SMC_ALG_HMAC_SHA1, key, keyLen, in, inLen, out, outLen);
}

int sliHmacSha224(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen) {
	return hmac(SEQ_SMC_ALG_HMAC_SHA224, key, keyLen, in, inLen, out, outLen);
}

int sliHmacSha256(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen) {
	return hmac(SEQ_SMC_ALG_HMAC_SHA256, key, keyLen, in, inLen, out, outLen);
}

int sliHmacSha384(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen) {
	return hmac(SEQ_SMC_ALG_HMAC_SHA384, key, keyLen, in, inLen, out, outLen);
}

int sliHmacSha512(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen) {
	return hmac(SEQ_SMC_ALG_HMAC_SHA512, key, keyLen, in, inLen, out, outLen);
}


/*
 * Cipher functions
 */

static int cipher(unsigned int alg, const uint8_t *key, size_t keyLen,
                  const uint8_t *iv, size_t ivLen,
                  const uint8_t *in, uint8_t *out,
                  size_t len, int encrypt) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_cipher_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	if (len > _smc_max_buf_len)
		return SEQ_SMC_ERROR_SHORT_BUFFER;

	if (in != _smc_in)
		memcpy(_smc_in, in, len);

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpCipher(alg, key, keyLen, iv, ivLen, encrypt))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, len,
		              (unsigned long)_smc_in, len, (unsigned long)op, opCipherLen(op),
		              &res);
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, len);

		freeOpCipher(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliAesCtrEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *iv, size_t ivLen,
                 const uint8_t *in, uint8_t *out, size_t len) {
	return cipher(SEQ_SMC_ALG_AES_CTR, key, keyLen, iv, ivLen, in, out, len, 1);
}

int sliAesCtrDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *iv, size_t ivLen,
                 const uint8_t *in, uint8_t *out, size_t len) {
	return cipher(SEQ_SMC_ALG_AES_CTR, key, keyLen, iv, ivLen, in, out, len, 0);
}

/*
 * Authenticated Encryption functions
 */

static int ae(unsigned int alg, const uint8_t *key, size_t keyLen,
              const uint8_t *nonce, size_t nonceLen,
              const uint8_t *aad, size_t aadLen,
              const uint8_t *in, uint8_t *out, size_t len,
              uint8_t *tag, size_t tagLen,
              int encrypt) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_ae_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	if (len > _smc_max_buf_len)
		return SEQ_SMC_ERROR_SHORT_BUFFER;

	if (in != _smc_in)
		memcpy(_smc_in, in, len);

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpAe(alg, key, keyLen, nonce, nonceLen, aad, aadLen,
	                  tag, tagLen, encrypt))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, len,
		              (unsigned long)_smc_in, len, (unsigned long)op, opAeLen(op),
		              &res);
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, len);

		if (encrypt)
			copyTagOpAe(op, tag);

		freeOpAe(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliAesCcmEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 uint8_t *tag, size_t tagLen) {
	return ae(SEQ_SMC_ALG_AES_CCM, key, keyLen, nonce, nonceLen, aad, aadLen,
	          in, out, len, tag, tagLen, 1);
}

int sliAesCcmDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 const uint8_t *tag, size_t tagLen) {
	return ae(SEQ_SMC_ALG_AES_CCM, key, keyLen, nonce, nonceLen, aad, aadLen,
	          in, out, len, (uint8_t*)tag, tagLen, 0);
}

int sliAesGcmEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 uint8_t *tag, size_t tagLen) {
	return ae(SEQ_SMC_ALG_AES_GCM, key, keyLen, nonce, nonceLen, aad, aadLen,
	          in, out, len, tag, tagLen, 1);
}

int sliAesGcmDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 const uint8_t *tag, size_t tagLen) {
	return ae(SEQ_SMC_ALG_AES_GCM, key, keyLen, nonce, nonceLen, aad, aadLen,
	          in, out, len, (uint8_t*)tag, tagLen, 0);
}

/*
 * Blob related functions
 */

static int blob(const uint8_t *keyMod, size_t keyModLen,
                const uint8_t *in, size_t inLen,
                uint8_t *out, size_t *outLen,
                int encrypt) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_blob_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	if (inLen > _smc_max_buf_len)
		return SEQ_SMC_ERROR_SHORT_BUFFER;

	if (in != _smc_in)
		memcpy(_smc_in, in, inLen);

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpBlob(keyMod, keyModLen, encrypt))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, *outLen,
		              (unsigned long)_smc_in, inLen, (unsigned long)op, opBlobLen(op),
		              &res);
		*outLen = res.a3;
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, *outLen);

		freeOpBlob(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliBlobEnc(const uint8_t *keyMod, size_t keyModLen,
               const uint8_t *in, size_t inLen,
               uint8_t *out, size_t *outLen) {
	return blob(keyMod, keyModLen, in, inLen, out, outLen, 1);
}

int sliBlobDec(const uint8_t *keyMod, size_t keyModLen,
               const uint8_t *in, size_t inLen,
               uint8_t *out, size_t *outLen) {
	return blob(keyMod, keyModLen, in, inLen, out, outLen, 0);
}

int sliBlobMasterDev() {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	ctrl.bits.PTR_OP = 1;

	if ((op = newOpMasterDev())) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0,
		              0, 0, (unsigned long)op, opMasterDevLen(op),
		              &res);
		ret = (int)res.a0;
		freeOpMasterDev(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliBlobMasterProv() {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	ctrl.bits.PTR_OP = 1;

	if ((op = newOpMasterProv())) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0,
		              0, 0, (unsigned long)op, opMasterProvLen(op),
		              &res);
		ret = (int)res.a0;
		freeOpMasterProv(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliBlobGenProv(const uint8_t *brn, size_t brnLen) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	if (brn != _smc_in)
		memcpy(_smc_in, brn, brnLen);

	ctrl.bits.PTR_IN = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpGenProv())) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0,
		              (unsigned long)_smc_in, brnLen, (unsigned long)op, opGenProvLen(op),
		              &res);
		ret = (int)res.a0;
		freeOpGenProv(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

int sliBlobSetPriBlobType(unsigned int type) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_priblob_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	ctrl.bits.PTR_OP = 1;

	if ((op = newOpPriBlob(type))) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0,
		              0, 0, (unsigned long)op, opPriBlobLen(op),
		              &res);
		ret = (int)res.a0;

		freeOpPriBlob(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

/*
 * RNG function
 */

int sliRng(uint8_t *out, size_t outLen) {
	int ret = SEQ_SMC_SUCCESS;
	seq_smc_op_t *op;
	SEQ_SMC_CTRL ctrl = { 0 };

	ctrl.bits.PTR_OUT = 1;
	ctrl.bits.PTR_OP = 1;

	if ((op = newOpRng())) {
		struct arm_smccc_res res;
		arm_smccc_smc(SMC_CRYPTO, ctrl.val, (unsigned long)_smc_out, outLen,
		              0, 0, (unsigned long)op, opRngLen(op),
		              &res);
		ret = (int)res.a0;

		if (out != _smc_out)
			memcpy(out, _smc_out, outLen);

		freeOpRng(op);
	} else
		ret = SEQ_SMC_ERROR_OP_INIT;

	return ret;
}

/*
 * Misc. crypto functions
 */

#define MAXOPSIZE 4096

uint8_t* sliGetInBuf(void) { return _smc_in; }
uint8_t* sliGetOutBuf(void) { return _smc_out; }
uint8_t* sliGetOpBuf(void) { return _smc_op; }

#if (SLI_SMC_TEST != 0)
static void printBuf(uint8_t *buf, size_t bufLen, char *tag) {
	int i;
	char *cout;
	uint32_t coutLen = 2*bufLen+1;
	if ((cout = malloc(coutLen))) {
		for (i = 0; i < bufLen; i++)
			snprintf(cout+2*i, 3, "%2.2x", buf[i]);
		cout[2*bufLen] = '\0';
		printf("%s =\n", tag ? tag : "");
		for (i = 0; i < (2*bufLen+49)/50; i++)
			printf("  %-.50s\n", cout+i*50);
	} else
		printf("Could not allocate memory for printing results\n");
}

static int sliTest(size_t maxBufLen) {
	int ret = SEQ_SMC_SUCCESS, i, j;
	const size_t inBufLen = 16;
	uint8_t in[inBufLen];
	const size_t outBufLen = 32;
	uint8_t out[outBufLen];
	size_t tmpLen;
	uint8_t hashOut[] = { 0x28, 0x96, 0x9c, 0xdf, 0xa7, 0x4a, 0x12, 0xc8,
	                      0x2f, 0x3b, 0xad, 0x96, 0x0b, 0x0b, 0x00, 0x0a,
	                      0xca, 0x2a, 0xc3, 0x29, 0xde, 0xea, 0x5c, 0x23,
	                      0x28, 0xeb, 0xc6, 0xf2, 0xba, 0x98, 0x02, 0xc1 };
	uint8_t macKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t macOut[] = { 0x7e, 0xbb, 0xf8, 0xa9, 0xe3, 0x37, 0xdf, 0xa2,
	                     0x6a, 0x93, 0x9c, 0x2e, 0x29, 0x2d, 0x4a, 0xa5,
	                     0x37, 0x94, 0x37, 0x2b, 0xb9, 0xf3, 0x76, 0x7b,
	                     0x00, 0x4e, 0x6d, 0x72, 0x79, 0xeb, 0xa4, 0x3d };
	uint8_t ctrIn[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	uint8_t ctrOut[] = { 0xf3, 0x46, 0x46, 0xe8, 0xc9, 0x36, 0x79, 0x27,
	                     0x94, 0x10, 0xe9, 0xa7, 0x1f, 0xd5, 0x23, 0xe3,
	                     0x45, 0x8f, 0xef, 0xfb, 0x96, 0xec, 0x52, 0x14,
	                     0x74, 0xb0, 0x02, 0xc5, 0x97, 0x5a, 0xac, 0xe8 };
	uint8_t ctrKey[] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	                     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	                     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	                     0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
	uint8_t gcmKey[32], gcmNonce[12], gcmTag[16];
	uint8_t gcmOut[] = { 0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
	                     0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18 };
	uint8_t gcmTagOut[] = { 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
	                        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19 };

	printf("SEQR Testing SMC Crypto interface:\n");

	/* Test RNG */
	printf("SEQR Testing RNG: ");
	memset(out, 0xdb, outBufLen);
	if ((ret = sliRng(out, outBufLen))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		printf("Pass\n");
		printBuf(out, outBufLen, "RNG");
	}

	/* Test hash */
	printf("SEQR Testing SHA256 hash: ");
	in[0] = 0xd3;
	tmpLen = outBufLen;
	memset(out, 0xdb, outBufLen);
	if ((ret = sliHashSha256(in, 1, out, &tmpLen))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((tmpLen != 32) || (memcmp(out, hashOut, 32))) {
			printf("Fail\n");
			printBuf(hashOut, 32, "expected");
			printBuf(out, tmpLen, "computed");
		} else {
			printf("Pass\n");
		}
	}

	/* Test HMAC */
	printf("SEQR Testing HMAC SHA256: ");
	in[0] = 0xd4;
	tmpLen = outBufLen;
	memset(out, 0xdb, outBufLen);
	if ((ret = sliHmacSha256(macKey, sizeof(macKey), in, 1, out, &tmpLen))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((tmpLen != 32) || (memcmp(out, macOut, 32))) {
			printf("Fail\n");
			printBuf(macOut, 32, "expected");
			printBuf(out, tmpLen, "computed");
		} else {
			printf("Pass\n");
		}
	}

	/* Test AES-CTR, using the mapped I/O buffers */
	printf("SEQR Testing AES-CTR 256-bit key encryption: ");
	tmpLen = sizeof(ctrIn);
	memcpy(sliGetInBuf(), ctrIn, tmpLen);
	memset(sliGetOutBuf(), 0xdb, tmpLen);
	if ((ret = sliAesCtrEnc(ctrKey, sizeof(ctrKey), NULL, 0, sliGetInBuf(), sliGetOutBuf(), tmpLen))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((memcmp(sliGetOutBuf(), ctrOut, tmpLen))) {
			printf("Fail\n");
			printBuf(ctrOut, sizeof(ctrOut), "expected");
			printBuf(sliGetOutBuf(), tmpLen, "computed");
		} else {
			printf("Pass\n");
		}
	}

	printf("SEQR Testing AES-CTR 256-bit key decryption: ");
	tmpLen = sizeof(ctrOut);
	memcpy(sliGetInBuf(), ctrOut, tmpLen);
	memset(sliGetOutBuf(), 0xdb, tmpLen);
	if ((ret = sliAesCtrDec(ctrKey, sizeof(ctrKey), NULL, 0, sliGetInBuf(), sliGetOutBuf(), tmpLen))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((memcmp(sliGetOutBuf(), ctrIn, tmpLen))) {
			printf("Fail\n");
			printBuf(ctrIn, sizeof(ctrIn), "expected");
			printBuf(sliGetOutBuf(), tmpLen, "computed");
		} else {
			printf("Pass\n");
		}
	}

	/* Test AES-GCM */
	printf("SEQR Testing AES-GCM 256-bit key encryption: ");
	tmpLen = sizeof(gcmOut);
	memset(in, 0, tmpLen);
	memset(out, 0xdb, tmpLen);
	memset(gcmNonce, 0, sizeof(gcmNonce));
	memset(gcmKey, 0, sizeof(gcmKey));
	memset(gcmTag, 0xdb, 16);
	if ((ret = sliAesGcmEnc(gcmKey, sizeof(gcmKey), gcmNonce, sizeof(gcmNonce),
	                        NULL, 0, in, out, tmpLen,
	                        gcmTag, sizeof(gcmTag)))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((memcmp(out, gcmOut, tmpLen))) {
			printf("Fail\n");
			printBuf(gcmOut, sizeof(gcmOut), "expected output");
			printBuf(out, tmpLen, "computed output");
		} else if ((memcmp(gcmTag, gcmTagOut, sizeof(gcmTag)))) {
			printf("Fail\n");
			printBuf(gcmTagOut, sizeof(gcmTagOut), "expected tag");
			printBuf(gcmTag, sizeof(gcmTag), "computed tag");
		} else {
			printf("Pass\n");
		}
	}

	printf("SEQR Testing AES-GCM 256-bit key decryption: ");
	tmpLen = sizeof(gcmOut);
	memcpy(sliGetInBuf(), gcmOut, tmpLen);
	memset(out, 0xdb, tmpLen);
	memset(gcmNonce, 0, sizeof(gcmNonce));
	memset(gcmKey, 0, sizeof(gcmKey));
	memcpy(gcmTag, gcmTagOut, 16);
	if ((ret = sliAesGcmDec(gcmKey, sizeof(gcmKey), gcmNonce, sizeof(gcmNonce),
	                        NULL, 0, sliGetInBuf(), out, tmpLen,
	                        gcmTag, sizeof(gcmTag)))) {
		printf("Error 0x%8.8X\n", (uint32_t)ret);
	} else {
		if ((memcmp(out, in, tmpLen))) {
			printf("Fail\n");
			printBuf(in, tmpLen, "expected");
			printBuf(out, tmpLen, "computed");
		} else {
			printf("Pass\n");
		}
	}

	/* Test blobs, both device and provisioning types. */
	for (i = 0; i < 2; i++) {
		size_t outLen;

		if (i == 0) {	/* Provisioning blob */
			printf("SEQR Testing provisioning blob: ");
			if ((ret = sliBlobGenProv(hashOut, sizeof(hashOut)))) {
					printf("Error generating provisioning key 0x%8.8X\n", (uint32_t)ret);
					continue;
			}
			sliBlobMasterProv();
			sliBlobSetPriBlobType(1);
		} else {	/* Device blob */
			printf("SEQR Testing device blob: ");
			sliBlobMasterDev();
			sliBlobSetPriBlobType(3);
		}

		tmpLen = maxBufLen - 48;	/* Need space for added key and tag in output */
		outLen = maxBufLen;
		memset(sliGetInBuf(), 0, tmpLen);
		memset(sliGetOutBuf(), 0xdb, outLen);
		if ((ret = sliBlobEnc(macKey, sizeof(macKey),
		                      sliGetInBuf(), tmpLen,
		                      sliGetOutBuf(), &outLen))) {
			printf("Error encrypting blob 0x%8.8X\n", (uint32_t)ret);
			continue;	/* Skip blob decryption test */
		} else {
			tmpLen = outLen;
			outLen = maxBufLen;
			memcpy(sliGetInBuf(), sliGetOutBuf(), tmpLen);
			memset(sliGetOutBuf(), 0xdb, outLen);
			if ((ret = sliBlobDec(macKey, sizeof(macKey),
			                      sliGetInBuf(), tmpLen,
			                      sliGetOutBuf(), &outLen))) {
				printf("Error decrypting blob 0x%8.8X\n", (uint32_t)ret);
			} else {
				if (outLen != (maxBufLen-48)) {
					printf("Fail\n");
					printf("Incorrect decrypted output length\n");
				} else {
					uint8_t *o = sliGetOutBuf();
					int fail = 0;
					for (j = 0; j < outLen; j++) {
						if ((o[j])) {	/* Should decode to '0' */
							fail = 1;
							break;
						}
					}
					if (fail) {
						printf("Fail\n");
						printf("Incorrect decrypted output at index %d\n", j);
					} else
						printf("Pass\n");
				}
			}
		}
	}

	return ret;
}
#endif

static int sliMapMem(void *addr, size_t len) {
	int ret = SEQ_SMC_SUCCESS;
	SEQ_SMC_CTRL ctrl = { 0 };
	struct arm_smccc_res res;

	ctrl.bits.MEM_MAP = 1;

	arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0, (unsigned long)addr, len, 0, 0, &res);
	ret = (int)res.a0;

	return ret;
}

int sliCryptoInit(void *smcBuf, size_t maxBufLen) {
	int ret = SEQ_SMC_SUCCESS;
	size_t len = 2*maxBufLen + MAXOPSIZE;

	_smc_max_buf_len = maxBufLen;

	if (smcBuf)
		_smc_bufs = smcBuf;
	else if ((_smc_bufs = memalign(4096*8, len)))	/* align to page size */
		_smc_bufs_allocated = 1;

//printf("XXXXX _smc_bufs = %p\n", _smc_bufs);
	if (_smc_bufs) {
		_smc_op = _smc_bufs;
		_smc_in = _smc_op + MAXOPSIZE;
		_smc_out = _smc_in + maxBufLen;
		ret = sliMapMem(_smc_bufs, len);
	} else
		ret = SEQ_SMC_ERROR_NO_MEMORY;

#if (SLI_SMC_TEST != 0)
	if (ret == SEQ_SMC_SUCCESS)
		ret = sliTest(maxBufLen);
#endif

	return ret;
}

int sliCryptoTerm(int disable) {
	int ret = SEQ_SMC_SUCCESS;

	if (_smc_bufs_allocated) {
		memset(_smc_bufs, 0, 2*_smc_max_buf_len + MAXOPSIZE);
		free(_smc_bufs);
		_smc_bufs = NULL;
		_smc_in = NULL;
		_smc_out = NULL;
		_smc_op = NULL;
		_smc_bufs_allocated = 0;
	}

	if (disable) {
		SEQ_SMC_CTRL ctrl = { 0 };
		struct arm_smccc_res res;
		ctrl.bits.DISABLE = 1;

		arm_smccc_smc(SMC_CRYPTO, ctrl.val, 0, 0, 0, 0, 0, 0, &res);
		ret = (int)res.a0;
	}

	return ret;
}
