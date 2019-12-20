#ifndef _SEQ_CRYPTO_FAST_SMC_H
#define _SEQ_CRYPTO_FAST_SMC_H

#include <stdlib.h>		/* size_t */

/*
 * We use the 8 SMC registers in the following way:
 * r0 SMC function ID and return code
 * r1 control word
 * r2 input buffer address
 * r3 input buffer size
 * r4 output buffer address
 * r5 output buffer size
 * r6 op buffer address
 * r7 op buffer size
 *
 * The control word contains the following information:
 * input buffer in use flag
 * output buffer in use flag
 * op buffer in use flag
 *
 * The output buffer size register will contain the number of bytes written
 * on return.
 */

typedef union {
	uint32_t val;
	struct {
		uint32_t PTR_IN     :1;
		uint32_t PTR_OUT    :1;
		uint32_t PTR_OP     :1;
		uint32_t MEM_MAP    :1;
		uint32_t DISABLE    :1;
		uint32_t res       :27;
	} bits;
} SEQ_SMC_CTRL;

/*
 * Each operation structure begins with a control word containing:
 *   crypto function ID
 *   algorithm ID
 *   key type
 *   end/dec flag
 */

typedef union {
	uint32_t val;
	struct {
		uint32_t FUNC       :8;
		uint32_t ALG        :8;
		uint32_t KEY_TYPE   :8;
		uint32_t ENC        :1;
	} bits;
} SEQ_SMC_OP_CTRL;

/* Generic op structure with no extra data.  Used for accessing the control
 * word of all specific op structures.  Also used for operations with no
 * extra data (RNG, blob master key selection, and memory mapping). */
typedef struct {
	SEQ_SMC_OP_CTRL ctrl;
} seq_smc_op_t;

typedef struct {
	SEQ_SMC_OP_CTRL ctrl;
	uint32_t keyPos;
	uint32_t keyLen;
	uint8_t arr[];
} seq_smc_op_mac_t;

typedef struct {
	SEQ_SMC_OP_CTRL ctrl;
	uint32_t keyPos;
	uint32_t keyLen;
	uint32_t ivPos;
	uint32_t ivLen;
	uint8_t arr[];
} seq_smc_op_cipher_t;

typedef struct {
	SEQ_SMC_OP_CTRL ctrl;
	uint32_t keyPos;
	uint32_t keyLen;
	uint32_t noncePos;
	uint32_t nonceLen;
	uint32_t aadPos;
	uint32_t aadLen;
	uint32_t tagPos;
	uint32_t tagLen;
	uint8_t arr[];
} seq_smc_op_ae_t;

typedef struct {
	SEQ_SMC_OP_CTRL ctrl;
	uint32_t keyModPos;
	uint32_t keyModLen;
	uint8_t arr[];
} seq_smc_op_blob_t;

#define SEQ_SMC_FUNC_HASH             0x01
#define SEQ_SMC_FUNC_MAC              0x02
#define SEQ_SMC_FUNC_CIPHER           0x03
#define SEQ_SMC_FUNC_AE               0x04
#define SEQ_SMC_FUNC_RNG              0x05
#define SEQ_SMC_FUNC_BLOB             0x06
#define SEQ_SMC_FUNC_MASTER_DEV       0x10
#define SEQ_SMC_FUNC_MASTER_PROV      0x11
#define SEQ_SMC_FUNC_GEN_PROV         0x12

#define SEQ_SMC_ALG_HASH_SHA1         0x01
#define SEQ_SMC_ALG_HASH_SHA224       0x02
#define SEQ_SMC_ALG_HASH_SHA256       0x03
#define SEQ_SMC_ALG_HASH_SHA384       0x04
#define SEQ_SMC_ALG_HASH_SHA512       0x05

#define SEQ_SMC_ALG_HMAC_SHA1         0x11
#define SEQ_SMC_ALG_HMAC_SHA224       0x12
#define SEQ_SMC_ALG_HMAC_SHA256       0x13
#define SEQ_SMC_ALG_HMAC_SHA384       0x14
#define SEQ_SMC_ALG_HMAC_SHA512       0x15

#define SEQ_SMC_ALG_AES_ECB           0x21
#define SEQ_SMC_ALG_AES_CBC           0x22
#define SEQ_SMC_ALG_AES_CTR           0x23
#define SEQ_SMC_ALG_AES_CCM           0x24
#define SEQ_SMC_ALG_AES_GCM           0x25

#define SEQ_SMC_ALG_BLOB              0x30

#define SEQ_SMC_ALG_RNG               0x40

#define SEQ_SMC_KEY_TYPE_AES          0x02
#define SEQ_SMC_KEY_TYPE_HMAC         0x02
#define SEQ_SMC_KEY_TYPE_ECDSA_PRV    0x11
#define SEQ_SMC_KEY_TYPE_ECDSA_PUB    0x12
#define SEQ_SMC_KEY_TYPE_ECDH_PRV     0x21
#define SEQ_SMC_KEY_TYPE_ECDH_PUB     0x22
#define SEQ_SMC_KEY_TYPE_RSA_PRV      0x31
#define SEQ_SMC_KEY_TYPE_RSA_PUB      0x32

size_t opHashLen(seq_smc_op_t *op);
size_t opMacLen(seq_smc_op_mac_t *op);
size_t opCipherLen(seq_smc_op_cipher_t *op);
size_t opAeLen(seq_smc_op_ae_t *op);
size_t opBlobLen(seq_smc_op_blob_t *op);
size_t opRngLen(seq_smc_op_t *op);
size_t opMasterDevLen(seq_smc_op_t *op);
size_t opMasterProvLen(seq_smc_op_t *op);
size_t opGenProvLen(seq_smc_op_t *op);

seq_smc_op_t* newOpHash(unsigned int alg);
seq_smc_op_mac_t* newOpMac(unsigned int alg,
                           const uint8_t *key, size_t keyLen);
seq_smc_op_cipher_t* newOpCipher(unsigned int alg,
                                 const uint8_t *key, size_t keyLen,
                                 const uint8_t *iv, size_t ivLen,
                                 int encrypt);
seq_smc_op_ae_t* newOpAe(unsigned int alg,
                         const uint8_t *key, size_t keyLen,
                         const uint8_t *nonce, size_t nonceLen,
                         const uint8_t *aad, size_t aadLen,
                         const uint8_t *tag, size_t tagLen,
                         int encrypt);
seq_smc_op_blob_t* newOpBlob(const uint8_t *keyMod, size_t keyModLen,
                             int encrypt);
seq_smc_op_t* newOpRng(void);
seq_smc_op_t* newOpMasterDev(void);
seq_smc_op_t* newOpMasterProv(void);
seq_smc_op_t* newOpGenProv(void);

void freeOpHash(seq_smc_op_t *op);
void freeOpMac(seq_smc_op_mac_t *op);
void freeOpCipher(seq_smc_op_cipher_t *op);
void freeOpAe(seq_smc_op_ae_t *op);
void freeOpBlob(seq_smc_op_blob_t *op);
void freeOpRng(seq_smc_op_t *op);
void freeOpMasterDev(seq_smc_op_t *op);
void freeOpMasterProv(seq_smc_op_t *op);
void freeOpGenProv(seq_smc_op_t *op);

void copyTagOpAe(seq_smc_op_ae_t *op, uint8_t *tag);

#endif /* _SEQ_CRYPTO_FAST_SMC_H */
