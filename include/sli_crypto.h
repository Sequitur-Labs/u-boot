#ifndef _SLI_CRYPTO_H
#define _SLI_CRYPTO_H

#include <common.h>

/*
 * Error codes generated in the SPL.
 * Note that error codes returned from the TEE are defined in tee_api_defines.h,
 * and are in the region 0xFFFFXXXX.
 */
#define SEQ_SMC_SUCCESS               0
#define SEQ_SMC_ERROR_SHORT_BUFFER    0xFFFA0001
#define SEQ_SMC_ERROR_OP_INIT         0xFFFA0002 
#define SEQ_SMC_ERROR_NO_MEMORY       0xFFFA0003 

/*
 *  *  * Compute hash in a single step.
 */

int sliHashSha1(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int sliHashSha224(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int sliHashSha256(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int sliHashSha384(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int sliHashSha512(const uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);

/*
 *  *  * Compute HMAC in a single step.
 */

int sliHmacSha1(const uint8_t *key, size_t keyLen,
                const uint8_t *in, size_t inLen,
                uint8_t *out, size_t *outLen);

int sliHmacSha224(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen);

int sliHmacSha256(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen);

int sliHmacSha384(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen);

int sliHmacSha512(const uint8_t *key, size_t keyLen,
                  const uint8_t *in, size_t inLen,
                  uint8_t *out, size_t *outLen);

/*
 *  *  * Encrypt/Decrypt with cipher in a single step.
 *   *   */
int sliAesCtrEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *iv, size_t ivLen,
                 const uint8_t *in, uint8_t *out, size_t len);

int sliAesCtrDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *iv, size_t ivLen,
                 const uint8_t *in, uint8_t *out, size_t len);

/*
 *  *  * Authenticated Encrypt/Decrypt in a single step.
 */

int sliAesCcmEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 uint8_t *tag, size_t tagLen);

int sliAesCcmDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 const uint8_t *tag, size_t tagLen);

int sliAesGcmEnc(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 uint8_t *tag, size_t tagLen);

int sliAesGcmDec(const uint8_t *key, size_t keyLen,
                 const uint8_t *nonce, size_t nonceLen,
                 const uint8_t *aad, size_t aadLen,
                 const uint8_t *in, uint8_t *out, size_t len,
                 const uint8_t *tag, size_t tagLen);

/*
 *  *  * Blob Encrypt/Decrypt in a single step.
 */

int sliBlobEnc(const uint8_t *keyMod, size_t keyModLen,
               const uint8_t *in, size_t inLen,
               uint8_t *out, size_t *outLen);

int sliBlobDec(const uint8_t *keyMod, size_t keyModLen,
               const uint8_t *in, size_t inLen,
               uint8_t *out, size_t *outLen);

/* Select the device key for blob operations. */
int sliBlobMasterDev(void);
/* Select the provisioning key for blob operations. */
int sliBlobMasterProv(void);
/* Generate the provisioning key based on the supplied BRN. */
int sliBlobGenProv(const uint8_t *brn, size_t brnLen);
/* Set private blob type.  The bits are sticky, and only apply in the
 * Trusted security state. */
int sliBlobSetPriBlobType(unsigned int type);

/*
 *  *  * RNG in a single step.
 */

int sliRng(uint8_t *out, size_t outLen);

/*
 *  *  * I/O and op buffer handling functions
 */

/* Sets up the buffers used for input, output and the op structure.
 * If smcBuf is set to NULL, space will be allocated on the heap.
 * maxBufLen is the size allocated for the input and the output
 * buffers.  The op structure is allocated 4096 bytes.  So, a
 * buffer passed to this function needs to be at least
 * 2*maxBufLen+4096 bytes in size.
 * The buffer region is mapped in the TEE during this call. */
int sliCryptoInit(void *smcBuf, size_t maxBufLen);

/* Frees the buffers if they were allocated by sliCryptoInit().
 * Disables the crypto interface in the TEE if *disable* is non-zero. */
int sliCryptoTerm(int disable);

/* Return the pointers to the buffers used for SMC communication
 * with the TEE.
 * If other I/O buffers are passed to the crypto functions above,
 * their contents will be copied to and from the mapped buffers
 * around the SMC call. If the buffers from the following functions
 * are passed to the crypto functions, they will be used as is
 * without copying. */
uint8_t* sliGetInBuf(void);
uint8_t* sliGetOutBuf(void);
uint8_t* sliGetOpBuf(void);

#endif /*_SLI_CRYPTO_H */

