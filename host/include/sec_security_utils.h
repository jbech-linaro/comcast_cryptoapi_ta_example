/**
 * Copyright 2014 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file sec_security_utils.h
 *
 * @brief Helper utilities for implementing the Security API
 *
 */

#ifndef SEC_SECURITY_UTILS_H_
#define SEC_SECURITY_UTILS_H_

#include "sec_security.h"
#if !defined(OPTEE_DEMO)
#include <openssl/rsa.h>
#include <openssl/x509.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
{
    SEC_ENDIANESS_BIG,
    SEC_ENDIANESS_LITTLE,
    SEC_ENDIANESS_UNKNOWN
} SecUtils_Endianess;

typedef struct
{
    uint8_t inner_kc_type;
    uint8_t reserved[7];

    uint8_t device_id[SEC_DEVICEID_LEN];
} SecUtils_KeyStoreHeader;

#define SEC_UTILS_KEYSTORE_MAGIC "KST0"

/* create a bit mask for a specified bit */
#define SEC_BIT_MASK(bit) (1 << bit)

/* read a specified bit */
#define SEC_BIT_READ(bit, input) ((input >> bit) & 1)

/* write a specified value at the specific bit position */
#define SEC_BIT_WRITE(bit, input, val) ((~SEC_BIT_MASK(bit) | input) | ((val & 1) << bit))

/**
 * Buffer information structure
 */
typedef struct
{
    SEC_BYTE* base;
    SEC_SIZE size;
    SEC_SIZE written;
} Sec_Buffer;

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle *proc, SEC_BOOL require_mac, void* store, SEC_SIZE store_len);
Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle *proc, SecUtils_KeyStoreHeader *header, Sec_KeyContainer container);
SecUtils_KeyStoreHeader *SecUtils_GetKeyStoreUserHeader(void *store);

/**
 * @brief memcmp replacement with constant time runtime
 */
int SecUtils_Memcmp(void* ptr1, void* ptr2, const size_t num);

/**
 * @brief memset replacement that cannot be optimized out
 */
void *SecUtils_Memset(void *ptr, int value, size_t num);

/**
 * @brief initialize the Sec_Buffer structure
 *
 * @param buffer Sec_Buffer structure to initialize
 * @param mem memory buffer to use
 * @param len size of the memory buffer
 */
void SecUtils_BufferInit(Sec_Buffer *buffer, void *mem, SEC_SIZE len);

/**
 * @brief reset the buffer
 *
 * @param buffer Sec_Buffer structure to initialize
 */
void SecUtils_BufferReset(Sec_Buffer *buffer);

/**
 * @brief Write data to a buffer
 *
 * @param buffer pointer to a Sec_Buffer structure to use
 * @param data input data to write
 * @param len length of input data
 *
 * @return Status of the operation.  Error status will be returned if there
 * is not enough space left in the output buffer.
 */
Sec_Result SecUtils_BufferWrite(Sec_Buffer *buffer, void *data, SEC_SIZE len);

/**
 * @brief Read data from a file into a specified buffer
 *
 * @param path file path
 * @param data output data buffer where the file contents will be written
 * @param data_len length of the output buffer
 * @param data_read actual number of bytes written
 *
 * @return status of the operation
 */
Sec_Result SecUtils_ReadFile(const char *path, void *data, SEC_SIZE data_len, SEC_SIZE *data_read);

/**
 * @brief Write the input data into a specified file
 *
 * @param path output file path
 * @param data data to write
 * @param data_len length of input data
 *
 * @return status of the operation
 */
Sec_Result SecUtils_WriteFile(const char *path, void *data, SEC_SIZE data_len);

/**
 * @brief create a specified directory
 * @param path directory path
 */
Sec_Result SecUtils_MkDir(const char *path);

/**
 * @brief Remove a specified file
 *
 * @param path of the file to remove
 */
Sec_Result SecUtils_RmFile(const char *path);

/**
 * @brief Checks whether the specified file exists
 *
 * @param path file path
 *
 * @return 1 if the file exists, 0 if it does not
 */
SEC_BOOL SecUtils_FileExists(const char *path);

typedef struct
{
    char name[256];
    SEC_BYTE is_dir;
} Sec_LsDirEntry;

/**
 * @brief Obtain directory entries from a specified dir
 *
 * @param path path of the directory to list
 * @param entries pointer to the entry array.  If NULL, the entries info will not be filled in, but the number
 * of items will still be returned
 * @param maxNumEntries The maximun number of entries to fill.
 *
 * @return number of directory entries in a specified dir
 */
SEC_SIZE SecUtils_LsDir(const char *path, Sec_LsDirEntry *entries, SEC_SIZE maxNumEntries);

/**
 * @brief  Obtain a key container type for a specified key type
 *
 * @param key_type key type
 * @return key container type
 */
Sec_KeyContainer SecUtils_RawContainer(Sec_KeyType key_type);

#if !defined(OPTEE_DEMO)
/**
 * @brief Write a BIGNUM value into the specified buffer
 */
void SecUtils_BigNumToBuffer(BIGNUM *bignum, SEC_BYTE *buffer,
        SEC_SIZE buffer_len);

/**
 * @brief Obtain an OpenSSL RSA object from the private key binary blob
 */
RSA *SecUtils_RSAFromPrivBinary(Sec_RSARawPrivateKey *binary);

/**
 * @brief Obtain an OpenSSL RSA object from the public key binary blob
 */
RSA *SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey *binary);

/**
 * @brief Write OpenSSL RSA object into a private key binary blob
 */
void SecUtils_RSAToPrivBinary(RSA *rsa, Sec_RSARawPrivateKey *binary);

/**
 * @brief Write OpenSSL RSA object into a public key binary blob
 */
void SecUtils_RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary);

/**
 * @brief Write an OpenSSL X509 object in DER format
 */
SEC_SIZE SecUtils_X509ToDer(X509 *x509, void *mem);

/**
 * @brief Load an OpenSSL X509 object from a DER format
 */
X509 * SecUtils_DerToX509(void *mem, SEC_SIZE len);

/**
 * @brief Verify X509 certificate with public RSA key
 */
Sec_Result SecUtils_VerifyX509WithRawPublicKey(
        X509 *x509, Sec_RSARawPublicKey* public_key);
#endif

/**
 * @brief Calculate a CRC32 value over the input
 */
uint32_t SecUtils_CRC(void *intput, SEC_SIZE input_len);

/**
 * @brief Endian swap
 */
uint16_t SecUtils_EndianSwap_uint16(uint16_t val);

/**
 * @brief Endian swap
 */
int16_t SecUtils_EndianSwap_int16(int16_t val);

/**
 * @brief Endian swap
 */
uint32_t SecUtils_EndianSwap_uint32(uint32_t val);

/**
 * @brief Endian swap
 */
int32_t SecUtils_EndianSwap_int32(int32_t val);

/**
 * @brief Endian swap
 */
int64_t SecUtils_EndianSwap_int64(int64_t val);

/**
 * @brief Endian swap
 */
uint64_t SecUtils_EndianSwap_uint64(uint64_t val);

/**
 * @brief Increment the AES 128-bit counter
 */
void SecUtils_AesCtrInc(SEC_BYTE *counter);

/**
 * @brief Print a hexadecimal value
 */
void SecUtils_PrintHex(void* data, SEC_SIZE numBytes);

/**
 * @brief Perform required padding for an RSA input data
 */
Sec_Result SecUtils_PadForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE keySize);

/**
 * @brief Obtain chip endianess at runtime
 */
SecUtils_Endianess SecUtils_GetEndianess(void);

/**
 * @brief Convert big endian bytes to native uint32
 */
uint32_t SecUtils_BEBytesToUint32(SEC_BYTE *bytes);

/**
 * @brief Convert big endian bytes to native uint64
 */
uint64_t SecUtils_BEBytesToUint64(SEC_BYTE *bytes);

/**
 * @brief Convert native uint32 to big endian bytes
 */
void SecUtils_Uint32ToBEBytes(uint32_t val, SEC_BYTE *bytes);

/**
 * @brief Convert native uint64 to big endian bytes
 */
void SecUtils_Uint64ToBEBytes(uint64_t val, SEC_BYTE *bytes);

/**
 * @brief Checks whether the specified strings ends with the other string
 */
SEC_BYTE SecUtils_EndsWith(const char* str, const char* end);

/**
 * @brief obtain the index of the item in a list
 */
int SecUtils_ItemIndex(SEC_OBJECTID *items, SEC_SIZE numItems, SEC_OBJECTID item);

/**
 * @brief insert new item into the list if it does not exist.
 */
SEC_SIZE SecUtils_UpdateItemList(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, SEC_OBJECTID item_id);

/**
 * @brief insert new items into the list from the specified directory.
 */
SEC_SIZE SecUtils_UpdateItemListFromDir(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, const char* dir, const char* ext);

/**
 * Initialize all OpenSSL algorithms used by the Security API.  Register securityapi engine.
 */
void SecUtils_InitOpenSSL(void);

#if !defined(OPTEE_DEMO)
/**
 * @brief Obtain an OpenSSL RSA key from the Security API key handle.  This RSA
 * key will support performing RSA encrypt/decrypt/sign/verify operations in hardware
 * when used by OpenSSL functions such as PKCS7_sign, PKCS7_verify, etc.
 */
RSA* SecUtils_KeyToEngineRSA(Sec_KeyHandle *key);

/**
 * @brief Obtain an OpenSSL X509 certificate from the Security API cert handle.
 */
X509* SecUtils_CertificateToX509(Sec_CertificateHandle *cert);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_UTILS_H_ */
