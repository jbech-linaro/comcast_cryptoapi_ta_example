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
 * @file sec_security.h
 *
 * @brief Comcast Security API.
 *
 * Comcast Security API provides common interfaces to cryptographic
 * functionality provided by different SOC vendors.
 *
 *
 * @par Document
 * https://www.teamccp.com/confluence/display/xcalPDEV/Security+API
 *
 */

#ifndef SEC_SECURITY_H_
#define SEC_SECURITY_H_

/*****************************************************************************
 * STANDARD INCLUDE FILES
 *****************************************************************************/
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*****************************************************************************
 * EXPORTED DEFINITIONS
 *****************************************************************************/

#define SEC_API_VERSION "1.7.4"

/* enables debug prints */
#define SEC_DEBUG

/* macro to string */
#define SEC_MTOS_(x) #x
#define SEC_MTOS(x) SEC_MTOS_(x)

/* min */
#ifndef SEC_MIN
#define SEC_MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* max */
#ifndef SEC_MAX
#define SEC_MAX(a,b) (((a)<(b))?(b):(a))
#endif

#define SEC_FREE(x) do { if ((x) != NULL) {free(x); x=NULL;} } while(0)
#define SEC_RSA_FREE(x) do { if ((x) != NULL) {RSA_free(x); x=NULL;} } while(0)
#define SEC_EVPPKEY_FREE(x) do { if ((x) != NULL) {EVP_PKEY_free(x); x=NULL;} } while(0)
#define SEC_BIO_FREE(x) do { if ((x) != NULL) {BIO_free(x); x=NULL;} } while(0)
#define SEC_X509_FREE(x) do { if ((x) != NULL) {X509_free(x); x=NULL;} } while(0)

#define SEC_MAX_FILE_PATH_LEN 4096

/* maximum length of a digest value */
#define SEC_DIGEST_MAX_LEN 32

/* maximum length of a MAC value */
#define SEC_MAC_MAX_LEN 32

/* maximum length of a MAC key */
#define SEC_MAC_KEY_MAX_LEN 32

/* maximum length of an RSA key modulus */
#define SEC_RSA_KEY_MAX_LEN 256

/* maximum length of a signature value */
#define SEC_SIGNATURE_MAX_LEN SEC_RSA_KEY_MAX_LEN

/* maximum length of an AES key */
#define SEC_AES_KEY_MAX_LEN 32

/* aes block size */
#define SEC_AES_BLOCK_SIZE 16

/* maximum length of a symetric key (AES or MAC) */
#define SEC_SYMETRIC_KEY_MAX_LEN SEC_MAX(SEC_AES_KEY_MAX_LEN, SEC_MAC_KEY_MAX_LEN)

/* maximum length of the IV value */
#define SEC_CIPHER_IV_MAX_LEN SEC_AES_KEY_MAX_LEN

/* the length of the device id */
#define SEC_DEVICEID_LEN 8

/* the length of client nonce */
#define SEC_NONCE_LEN 20

/* debug prints */
#define SEC_PRINT(fmt, ...) \
    if (Sec_GetLogger() != NULL) \
    {   \
        Sec_GetLogger()(fmt, ## __VA_ARGS__);   \
    }

#ifdef SEC_DEBUG
#define SEC_LOG_ERROR(txt, ...) SEC_PRINT(txt " (%s, line %d)\n", ## __VA_ARGS__, __FILE__, __LINE__)
#else
#define SEC_LOG_ERROR(txt, ...)
#endif

#define CHECK_EXACT(call, value, label) \
    if ((call) != value) \
    { \
        SEC_LOG_ERROR(#call " returned error"); \
        goto label; \
    }

/* fixed reserved ids */
#define SEC_OBJECTID_INVALID 0xffffffffffffffffULL
#define SEC_OBJECTID_BASE_KEY_AES 0xfffffffffffffffeULL
#define SEC_OBJECTID_BASE_KEY_MAC 0xfffffffffffffffdULL
#define SEC_OBJECTID_STORE_MACKEYGEN_KEY 0xfffffffffffffffcULL
#define SEC_OBJECTID_CERTSTORE_KEY 0xfffffffffffffffbULL
#define SEC_OBJECTID_STORE_AES_KEY 0xfffffffffffffffaULL
#define SEC_OBJECTID_RESERVED_9 0xfffffffffffffff9ULL
#define SEC_OBJECTID_RESERVED_8 0xfffffffffffffff8ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_7 0xfffffffffffffff7ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_6 0xfffffffffffffff6ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_5 0xfffffffffffffff5ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_4 0xfffffffffffffff4ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_3 0xfffffffffffffff3ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_2 0xfffffffffffffff2ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_1 0xfffffffffffffff1ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_0 0xfffffffffffffff0ULL

/* reserved key space */
#define SEC_OBJECTID_RESERVED_TOP  0xfffffffffffffff0ULL
#define SEC_OBJECTID_RESERVED_BASE 0xffffffffffffff00ULL

/* user key space */
#define SEC_OBJECTID_USER_TOP  0xffffffffffffff00ULL
#define SEC_OBJECTID_USER_BASE 0xffffffffffff0000ULL

/* comcast object ids */
#define SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY 0xffffffff00000001ULL
#define SEC_OBJECTID_COMCAST_XCALSESSIONMACKEYTOKEN 0xffffffff00000002ULL

#define SEC_OBJECTID_COMCAST_SGNCERT 0x0111000001110001ULL
#define SEC_OBJECTID_COMCAST_SGNSUBCACERT 0x0111000001110002ULL
#define SEC_OBJECTID_COMCAST_SGNROOTCACERT 0x0111000001110003ULL
#define SEC_OBJECTID_COMCAST_ENCCERT 0x0111000001110004ULL
#define SEC_OBJECTID_COMCAST_ENCSUBCACERT 0x0111000001110005ULL
#define SEC_OBJECTID_COMCAST_ENCROOTCACERT 0x0111000001110006ULL
#define SEC_OBJECTID_COMCAST_TLSCERT 0x0111000001110007ULL
#define SEC_OBJECTID_COMCAST_TLSSUBCACERT 0x0111000001110008ULL
#define SEC_OBJECTID_COMCAST_TLSROOTCACERT 0x0111000001110009ULL
#define SEC_OBJECTID_COMCAST_CERTCA01CERT 0x0211000002110001ULL
#define SEC_OBJECTID_COMCAST_STATUSCA01CERT 0x0211000002110002ULL
#define SEC_OBJECTID_COMCAST_SGNKEY 0x0311000003110001ULL
#define SEC_OBJECTID_COMCAST_ENCKEY 0x0311000003110002ULL
#define SEC_OBJECTID_COMCAST_TLSKEY 0x0311000003110003ULL
#define SEC_OBJECTID_COMCAST_PKIBUNDLE 0x0511000005110001ULL
#define SEC_OBJECTID_COMCAST_HASHLOCKED 0x0711000007110001ULL

/* adobe object ids */
#define SEC_OBJECTID_ADOBE_DRMMODELKEY 0x0321000003214030ULL
#define SEC_OBJECTID_ADOBE_DRMMODELCERT 0x0121000001210001ULL
#define SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATERUNTIMEDRMCACERT 0x0121000001210002ULL
#define SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATECACERT 0x0121000001210003ULL
#define SEC_OBJECTID_ADOBE_DRMMODELROOTCACERT 0x0121000001210004ULL
#define SEC_OBJECTID_ADOBE_SD01CERT 0x0121000001210005ULL
#define SEC_OBJECTID_ADOBE_SD01INTERMEDIATERUNTIMEDRMCACERT 0x0121000001210006ULL
#define SEC_OBJECTID_ADOBE_SD01INTERMEDIATECACERT 0x0121000001210007ULL
#define SEC_OBJECTID_ADOBE_SD01ROOTCACERT 0x0121000001210008ULL
#define SEC_OBJECTID_ADOBE_SD02CERT 0x0121000001210009ULL
#define SEC_OBJECTID_ADOBE_SD02INTERMEDIATERUNTIMEDRMCACERT 0x012100000121000AULL
#define SEC_OBJECTID_ADOBE_SD02INTERMEDIATECACERT 0x012100000121000BULL
#define SEC_OBJECTID_ADOBE_SD02ROOTCACERT 0x012100000121000CULL
#define SEC_OBJECTID_ADOBE_SD03CERT 0x012100000121000DULL
#define SEC_OBJECTID_ADOBE_SD03INTERMEDIATERUNTIMEDRMCACERT 0x012100000121000EULL
#define SEC_OBJECTID_ADOBE_SD03INTERMEDIATECACERT 0x012100000121000FULL
#define SEC_OBJECTID_ADOBE_SD03ROOTCACERT 0x0121000001210010ULL
#define SEC_OBJECTID_ADOBE_INDIVTRANSPORTCERT 0x0121000001210011ULL
#define SEC_OBJECTID_ADOBE_SD01KEY 0x0321000003210002ULL
#define SEC_OBJECTID_ADOBE_SD02KEY 0x0321000003210003ULL
#define SEC_OBJECTID_ADOBE_SD03KEY 0x0321000003210004ULL
#define SEC_OBJECTID_ADOBE_PRODADOBEROOTDIGEST 0x0421000004210001ULL
#define SEC_OBJECTID_ADOBE_DRMPKI 0x0621000006210001ULL
#define SEC_OBJECTID_ADOBE_DRMPKI_ENHANCED 0x0621000006210002ULL

#define SEC_FKPSTYPE_CERTIFICATE 0x01
#define SEC_FKPSTYPE_CACERTIFICATE 0x02
#define SEC_FKPSTYPE_KEYCONTAINER 0x03
#define SEC_FKPSTYPE_MESSAGEDIGEST 0x04
#define SEC_FKPSTYPE_PKIBUNDLE 0x05
#define SEC_FKPSTYPE_DRMPKIBUNDLE 0x06
#define SEC_FKPSTYPE_HASHLOCKED 0x07
#define SEC_FKPSTYPE_RESERVED 0xFF

#define SEC_OBJECTID_PATTERN "%016llx"
#define SEC_KEY_FILENAME_EXT ".key"
#define SEC_KEY_FILENAME_PATTERN "%016llx.key"
#define SEC_KEYINFO_FILENAME_PATTERN "%016llx.keyinfo"
#define SEC_CERT_FILENAME_EXT ".cert"
#define SEC_CERT_FILENAME_PATTERN "%016llx.cert"
#define SEC_CERTINFO_FILENAME_PATTERN "%016llx.certinfo"
#define SEC_BUNDLE_FILENAME_EXT ".bin"
#define SEC_BUNDLE_FILENAME_PATTERN "%016llx.bin"

#define SEC_BUNDLE_MAX_LEN 128*1024
#define SEC_CERT_MAX_DATA_LEN (1024 * 64)

#define SEC_TRUE 1
#define SEC_FALSE 0

/*****************************************************************************
 * EXPORTED TYPES
 *****************************************************************************/

typedef uint8_t SEC_BYTE;
typedef uint8_t SEC_BOOL;
typedef unsigned int SEC_SIZE;
typedef uint64_t SEC_OBJECTID;

/**
 * @brief Cipher algorithms
 *
 */
typedef enum
{
    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING = 0,
    SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING,
    SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING,
    SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING,
    SEC_CIPHERALGORITHM_AES_CTR,
    SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING,
    SEC_CIPHERALGORITHM_RSA_OAEP_PADDING,
    SEC_CIPHERALGORITHM_NUM
} Sec_CipherAlgorithm;

/**
 * @brief Key types
 *
 */
typedef enum
{
    SEC_KEYTYPE_AES_128 = 0,
    SEC_KEYTYPE_AES_256,
    SEC_KEYTYPE_RSA_1024,
    SEC_KEYTYPE_RSA_2048,
    SEC_KEYTYPE_RSA_1024_PUBLIC,
    SEC_KEYTYPE_RSA_2048_PUBLIC,
    SEC_KEYTYPE_HMAC_128,
    SEC_KEYTYPE_HMAC_160,
    SEC_KEYTYPE_HMAC_256,
    SEC_KEYTYPE_NUM
} Sec_KeyType;

/**
 * @brief Key container types
 *
 */
typedef enum
{
    SEC_KEYCONTAINER_RAW_AES_128 = 0,
    SEC_KEYCONTAINER_RAW_AES_256,
    SEC_KEYCONTAINER_RAW_HMAC_128,
    SEC_KEYCONTAINER_RAW_HMAC_160,
    SEC_KEYCONTAINER_RAW_HMAC_256,
    SEC_KEYCONTAINER_RAW_RSA_1024,
    SEC_KEYCONTAINER_RAW_RSA_2048,
    SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC,
    SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC,
    SEC_KEYCONTAINER_PEM_RSA_1024,
    SEC_KEYCONTAINER_PEM_RSA_2048,
    SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC,
    SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC,
    SEC_KEYCONTAINER_SOC,
    SEC_KEYCONTAINER_SOC_INTERNAL_0,
    SEC_KEYCONTAINER_SOC_INTERNAL_1,
    SEC_KEYCONTAINER_SOC_INTERNAL_2,
    SEC_KEYCONTAINER_SOC_INTERNAL_3,
    SEC_KEYCONTAINER_SOC_INTERNAL_4,
    SEC_KEYCONTAINER_SOC_INTERNAL_5,
    SEC_KEYCONTAINER_SOC_INTERNAL_6,
    SEC_KEYCONTAINER_SOC_INTERNAL_7,
    SEC_KEYCONTAINER_STORE,
    SEC_KEYCONTAINER_NUM
} Sec_KeyContainer;

/**
 * @brief Certificate container types
 *
 */
typedef enum
{
    SEC_CERTIFICATECONTAINER_X509_DER = 0,
    SEC_CERTIFICATECONTAINER_X509_PEM,
    SEC_CERTIFICATECONTAINER_SOC,
    SEC_CERTIFICATECONTAINER_NUM
} Sec_CertificateContainer;

/**
 * @brief Storage locations
 *
 */
typedef enum {
    SEC_STORAGELOC_RAM = 0,
    SEC_STORAGELOC_RAM_SOFT_WRAPPED,
    SEC_STORAGELOC_FILE,
    SEC_STORAGELOC_FILE_SOFT_WRAPPED,
    SEC_STORAGELOC_OEM,
    SEC_STORAGELOC_SOC = SEC_STORAGELOC_OEM,
    SEC_STORAGELOC_NUM
} Sec_StorageLoc;

/**
 * @brief Cipher modes
 *
 */
typedef enum
{
    SEC_CIPHERMODE_ENCRYPT = 0,
    SEC_CIPHERMODE_DECRYPT,
    SEC_CIPHERMODE_ENCRYPT_NATIVEMEM,
    SEC_CIPHERMODE_DECRYPT_NATIVEMEM,
    SEC_CIPHERMODE_NUM
} Sec_CipherMode;

/**
 * @brief Signature algorithms
 *
 */
typedef enum
{
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS = 0,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS,
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST,
    SEC_SIGNATUREALGORITHM_NUM
} Sec_SignatureAlgorithm;

/**
 * @brief Signature modes
 *
 */
typedef enum
{
    SEC_SIGNATUREMODE_SIGN = 0,
    SEC_SIGNATUREMODE_VERIFY,
    SEC_SIGNATUREMODE_NUM
} Sec_SignatureMode;

/**
 * @brief MAC algorithms
 *
 */
typedef enum
{
    SEC_MACALGORITHM_HMAC_SHA1 = 0,
    SEC_MACALGORITHM_HMAC_SHA256,
    SEC_MACALGORITHM_CMAC_AES_128,
    SEC_MACALGORITHM_NUM
} Sec_MacAlgorithm;

/**
 * @brief Digest algorithms
 *
 */
typedef enum
{
    SEC_DIGESTALGORITHM_SHA1 = 0,
    SEC_DIGESTALGORITHM_SHA256,
    SEC_DIGESTALGORITHM_NUM
} Sec_DigestAlgorithm;

/**
 * @brief Random algorithms
 *
 */
typedef enum
{
    SEC_RANDOMALGORITHM_TRUE = 0,
    SEC_RANDOMALGORITHM_PRNG,
    SEC_RANDOMALGORITHM_NUM
} Sec_RandomAlgorithm;

/**
 * @brief Function return codes
 *
 */
typedef enum
{
    SEC_RESULT_SUCCESS = 0,
    SEC_RESULT_FAILURE,
    SEC_RESULT_INVALID_PARAMETERS,
    SEC_RESULT_NO_SUCH_ITEM,
    SEC_RESULT_BUFFER_TOO_SMALL,
    SEC_RESULT_INVALID_INPUT_SIZE,
    SEC_RESULT_INVALID_HANDLE,
    SEC_RESULT_INVALID_PADDING,
    SEC_RESULT_UNIMPLEMENTED_FEATURE,
    SEC_RESULT_ITEM_ALREADY_PROVISIONED,
    SEC_RESULT_ITEM_NON_REMOVABLE,
    SEC_RESULT_VERIFICATION_FAILED,
    SEC_RESULT_NUM
} Sec_Result;

/**
 * @brief Raw Private RSA key data
 *
 */
typedef struct
{
    SEC_BYTE n[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE d[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE e[4];
    SEC_BYTE modulus_len_be[4];
    uint32_t padding[2];
} Sec_RSARawPrivateKey;

/**
 * @brief Raw Public RSA key data
 *
 */
typedef struct
{
    SEC_BYTE n[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE e[4];
    SEC_BYTE modulus_len_be[4];
} Sec_RSARawPublicKey;

/**
 * @brief Opaque processor initialization parameters
 *
 */
typedef struct Sec_ProcessorInitParams_struct Sec_ProcessorInitParams;

/**
 * @brief Opaque processor handle
 *
 */
typedef struct Sec_ProcessorHandle_struct Sec_ProcessorHandle;

/**
 * @brief Opaque key handle
 *
 */
typedef struct Sec_KeyHandle_struct Sec_KeyHandle;

/**
 * @brief Opaque bundle handle
 *
 */
typedef struct Sec_BundleHandle_struct Sec_BundleHandle;

/**
 * @brief Opaque cipher handle
 *
 */
typedef struct Sec_CipherHandle_struct Sec_CipherHandle;

/**
 * @brief Opaque digest handle
 *
 */
typedef struct Sec_DigestHandle_struct Sec_DigestHandle;

/**
 * @brief Opaque mac handle
 *
 */
typedef struct Sec_MacHandle_struct Sec_MacHandle;

/**
 * @brief Opaque signature handle
 *
 */
typedef struct Sec_SignatureHandle_struct Sec_SignatureHandle;

/**
 * @brief Opaque random handle
 *
 */
typedef struct Sec_RandomHandle_struct Sec_RandomHandle;

/**
 * @brief Opaque certificate handle
 *
 */
typedef struct Sec_CertificateHandle_struct Sec_CertificateHandle;

/**
 * @brief Initialize secure processor
 *
 * Initializes the secure processor, generates key derivation base key,
 * sets up all required resources.  Only one secure processor can be
 * active at a time.
 *
 * @param secProcHandle pointer to a processor handle that will be set to
 * a constructed handle.
 * @param socInitParams pointer to initialization information for the secure
 * processor.  This structure is implementation specific.
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_GetInstance(Sec_ProcessorHandle** secProcHandle,
        Sec_ProcessorInitParams* socInitParams);

/**
 * @brief Prints SOC specific version info
 *
 * @param secProcHandle secure processor handle
 */
Sec_Result SecProcessor_PrintInfo(Sec_ProcessorHandle* secProcHandle);

/**
 * @brief Obtain the device id
 *
 * @param secProcHandle secure processor handle
 * @param deviceId pointer to a buffer that is SEC_DEVICEID_LEN long.  The
 * buffer will be filled with a device id.
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_GetDeviceId(Sec_ProcessorHandle* secProcHandle,
        SEC_BYTE *deviceId);

/**
 * @brief Release the security processor
 *
 * @param secProcHandle secure processor handle
 *
 * @return The status of the operation
 */
Sec_Result SecProcessor_Release(Sec_ProcessorHandle* secProcHandle);

/**
 * @brief Initialize cipher object
 *
 * @param secProcHandle secure processor handle
 * @param algorithm cipher algorithm to use
 * @param mode cipher mode to use
 * @param key handle to use
 * @param iv initialization vector value.  Can be set to NULL is the cipher
 * algorithm chosen does not require it.
 * @param cipherHandle pointer to a cipher handle that will be set once
 * the cipher object is constructed
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, Sec_KeyHandle* key,
        SEC_BYTE* iv, Sec_CipherHandle** cipherHandle);

/**
 * @brief En/De-cipher specified input data into and output buffer
 *
 * @param cipherHandle cipher handle
 * @param input pointer to input data
 * @param inputSize the length of input data in bytes
 * @param lastInput boolean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer
 * @param outputSize the size of the output buffer
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_Process(Sec_CipherHandle* cipherHandle, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_BYTE* output, SEC_SIZE outputSize,
        SEC_SIZE *bytesWritten);

/**
 * @brief En/De-cipher specified fragmented input data into and output buffer
 *
 * @param cipherHandle cipher handle
 * @param input pointer to input data
 * @param inputSize the length of input data in bytes
 * @param lastInput boolean value specifying whether this is the last chunk
 * of input that will be processed.
 * @param output pointer to output data buffer
 * @param outputSize the size of the output buffer
 * @param bytesWritten pointer to a value that will be set to number
 * of bytes written to the output buffer
 * @param framentOffset offset in bytes of the fragment data within larger packet
 * @param fragmentSize length in bytes of the data fragment
 * @param fragmentPeriod the length in bytes of the packet containing the fragment
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_ProcessFragmented(Sec_CipherHandle* cipherHandle, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_BYTE* output, SEC_SIZE outputSize,
        SEC_SIZE *bytesWritten, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod);

/**
 * @brief Release the cipher object
 *
 * @param cipherHandle cipher handle
 *
 * @return The status of the operation
 */
Sec_Result SecCipher_Release(Sec_CipherHandle* cipherHandle);

/**
 * @brief Utility function for encrypting a single input buffer of data
 *
 * @param proc security processor handle
 * @param alg cipher algorithm to use
 * @param mode cipher mode
 * @param key key to use
 * @param iv Initialization Vector
 * @param input input buffer
 * @param input_len length of input data in bytes
 * @param output output buffer
 * @param output_len length of output buffer in bytes
 * @param written actual number of bytes written to the output buffer
 *
 * @return status of the operation
 */
Sec_Result SecCipher_SingleInput(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode,
        Sec_KeyHandle *key, SEC_BYTE *iv,
        SEC_BYTE *input, SEC_SIZE input_len,
        SEC_BYTE *output, SEC_SIZE output_len,
        SEC_SIZE *written);

/**
 * @brief Obtain a digest object handle
 *
 * @param secProcHandle secure processor handle
 * @param algorithm digest algorithm to use
 * @param digestHandle output digest object handle
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_DigestAlgorithm algorithm, Sec_DigestHandle** digestHandle);

/**
 * @brief Update the digest value with the specified input
 *
 * @param digestHandle handle of the digest object
 * @param input pointer to the input buffer
 * @param inputSize size of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_Update(Sec_DigestHandle* digestHandle, SEC_BYTE* input,
        SEC_SIZE inputSize);
/**
 * @brief Update the digest value with the key data
 *
 * @param digestHandle handle of the digest object
 * @param keyHandle key to use
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_UpdateWithKey(Sec_DigestHandle* digestHandle, Sec_KeyHandle *keyHandle);

/**
 * @brief Calculate the resulting digest value and release the digest object
 *
 * @param digestHandle digest handle
 * @param digestOutput pointer to an output buffer that will be filled with the resulting
 * digest value.  Buffer should be SEC_DIGEST_MAX_LEN bytes long.
 * @param digestSize pointer to a value that will be set to actual size of the digest value
 *
 * @return The status of the operation
 */
Sec_Result SecDigest_Release(Sec_DigestHandle* digestHandle,
        SEC_BYTE* digestOutput, SEC_SIZE* digestSize, SEC_BYTE* input,
        SEC_SIZE inputSize);

/**
 * @brief Utility function for calculating a digest value of a single input buffer
 *
 * @param proc secure processor handle
 * @param alg digest algorithm to use
 * @param input input data to calculate digest over
 * @param input_len size of input data in bytes
 * @param digest output buffer where the calculated digest value will be written
 * @param digest_len number of bytes written to the output digest buffer
 *
 * @return status of the operation
 */
Sec_Result SecDigest_SingleInput(Sec_ProcessorHandle *proc, Sec_DigestAlgorithm alg, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *digest, SEC_SIZE *digest_len);

/**
 * @brief Obtian a handle to the signature calculator
 *
 * @param secProcHandle secure processor handle
 * @param algorithm signing algorithm
 * @param mode signing mode
 * @param key key used for signing operations
 * @param signatureHandle output signature handle
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* key, Sec_SignatureHandle** signatureHandle);

/**
 * @brief Sign/Verify Signature of the input data
 *
 * @param signatureHandle signature handle
 * @param input pointer to the input buffer whose signature we are generating/verifying
 * @param inputSize the length of the input
 * @param signature buffer where signature is/will be stored
 * @param signatureSize output variable that will be set to the signature size
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_Process(Sec_SignatureHandle* signatureHandle,
        SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

/**
 * @brief Signature util that handles Sec_SignatureHandle generation and release
 *
 * @param secProcHandle processor handle
 * @param algorithm signing algorithm
 * @param mode signing mode
 * @param key key used for signing operations
 * @param input pointer to the input buffer whose signature we are generating/verifying
 * @param inputSize the length of the input
 * @param signature buffer where signature is/will be stored
 * @param signatureSize output variable that will be set to the signature size
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_SingleInput(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

/**
 * @brief Release the signature object
 *
 * @param signatureHandle cipher handle
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_Release(Sec_SignatureHandle* signatureHandle);

/**
 * @brief Obtain a handle for the MAC calculator
 *
 * @param secProcHandle secure processor handle
 * @param algorithm MAC algorithm to use for MAC calculation
 * @param key key to use for the MAC calculation
 * @param macHandle output MAC calculator handle
 *
 * @return The status of the operation
 */
Sec_Result SecMac_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_MacAlgorithm algorithm, Sec_KeyHandle* key,
        Sec_MacHandle** macHandle);

/**
 * @brief Updates the digest value with the input data
 *
 * @param macHandle mac handle
 * @param input pointer to the input data
 * @param size of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecMac_Update(Sec_MacHandle* macHandle, SEC_BYTE* input,
        SEC_SIZE inputSize);

/**
 * @brief Updates the digest value with the contents of a key
 *
 * @param macHandle mac handle
 * @param keyHandle key to use
 *
 * @return The status of the operation
 */
Sec_Result SecMac_UpdateWithKey(Sec_MacHandle* macHandle, Sec_KeyHandle *keyHandle);

/**
 * @brief Calculate the resulting MAC value and release the MAC object
 *
 * @param macHandle mac handle
 * @param macBuffer pointer to an output buffer that will be filled with the resulting
 * MAC value.  Buffer should be SEC_MAC_MAX_LEN bytes long.
 * @param macSize pointer to a value that will be set to actual size of the MAC value
 *
 * @return The status of the operation
 */
Sec_Result SecMac_Release(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer, SEC_SIZE* macSize);

/**
 * @brief Utility function for calculating a MAC value of a single input buffer
 *
 * @param proc secure processor handle
 * @param alg MAC algorithm to use
 * @param key key to use
 * @param input input data to calculate MAC over
 * @param input_len size of input data in bytes
 * @param mac output buffer where the calculated MAC value will be written
 * @param mac_len number of bytes written to the output MAC buffer
 *
 * @return status of the operation
 */
Sec_Result SecMac_SingleInput(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg, Sec_KeyHandle *key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac, SEC_SIZE *mac_len);

/**
 * @brief Obtain a handle to the random number generator
 *
 * @param secProcHandle secure processor handle
 * @param algorithm random number algorithm to use
 * @param randomHandle output handle for the random number generator
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_RandomAlgorithm algorithm, Sec_RandomHandle** randomHandle);

/**
 * @brief Generate random data
 *
 * @param randomHandle random number generator handle
 * @param output pointer to the output buffer where the random data will be stored
 * @param outpuSize the size of the output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_Process(Sec_RandomHandle* randomHandle, SEC_BYTE* output,
        SEC_SIZE outputSize);

/**
 * @brief Release the random object
 *
 * @param randomHandle random handle
 *
 * @return The status of the operation
 */
Sec_Result SecRandom_Release(Sec_RandomHandle* randomHandle);

/**
 * @brief Utility function for filling out a random value
 *
 * @param proc secure processor handle
 * @param alg random algorithm to use
 * @param output output buffer where the random value will be written
 * @param output_len number of bytes written to the output buffer
 *
 * @return status of the operation
 */
Sec_Result SecRandom_SingleInput(Sec_ProcessorHandle *proc,
        Sec_RandomAlgorithm alg, SEC_BYTE *output, SEC_SIZE output_len);

/**
 * @brief Obtain a handle to the provisioned certificate
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 * @param certHandle output certificate handle
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_CertificateHandle** certHandle);

/**
 * @brief Find if the certificate with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecCertificate_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief Provision a certificate onto the system
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate to provision
 * @param location location where the certificate should be provisioned to
 * @param data_type container type for the input certificate data
 * @param data pointer to certificate container data
 * @param data_len certificate container data length
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Provision(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location,
        Sec_CertificateContainer data_type, SEC_BYTE *data, SEC_SIZE data_len);

/**
 * @brief Delete the specified certificate from the system
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate to delete
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Delete(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief Extract the public key information from the certificate
 *
 * @param cert_handle certificate handle
 * @param public_key pointer to the output structure that will be filled with
 * public key data
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_ExtractPublicKey(Sec_CertificateHandle* cert_handle,
        Sec_RSARawPublicKey *public_key);

/**
 * @brief Verify certificate signature
 *
 * @param cert_handle certificate handle
 * @param key_handle handle of the private key used for signing or it's corresponding
 * public key
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Verify(Sec_CertificateHandle* cert_handle,
        Sec_KeyHandle* key_handle);

/**
 * @brief Verify certificate signature
 *
 * @param cert_handle certificate handle
 * @param public_key structure holding the public key information
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_VerifyWithRawPublicKey(Sec_CertificateHandle* cert_handle,
        Sec_RSARawPublicKey* public_key);

/**
 * @brief Obtain the certificate data in clear text DER format
 *
 * @param cert_handle certificate handle
 * @param buffer pointer to the output buffer that will be filled with certificate data
 * @param buffer_len the length of the output buffer
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Export(Sec_CertificateHandle* cert_handle,
        SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written);

/**
 * @brief Release the certificate object
 *
 * @param certificateHandle certificate handle
 *
 * @return The status of the operation
 */
Sec_Result SecCertificate_Release(Sec_CertificateHandle* certHandle);

/**
 * @brief finds the first available certificate id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecCertificate_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base, SEC_OBJECTID top);

/**
 * @brief Obtain the size of the certificate in DER format
 *
 * @param cert_handle certificate whose size we want to obtain
 */
SEC_SIZE SecCertificate_GetSize(Sec_CertificateHandle* cert_handle);

/**
 * @brief Obtain a list of all provisioned items.  At most maxNumItems will be written to the output buffer.
 *
 * @param proc Secure processor handle
 * @param items buffer that the found item ids will be stored in
 * @param maxNumItems maximum number of items that can be written to the output buffer
 *
 * @return number of items written
 */
SEC_SIZE SecCertificate_List(Sec_ProcessorHandle *proc, SEC_OBJECTID *items, SEC_SIZE maxNumItems);

/**
 * @brief Get the length of the specified key in bytes
 *
 * In case of symetric keys, the length returned is the actual size of the key data.
 * In case of asymetric keys, the length returned is the size of the modulus in bytes.
 *
 * @param keyHandle key handle
 *
 * @return The status of the operation
 */
SEC_SIZE SecKey_GetKeyLen(Sec_KeyHandle* keyHandle);

/**
 * @brief Get the key type of the specified key handle
 *
 * @param keyHandle key handle
 *
 * @return The status of the operation
 */
Sec_KeyType SecKey_GetKeyType(Sec_KeyHandle* keyHandle);

/**
 * @brief Obtain a handle to a provisioned key
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the provisioned key that we are attempting to abtain
 * @param keyHandle pointer to the output key handle
 *
 * @return The status of the operation
 */
Sec_Result SecKey_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_KeyHandle** keyHandle);

/**
 * @brief Find if the key with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecKey_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief Extract a public key from a specified private key handle
 *
 * @param key_handle handle of the private key
 * @param public_key pointer to the output structure containing the public rsa key
 *
 * @return The status of the operation
 */
Sec_Result SecKey_ExtractPublicKey(Sec_KeyHandle* key_handle,
        Sec_RSARawPublicKey *public_key);

/**
 * @brief Generate and provision a new key.
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the key to generate
 * @param keyType type of the key to generate
 * @param location location where the key should be stored
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Generate(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id,
        Sec_KeyType keyType, Sec_StorageLoc location);

/**
 * @brief Provision a key
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the key to provision
 * @param location storage location where the key should be provisioned
 * @param data_type type of input key container that is being used
 * @param data pointer to the input key container
 * @param data_len the size of the input key container
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Provision(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, Sec_KeyContainer data_type, SEC_BYTE *data,
        SEC_SIZE data_len);

/**
 * @brief Derive and provision a key using the HKDF algorithm
 *
 * @param secProcHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param macAlgorithm mac algorithm to use in the key derivation process
 * @param salt pointer to the salt value to use in key derivation process
 * @param saltSize the length of the salt buffer in bytes
 * @param info pointer to the info value to use in key derivation process
 * @param infoSize the length of the info buffer in bytes
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_HKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *salt, SEC_SIZE saltSize, SEC_BYTE *info, SEC_SIZE infoSize);

/**
 * @brief Derive and provision a key using the Concat KDF algorithm
 *
 * @param secProcHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param digestAlgorithm digest algorithm to use in the key derivation process
 * @param otherInfo pointer to the info value to use in key derivation process
 * @param otherInfoSize the length of the other info buffer in bytes
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_ConcatKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_DigestAlgorithm digestAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *otherInfo, SEC_SIZE otherInfoSize);

/**
 * @brief Derive and provision a key using the PBEKDF algorithm
 *
 * @param secProcHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param type_derived derived key type
 * @param loc_derived storage location where the derived key should be provisioned
 * @param macAlgorithm mac algorithm to use in the key derivation process
 * @param salt pointer to the salt value to use in key derivation process
 * @param saltSize the length of the salt buffer in bytes
 * @param numIterations number of iterations to use in the key derivation process
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_PBEKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *salt, SEC_SIZE saltSize, SEC_SIZE numIterations);

/**
 * @brief Derive and provision an AES 128-bit key a vendor specific key ladder algorithm.
 *
 * This function will generate a key derived from one of the OTP keys.  The
 * result of this function may not be usable in Digest and Mac _UpdateWithKey
 * functions.  In general, this function will keep the derived key more secure
 * then the other SecKey_Derive functions because the key will not be accessable
 * by the host even during the generation time.
 *
 * @param secProcHandle secure processor handle
 * @param object_id_derived id of the key to provision
 * @param loc_derived storage location where the derived key should be provisioned
 * @param input input buffer for the key derivation
 * @param input_len the length of the input buffer
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Derive_VendorAes128(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_StorageLoc loc_derived, SEC_BYTE *input, SEC_SIZE input_len);

/**
 * @brief Delete a provisioned key
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the key to delete
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Delete(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id);

/**
 * @brief Release the key object
 *
 * @param keyHandle key handle to release
 *
 * @return The status of the operation
 */
Sec_Result SecKey_Release(Sec_KeyHandle* keyHandle);

/**
 * @brief Obtain a digest value computed over the base key contents
 *
 * @param secProcHandle secure processor handle
 * @param nonce client nonce
 * @param alg digest algorithm
 * @param digest output digest value
 * @param digest_len the length of output digest value
 *
 * @return status of the operation
 */
Sec_Result SecKey_ComputeBaseKeyDigest(Sec_ProcessorHandle* secProcHandle, SEC_BYTE *nonce,
        Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len);

/**
 * @brief Obtain a digest value computed over a specified key
 *
 * @param proc secure processor handle
 * @param key_id key id
 * @param alg digest algorithm to use
 * @param digest output digest value
 * @param digest_len size of the written digest value
 * @return
 */
Sec_Result SecKey_ComputeKeyDigest(Sec_ProcessorHandle *proc, SEC_OBJECTID key_id,
        Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len);

/**
 * @brief finds the first available key id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecKey_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base, SEC_OBJECTID top);

/**
 * @brief Obtain a processor handle
 *
 * @param key key handle
 *
 * @return Processor handle
 */
Sec_ProcessorHandle* SecKey_GetProcessor(Sec_KeyHandle* key);

/**
 * @brief Obtain a handle to a provisioned bundle
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the provisioned bundle that we are attempting to abtain
 * @param bundleHandle pointer to the output key handle
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_BundleHandle** bundleHandle);

/**
 * @brief Find if the bundle with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecBundle_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief Provision a bundle
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the bundle to provision
 * @param location storage location where the bundle should be provisioned
 * @param data pointer to the input key container
 * @param data_len the size of the input key container
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Provision(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id,
        Sec_StorageLoc location, SEC_BYTE *data, SEC_SIZE data_len);

/**
 * @brief Delete a provisioned bundle
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the key to delete
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Delete(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id);

/**
 * @brief Release the bundle object
 *
 * @param bundleHandle bundle handle to release
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Release(Sec_BundleHandle* bundleHandle);

/**
 * @brief Obtain the bundle data
 *
 * @param bundle_handle bundle handle
 * @param buffer pointer to the output buffer that will be filled with bundle data
 * @param buffer_len the length of the output buffer
 * @param written pointer to the output value specifying the number of bytes written to the
 * output buffer
 *
 * @return The status of the operation
 */
Sec_Result SecBundle_Export(Sec_BundleHandle* bundle_handle,
        SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written);

/**
 * @brief finds the first available bundle id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecBundle_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
        SEC_OBJECTID top);

/**
 * log callback function
 */
typedef void (*SecApiLogCallback)(const char *fmt, ...);

/**
 * @brief set log callback function
 *
 * @param cb pointer to the logger function
 */
void Sec_SetLogger(SecApiLogCallback cb);

/**
 * @brief get the log callback function
 *
 * @return pointer to the logger function
 */
SecApiLogCallback Sec_GetLogger(void);

/**
 * @brief Get the type (msd byte) of the object id
 */
uint8_t SecKey_GetObjectType(SEC_OBJECTID object_id);

/**
 * @brief Get the logical name that corresponds to the object_id.  Returns empty string if
 * object_id has no logical name mapping
 */
const char* Sec_GetObjectUrn(SEC_OBJECTID object_id);

/**
 * @brief Get the object id that corresponds to the urn.  Returns SEC_OBJECTID_INVALID if urn
 * is unknown
 */
SEC_OBJECTID Sec_GetObjectId(const char* urn);

/**
 * @brief Allocate platform specific memory optimized for encryption/decryption.  Used
 * With SEC_CIPHERMODE_ENCRYPT_NATIVEMEM and SEC_CIPHERMODE_DECRYPT_NATIVEMEM
 */
SEC_BYTE* Sec_NativeMalloc(SEC_SIZE length);

/**
 * @brief Free memory allocated with Sec_NativeMalloc
 */
void Sec_NativeFree(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_H_ */
