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
 * @file sec_security_common.h
 *
 * @brief Common functions used by all platform implementations
 *
 */

#ifndef SEC_SECURITY_COMMON_H_
#define SEC_SECURITY_COMMON_H_

#include "sec_security.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Check whether the supplied key and iv are valid for the chosen cipher algorithm
 *
 * @param key_type key type
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param iv initialization vector
 *
 * @return status of the call
 */
Sec_Result SecCipher_IsValidKey(Sec_KeyType key_type,
        Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, SEC_BYTE *iv);

/**
 * @brief Check whether the supplied input and output buffers are of correct size for
 * the chosen cipher algorithm
 *
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param keyType key type
 * @param inputSize size of the input buffer
 * @param outputSize size of the output buffer
 * @param lastInput is this the last input to the cipher
 *
 * @return status of the call
 */
Sec_Result SecCipher_CheckInputOutputSizes(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize, SEC_SIZE outputSize,
        SEC_BOOL lastInput);


/**
 * @brief Check whether the supplied input and output buffers are of correct size for
 * the chosen cipher algorithm and fragmented mode of operation
 *
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param keyType key type
 * @param inputSize size of the input buffer
 * @param outputSize size of the output buffer
 * @param lastInput is this the last input to the cipher
 * @param framentOffset offset in bytes of the fragment data within larger packet
 * @param fragmentSize length in bytes of the data fragment
 * @param fragmentPeriod the length in bytes of the packet containing the fragment
 *
 * @return status of the call
 */
Sec_Result SecCipher_CheckFragmentedInputOutputSizes(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
        SEC_SIZE outputSize, SEC_BOOL lastInput, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod);

/**
 * @brief Apply PKCS7 padding to the AES input block
 *
 * @param inputBlock input data to pad
 * @param inputSize size of input data
 * @param outputBlock Output block.  Has to be the size of SEC_AES_BLOCKSIZE
 */
void SecCipher_PadAESPKCS7Block(SEC_BYTE *inputBlock, SEC_SIZE inputSize,
        SEC_BYTE *outputBlock);

/**
 * @brief Checks whether the specified cipher algorithm is AES
 */
SEC_BOOL SecCipher_IsAES(Sec_CipherAlgorithm alg);

/**
 * @brief Checks whether the specified cipher algorithm is RSA
 */
SEC_BOOL SecCipher_IsRsa(Sec_CipherAlgorithm alg);

Sec_Result SecCipher_SingleInputId(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_OBJECTID key,
        SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
        SEC_SIZE output_len, SEC_SIZE *written);

/**
 * @brief Checks whether the passed in key is valid for a chosen signing algorithm and mode
 *
 * @param key_type key type
 * @param algorithm signing algorithm
 * @param mode signing mode
 *
 * @return status of the operation
 */
Sec_Result SecSignature_IsValidKey(Sec_KeyType key_type,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode);

/**
 * @brief Obtain a digest algorithm used by a specific signing algorithm
 *
 * @param alg signing algorithm
 *
 * @return digest algorithm used
 */
Sec_DigestAlgorithm SecSignature_GetDigestAlgorithm(Sec_SignatureAlgorithm alg);

/**
 * @brief Check whether the passed in key type is valid for a chosen MAC algorithm
 *
 * @param key_type key type
 * @param algorithm MAC algorithm
 *
 * @return status of the operation
 */
Sec_Result SecMac_IsValidKey(Sec_KeyType key_type, Sec_MacAlgorithm algorithm);

/**
 * @brief Obtain a digest algorithm used by a specified MAC algorithm
 *
 * @param alg MAC algorithm
 *
 * @return digest algorithm used
 */
Sec_DigestAlgorithm SecMac_GetDigestAlgorithm(Sec_MacAlgorithm alg);

Sec_Result SecMac_SingleInputId(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
        SEC_OBJECTID key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
        SEC_SIZE *mac_len);

/**
 * @brief Checks if a passed in key type is symetric.
 *
 * @param type key type
 *
 * @return 1 if key type is symetric, 0 if asymetric
 */
SEC_BOOL SecKey_IsSymetric(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is an AES key.
 *
 * @param type key type
 *
 * @return 1 if key type is AES, 0 if not
 */
SEC_BOOL SecKey_IsAES(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsRsa(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is pub Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is pub rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsPubRsa(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is priv Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is priv rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsPrivRsa(Sec_KeyType type);

/**
 * @brief Obtain a key length in bytes for a specified key type.
 *
 * For symetric keys, the return value will be the actual key size.  For asymetric keys
 * the return value will be the modulus size.
 *
 * @param keyType key type
 *
 * @return key size
 */
SEC_SIZE SecKey_GetKeyLenForKeyType(Sec_KeyType keyType);

/**
 * @brief Is the specified container a raw (clear) container
 */
SEC_BOOL SecKey_IsClearKeyContainer(Sec_KeyContainer kct);

/**
 * @brief Obtain the size of the digest for a specified digest algorithm
 *
 * @param alg digest algorithm
 *
 * @return digest size in bytes
 */
SEC_SIZE SecDigest_GetDigestLenForAlgorithm(Sec_DigestAlgorithm alg);

/**
 * @brief compute inputs for the base key ladder
 */
Sec_Result SecKey_ComputeBaseKeyLadderInputs(Sec_ProcessorHandle *secProcHandle,
        const char *inputDerivationStr, const char *cipherAlgorithmStr,
        SEC_BYTE *nonce, Sec_DigestAlgorithm digestAlgorithm, SEC_SIZE inputSize,
        SEC_BYTE *c1, SEC_BYTE *c2, SEC_BYTE *c3, SEC_BYTE *c4);

/**
 * @brief Check if provided algorithm takes digest as an input
 */
SEC_BOOL SecSignature_IsDigest(Sec_SignatureAlgorithm alg);

/**
 * @brief default logger implementation (stdout)
 */
void Sec_DefaultLogCb(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_COMMON_H_ */
