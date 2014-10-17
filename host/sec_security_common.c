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

#include "sec_security_common.h"
#include "sec_security_utils.h"
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

typedef struct
{
    SEC_OBJECTID object_id;
    const char* urn;
} Sec_ObjUrn;

SecApiLogCallback g_sec_logcb = Sec_DefaultLogCb;

Sec_ObjUrn g_sec_obj_urns[] = {
    { SEC_OBJECTID_COMCAST_SGNCERT, "comcast:xcal:sgnCert" },
    { SEC_OBJECTID_COMCAST_SGNSUBCACERT, "comcast:xcal:sgnSubCaCert" },
    { SEC_OBJECTID_COMCAST_SGNROOTCACERT, "comcast:xcal:sgnRootCaCert"},
    { SEC_OBJECTID_COMCAST_ENCCERT, "comcast:xcal:encCert" },
    { SEC_OBJECTID_COMCAST_ENCSUBCACERT, "comcast:xcal:encSubCaCert"},
    { SEC_OBJECTID_COMCAST_ENCROOTCACERT, "comcast:xcal:encRootCaCert"},
    { SEC_OBJECTID_COMCAST_TLSCERT, "comcast:xcal:tlsCert"},
    { SEC_OBJECTID_COMCAST_TLSSUBCACERT, "comcast:xcal:tlsCert"},
    { SEC_OBJECTID_COMCAST_TLSROOTCACERT, "comcast:xcal:tlsRootCaCert"},
    { SEC_OBJECTID_COMCAST_CERTCA01CERT, "comcast:xcal:certCa01Cert"},
    { SEC_OBJECTID_COMCAST_STATUSCA01CERT, "comcast:xcal:statusCa01Cert"},
    { SEC_OBJECTID_COMCAST_SGNKEY, "comcast:xcal:sgnKey"},
    { SEC_OBJECTID_COMCAST_ENCKEY, "comcast:xcal:encKey"},
    { SEC_OBJECTID_COMCAST_TLSKEY, "comcast:xcal:tlsKey"},
    { SEC_OBJECTID_COMCAST_PKIBUNDLE, "comcast:xcal:pkiBundle"},
    { SEC_OBJECTID_COMCAST_HASHLOCKED, "comcast:xcal:hashLock"},
    { SEC_OBJECTID_ADOBE_DRMMODELKEY, "adobe:flashAccess:drmModelKey"},
    { SEC_OBJECTID_ADOBE_DRMMODELCERT, "adobe:flashAccess:drmModelCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:drmModelIntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELINTERMEDIATECACERT, "adobe:flashAccess:drmModelIntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_DRMMODELROOTCACERT, "adobe:flashAccess:drmModelRootCaCert"},
    { SEC_OBJECTID_ADOBE_SD01CERT, "adobe:flashAccess:sd01Cert"},
    { SEC_OBJECTID_ADOBE_SD01INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd01IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD01INTERMEDIATECACERT, "adobe:flashAccess:sd01IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD01ROOTCACERT, "adobe:flashAccess:sd01RootCaCert"},
    { SEC_OBJECTID_ADOBE_SD02CERT, "adobe:flashAccess:sd02Cert"},
    { SEC_OBJECTID_ADOBE_SD02INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd02IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD02INTERMEDIATECACERT, "adobe:flashAccess:sd02IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD02ROOTCACERT, "adobe:flashAccess:sd02RootCaCert"},
    { SEC_OBJECTID_ADOBE_SD03CERT, "adobe:flashAccess:sd03Cert"},
    { SEC_OBJECTID_ADOBE_SD03INTERMEDIATERUNTIMEDRMCACERT, "adobe:flashAccess:sd03IntermediateRuntimeDrmCaCert"},
    { SEC_OBJECTID_ADOBE_SD03INTERMEDIATECACERT, "adobe:flashAccess:sd03IntermediateCaCert"},
    { SEC_OBJECTID_ADOBE_SD03ROOTCACERT, "adobe:flashAccess:sd03RootCaCert"},
    { SEC_OBJECTID_ADOBE_INDIVTRANSPORTCERT, "adobe:flashAccess:indivTransportCert"},
    { SEC_OBJECTID_ADOBE_SD01KEY, "adobe:flashAccess:sd01Key"},
    { SEC_OBJECTID_ADOBE_SD02KEY, "adobe:flashAccess:sd02Key"},
    { SEC_OBJECTID_ADOBE_SD03KEY, "adobe:flashAccess:sd03Key"},
    { SEC_OBJECTID_ADOBE_PRODADOBEROOTDIGEST, "adobe:flashAccess:prodAdobeRootDigest"},
    { SEC_OBJECTID_ADOBE_DRMPKI, "adobe:flashAccess:drmPkiBundle" },
    { SEC_OBJECTID_INVALID, "" }
};

#if !defined(OPTEE_DEMO)
Sec_Result SecCipher_IsValidKey(Sec_KeyType key_type,
        Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, SEC_BYTE *iv)
{
    switch (algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
            if (SecKey_IsAES(key_type))
            {
                if (iv == NULL
                        && algorithm != SEC_CIPHERALGORITHM_AES_CTR
                        && algorithm != SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING
                        && algorithm != SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING)
                {
                    SEC_LOG_ERROR("IV cannot be null in CBC and CTR modes.");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            }
            else
            {
                SEC_LOG_ERROR("Not an AES key");
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            if (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM)
            {
                if (!SecKey_IsRsa(key_type))
                {
                    SEC_LOG_ERROR("Not an RSA key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            }
            else if (mode == SEC_CIPHERMODE_DECRYPT || mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM)
            {
                if (!SecKey_IsPrivRsa(key_type))
                {
                    SEC_LOG_ERROR("Not an RSA key");
                    return SEC_RESULT_FAILURE;
                }

                return SEC_RESULT_SUCCESS;
            }
            else
            {
                SEC_LOG_ERROR(
                        "Unknown cipher mode encountered: %d", mode);
                return SEC_RESULT_FAILURE;
            }
            break;

            /* NEW: add new key types and cipher algorithms */
        default:
            break;
    }

    SEC_LOG_ERROR("Unimplemented algorithm");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_CheckInputOutputSizes(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
        SEC_SIZE outputSize, SEC_BOOL lastInput)
{
    SEC_SIZE maxClearSize = 0;
    SEC_SIZE outputSizeNeeded = 0;
    SEC_SIZE rsa_block_size = 0;

    if (inputSize <= 0)
    {
        SEC_LOG_ERROR("Empty input is not allowed");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    switch (algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
            if (inputSize % SEC_AES_BLOCK_SIZE != 0)
            {
                SEC_LOG_ERROR("Input size is not a multiple of block size");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            outputSizeNeeded = inputSize;
            if (outputSize < outputSizeNeeded)
            {
                SEC_LOG_ERROR("Output buffer is too small");
                return SEC_RESULT_BUFFER_TOO_SMALL;
            }
            break;

        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            if ((mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM)
                    && !lastInput
                    && inputSize % SEC_AES_BLOCK_SIZE != 0)
            {
                SEC_LOG_ERROR(
                        "Encryption input size is not a multiple of block size and is not last input");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            if ((mode == SEC_CIPHERMODE_DECRYPT || mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM)
                    && inputSize % SEC_AES_BLOCK_SIZE != 0)
            {
                SEC_LOG_ERROR(
                        "Decryption input size is not a multiple of block size");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            outputSizeNeeded = (inputSize / 16) * 16
                    + ((lastInput && (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM)) ? 16 : 0);
            if (outputSize < outputSizeNeeded)
            {
                SEC_LOG_ERROR("Output buffer is too small");
                return SEC_RESULT_BUFFER_TOO_SMALL;
            }
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            rsa_block_size = outputSizeNeeded = SecKey_GetKeyLenForKeyType(
                    keyType);

            if (algorithm == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING)
            {
                maxClearSize = rsa_block_size - 41;
            }
            else
            {
                maxClearSize = rsa_block_size - 11;
            }

            if ((mode == SEC_CIPHERMODE_DECRYPT || mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM) && inputSize != rsa_block_size)
            {
                SEC_LOG_ERROR(
                        "Decrypt input size is not equal to the RSA block size");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }
            else if ((mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) && inputSize > maxClearSize)
            {
                SEC_LOG_ERROR( "Encrypt input size is too large");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }

            if (outputSize < outputSizeNeeded)
            {
                SEC_LOG_ERROR("Output buffer is too small");
                return SEC_RESULT_BUFFER_TOO_SMALL;
            }
            break;

            /* NEW: other cipher algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_CheckFragmentedInputOutputSizes(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
        SEC_SIZE outputSize, SEC_BOOL lastInput, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod)
{
    SEC_SIZE outputSizeNeeded = 0;

    if (inputSize <= 0)
    {
        SEC_LOG_ERROR("Empty input is not allowed");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    if ((inputSize % fragmentPeriod) != 0)
    {
        SEC_LOG_ERROR("Input size is not a multiple of a fragment period");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    if ((fragmentSize % SEC_AES_BLOCK_SIZE) != 0)
    {
        SEC_LOG_ERROR("fragment size is not a multiple of block size");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    if ((fragmentOffset + fragmentSize) > fragmentPeriod)
    {
        SEC_LOG_ERROR("Invalid fragment parameters");
        return SEC_RESULT_INVALID_INPUT_SIZE;
    }

    switch (algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            outputSizeNeeded = inputSize;
            if (outputSize < outputSizeNeeded)
            {
                SEC_LOG_ERROR("Output buffer is too small");
                return SEC_RESULT_BUFFER_TOO_SMALL;
            }
            break;

            /* NEW: other cipher algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

void SecCipher_PadAESPKCS7Block(SEC_BYTE *inputBlock, SEC_SIZE inputSize,
        SEC_BYTE *outputBlock)
{
    SEC_BYTE pad_val = (SEC_BYTE) (SEC_AES_BLOCK_SIZE
            - inputSize % SEC_AES_BLOCK_SIZE);

    memset(outputBlock, pad_val, SEC_AES_BLOCK_SIZE);
    memcpy(outputBlock, inputBlock, inputSize % SEC_AES_BLOCK_SIZE);
}

Sec_Result SecCipher_SingleInput(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, Sec_KeyHandle *key,
        SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
        SEC_SIZE output_len, SEC_SIZE *written)
{
    Sec_Result res;
    Sec_CipherHandle *cipher_handle = NULL;

    res = SecCipher_GetInstance(proc, alg, mode, key, iv, &cipher_handle);
    if (res != SEC_RESULT_SUCCESS)
        return res;

    res = SecCipher_Process(cipher_handle, input, input_len, 1, output,
            output_len, written);
    SecCipher_Release(cipher_handle);

    return res;
}

Sec_Result SecCipher_SingleInputId(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_OBJECTID key,
        SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
        SEC_SIZE output_len, SEC_SIZE *written)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Sec_KeyHandle *key_handle = NULL;

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, key, &key_handle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }

    res = SecCipher_SingleInput(proc, alg, mode, key_handle, iv, input, input_len, output, output_len, written);

done:
    if (key_handle != NULL)
        SecKey_Release(key_handle);

    return res;
}

SEC_BOOL SecCipher_IsAES(Sec_CipherAlgorithm alg)
{
    return alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING
            || alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING
            || alg == SEC_CIPHERALGORITHM_AES_CTR
            || alg == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING
            || alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
}

SEC_BOOL SecCipher_IsRsa(Sec_CipherAlgorithm alg)
{
    return alg == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING
            || alg == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
}

Sec_DigestAlgorithm SecSignature_GetDigestAlgorithm(Sec_SignatureAlgorithm alg)
{
    switch (alg)
    {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
            return SEC_DIGESTALGORITHM_SHA1;
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
            return SEC_DIGESTALGORITHM_SHA256;
        default:
            break;
    }

    return SEC_DIGESTALGORITHM_NUM;
}

Sec_Result SecSignature_IsValidKey(Sec_KeyType key_type,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode)
{
    switch (algorithm)
    {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
            if (mode == SEC_SIGNATUREMODE_SIGN)
            {
                if (key_type == SEC_KEYTYPE_RSA_1024
                        || key_type == SEC_KEYTYPE_RSA_2048)
                    return SEC_RESULT_SUCCESS;
                else
                    return SEC_RESULT_FAILURE;
            }
            else
            {
                if (key_type == SEC_KEYTYPE_RSA_1024
                        || key_type == SEC_KEYTYPE_RSA_2048
                        || key_type == SEC_KEYTYPE_RSA_1024_PUBLIC
                        || key_type == SEC_KEYTYPE_RSA_2048_PUBLIC)
                    return SEC_RESULT_SUCCESS;
                else
                    return SEC_RESULT_FAILURE;
            }
            break;

            /* NEW: add new key types and signature algorithms */
        default:
            break;
    }

    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecSignature_SingleInput(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Sec_SignatureHandle *sig = NULL;

    if (SEC_RESULT_SUCCESS != SecSignature_GetInstance(secProcHandle, algorithm, mode, key, &sig))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecSignature_Process(sig, input, inputSize, signature, signatureSize))
    {
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

    done:
    if (sig != NULL)
        SecSignature_Release(sig);

    return res;
}

SEC_BOOL SecSignature_IsDigest(Sec_SignatureAlgorithm alg)
{
    return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
            || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST;
}

Sec_Result SecMac_IsValidKey(Sec_KeyType key_type, Sec_MacAlgorithm algorithm)
{
    switch (algorithm)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            if (key_type == SEC_KEYTYPE_HMAC_256
                    || key_type == SEC_KEYTYPE_HMAC_160
                    || key_type == SEC_KEYTYPE_HMAC_128)
            {
                return SEC_RESULT_SUCCESS;
            }
            else
            {
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            if (key_type == SEC_KEYTYPE_AES_128
                    || key_type == SEC_KEYTYPE_AES_256)
            {
                return SEC_RESULT_SUCCESS;
            }
            else
            {
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            break;
    }

    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_DigestAlgorithm SecMac_GetDigestAlgorithm(Sec_MacAlgorithm alg)
{
    switch (alg)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
            return SEC_DIGESTALGORITHM_SHA1;
        case SEC_MACALGORITHM_HMAC_SHA256:
            return SEC_DIGESTALGORITHM_SHA256;
        case SEC_MACALGORITHM_CMAC_AES_128:
        default:
            break;
    }

    return SEC_DIGESTALGORITHM_NUM;
}

Sec_Result SecMac_SingleInput(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
        Sec_KeyHandle *key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
        SEC_SIZE *mac_len)
{
    Sec_Result res;
    Sec_MacHandle *mac_handle = NULL;

    res = SecMac_GetInstance(proc, alg, key, &mac_handle);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecMac_GetInstance failed");
        return res;
    }

    res = SecMac_Update(mac_handle, input, input_len);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecMac_Update failed");
        SecMac_Release(mac_handle, mac, mac_len);
        return res;
    }

    res = SecMac_Release(mac_handle, mac, mac_len);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecMac_Update failed");
        return res;
    }

    return res;
}

Sec_Result SecMac_SingleInputId(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
        SEC_OBJECTID key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
        SEC_SIZE *mac_len)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Sec_KeyHandle *key_handle = NULL;

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, key, &key_handle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }

    res = SecMac_SingleInput(proc, alg, key_handle, input, input_len, mac, mac_len);

done:
    if (key_handle != NULL)
        SecKey_Release(key_handle);

    return res;
}

SEC_SIZE SecKey_GetKeyLenForKeyType(Sec_KeyType keyType)
{
    switch (keyType)
    {
        case SEC_KEYTYPE_AES_128:
            return 16;
        case SEC_KEYTYPE_AES_256:
            return 32;
        case SEC_KEYTYPE_HMAC_128:
            return 16;
        case SEC_KEYTYPE_HMAC_160:
            return 20;
        case SEC_KEYTYPE_HMAC_256:
            return 32;
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
            return 128;
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return 256;

            /* NEW: add new key types here */
        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsSymetric(Sec_KeyType type)
{
    switch (type)
    {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            return 1;

        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsAES(Sec_KeyType type)
{
    switch (type)
    {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
            return 1;

        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsRsa(Sec_KeyType type)
{
    switch (type)
    {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return 1;

        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsPubRsa(Sec_KeyType type)
{
    switch (type)
    {
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return 1;

        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsPrivRsa(Sec_KeyType type)
{
    switch (type)
    {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
            return 1;

        default:
            break;
    }

    return 0;
}

SEC_BOOL SecKey_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id)
{
    Sec_KeyHandle *key;

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(secProcHandle, object_id, &key))
    {
        return 0;
    }

    SecKey_Release(key);
    return 1;
}

SEC_OBJECTID SecKey_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
        SEC_OBJECTID top)
{
    SEC_OBJECTID id;
    Sec_KeyHandle *key_handle;
    Sec_Result res;

    for (id = base; id < top; ++id)
    {
        res = SecKey_GetInstance(proc, id, &key_handle);
        if (SEC_RESULT_SUCCESS == res)
            SecKey_Release(key_handle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}

SEC_BYTE SecKey_GetObjectType(SEC_OBJECTID object_id)
{
    return (SEC_BYTE) ((object_id & 0xff00000000000000ULL) >> 56);
}

Sec_Result SecKey_ComputeKeyDigest(Sec_ProcessorHandle *proc, SEC_OBJECTID key_id,
        Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len)
{
    Sec_KeyHandle *key_handle = NULL;
    Sec_DigestHandle *digest_handle = NULL;
    Sec_Result res;

    CHECK_EXACT(SecKey_GetInstance(proc, key_id, &key_handle),
            SEC_RESULT_SUCCESS, error);

    CHECK_EXACT( SecDigest_GetInstance(proc, alg, &digest_handle),
            SEC_RESULT_SUCCESS, error);

    CHECK_EXACT( SecDigest_UpdateWithKey(digest_handle, key_handle),
            SEC_RESULT_SUCCESS, error);

    SecKey_Release(key_handle);
    res = SecDigest_Release(digest_handle, digest, digest_len);
    digest_handle = NULL;

    return res;

    error:
    if (key_handle != NULL)
        SecKey_Release(key_handle);
    if (digest_handle != NULL )
        SecDigest_Release(digest_handle, digest, digest_len);

    return SEC_RESULT_FAILURE;
}

Sec_Result SecKey_ComputeBaseKeyLadderInputs(Sec_ProcessorHandle *secProcHandle,
        const char *inputDerivationStr, const char *cipherAlgorithmStr,
        SEC_BYTE *nonce, Sec_DigestAlgorithm digestAlgorithm, SEC_SIZE inputSize,
        SEC_BYTE *c1, SEC_BYTE *c2, SEC_BYTE *c3, SEC_BYTE *c4)
{
    int i;
    SEC_BYTE loop[] = { 0, 0, 0, 0 };
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;
    Sec_Result res = SEC_RESULT_FAILURE;
    SEC_BYTE *c[4] = { c1, c2, c3, c4 };
    Sec_Buffer inputBuffer;
    SEC_SIZE bufferLen;

    if (inputSize > SecDigest_GetDigestLenForAlgorithm(digestAlgorithm))
    {
        SEC_LOG_ERROR("Invalid input size for specified digest algorithm");
        return SEC_RESULT_FAILURE;
    }

    bufferLen = SEC_NONCE_LEN + strlen(inputDerivationStr) + strlen(cipherAlgorithmStr) + sizeof(loop);
    SecUtils_BufferInit(&inputBuffer, malloc(bufferLen), bufferLen);
    if (NULL == inputBuffer.base)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    for (i = 1; i <= 4; i++)
    {
        loop[3] = i;

        SecUtils_BufferReset(&inputBuffer);

        CHECK_EXACT(
                SecUtils_BufferWrite(&inputBuffer, nonce, SEC_NONCE_LEN),
                SEC_RESULT_SUCCESS, done);

        CHECK_EXACT(
                SecUtils_BufferWrite(&inputBuffer, (SEC_BYTE *) inputDerivationStr, strlen(inputDerivationStr)),
                SEC_RESULT_SUCCESS, done);

        CHECK_EXACT(
                SecUtils_BufferWrite(&inputBuffer, (SEC_BYTE *) cipherAlgorithmStr, strlen(cipherAlgorithmStr)),
                SEC_RESULT_SUCCESS, done);

        CHECK_EXACT(SecUtils_BufferWrite(&inputBuffer, loop, sizeof(loop)),
                SEC_RESULT_SUCCESS, done);

        res = SecDigest_SingleInput(secProcHandle, digestAlgorithm, inputBuffer.base, inputBuffer.written,
                digest, &digest_len);
        if (SEC_RESULT_SUCCESS != res)
            goto done;

        memcpy(c[i-1], digest, inputSize);
    }

done:
    SEC_FREE(inputBuffer.base);
    return res;
}

SEC_BOOL SecKey_IsClearKeyContainer(Sec_KeyContainer kct)
{
    switch (kct)
    {
        case SEC_KEYCONTAINER_RAW_AES_128:
        case SEC_KEYCONTAINER_RAW_AES_256:
        case SEC_KEYCONTAINER_RAW_HMAC_128:
        case SEC_KEYCONTAINER_RAW_HMAC_160:
        case SEC_KEYCONTAINER_RAW_HMAC_256:
        case SEC_KEYCONTAINER_RAW_RSA_1024:
        case SEC_KEYCONTAINER_RAW_RSA_2048:
        case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_1024:
        case SEC_KEYCONTAINER_PEM_RSA_2048:
        case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
        case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
            return SEC_TRUE;
            break;

        default:
            break;
    }

    return SEC_FALSE;
}

SEC_BOOL SecCertificate_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id)
{
    Sec_CertificateHandle *cert;

    if (SEC_RESULT_SUCCESS != SecCertificate_GetInstance(secProcHandle, object_id, &cert))
    {
        return 0;
    }

    SecCertificate_Release(cert);
    return 1;
}

SEC_SIZE SecCertificate_GetSize(Sec_CertificateHandle* cert_handle)
{
    SEC_BYTE buffer[SEC_CERT_MAX_DATA_LEN];
    SEC_SIZE written;

    if (SEC_RESULT_SUCCESS != SecCertificate_Export(cert_handle, buffer, sizeof(buffer), &written))
    {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return 0;
    }

    return written;
}

SEC_OBJECTID SecCertificate_ObtainFreeObjectId(Sec_ProcessorHandle *proc,
        SEC_OBJECTID base, SEC_OBJECTID top)
{
    SEC_OBJECTID id;
    Sec_CertificateHandle *cert_handle;
    Sec_Result res;

    for (id = base; id < top; ++id)
    {
        res = SecCertificate_GetInstance(proc, id, &cert_handle);

        if (SEC_RESULT_SUCCESS == res)
            SecCertificate_Release(cert_handle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}

SEC_SIZE SecDigest_GetDigestLenForAlgorithm(Sec_DigestAlgorithm alg)
{
    switch (alg)
    {
        case SEC_DIGESTALGORITHM_SHA1:
            return 20;

        case SEC_DIGESTALGORITHM_SHA256:
            return 32;

        default:
            break;
    }

    return 0;
}

Sec_Result SecDigest_SingleInput(Sec_ProcessorHandle *proc,
        Sec_DigestAlgorithm alg, SEC_BYTE *input, SEC_SIZE input_len,
        SEC_BYTE *digest, SEC_SIZE *digest_len)
{
    Sec_Result res;
    Sec_DigestHandle *digest_handle = NULL;

    res = SecDigest_GetInstance(proc, alg, &digest_handle);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecDigest_GetInstance failed");
        return res;
    }

    res = SecDigest_Update(digest_handle, input, input_len);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecDigest_Update failed");
        SecDigest_Release(digest_handle, digest, digest_len);
        return res;
    }

    return SecDigest_Release(digest_handle, digest, digest_len);
}

Sec_Result SecRandom_SingleInput(Sec_ProcessorHandle *proc,
        Sec_RandomAlgorithm alg, SEC_BYTE *output, SEC_SIZE output_len)
{
    Sec_Result res;
    Sec_RandomHandle *random_handle = NULL;

    res = SecRandom_GetInstance(proc, alg, &random_handle);
    if (res != SEC_RESULT_SUCCESS)
        return res;

    res = SecRandom_Process(random_handle, output, output_len);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecRandom_Process failed");
        return res;
    }

    SecRandom_Release(random_handle);

    return res;
}

SEC_BOOL SecBundle_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id)
{
    Sec_BundleHandle *bundle;

    if (SEC_RESULT_SUCCESS != SecBundle_GetInstance(secProcHandle, object_id, &bundle))
    {
        return 0;
    }

    SecBundle_Release(bundle);
    return 1;
}

SEC_OBJECTID SecBundle_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
        SEC_OBJECTID top)
{
    SEC_OBJECTID id;
    Sec_BundleHandle *bundle_handle;
    Sec_Result res;

    for (id = base; id < top; ++id)
    {
        res = SecBundle_GetInstance(proc, id, &bundle_handle);
        if (SEC_RESULT_SUCCESS == res)
            SecBundle_Release(bundle_handle);
        else
            return id;
    }

    return SEC_OBJECTID_INVALID;
}

void Sec_SetLogger(SecApiLogCallback cb)
{
    g_sec_logcb = cb;
}
#endif

SecApiLogCallback Sec_GetLogger(void)
{
    return g_sec_logcb;
}

void Sec_DefaultLogCb(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end (args);

    fflush(stdout);
}
#if !defined(OPTEE_DEMO)

const char* Sec_GetObjectUrn(SEC_OBJECTID object_id)
{
    Sec_ObjUrn* ptr = &g_sec_obj_urns[0];

    while (ptr->object_id != SEC_OBJECTID_INVALID)
    {
        if (ptr->object_id == object_id)
            return ptr->urn;
    }

    return "";
}

SEC_OBJECTID Sec_GetObjectId(const char* urn)
{
    Sec_ObjUrn* ptr = &g_sec_obj_urns[0];

    while (ptr->object_id != SEC_OBJECTID_INVALID)
    {
        if (strcmp(urn, ptr->urn) == 0)
            return ptr->object_id;
    }

    return SEC_OBJECTID_INVALID;
}
#endif
