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

/*
 * OpenSSL implementation of the Comcast Security API.
 *
 * This implementation does not provide any real protection of the key material.  It only
 * simulates the protection using a Key Wrapping Key stored in a global variable.  This
 * implementation should be used in development environment only and never in the field!
 *
 */

#include "sec_security_openssl.h"
#include "sec_security_utils.h"
#include "sec_security_common.h"
#include "comcast_crypto_gp_client.h"
#include <stdlib.h>
#include <string.h>
#if !defined(OPTEE_DEMO)
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#endif

#define CHECK_HANDLE(handle) \
    if (NULL == handle) { \
        SEC_LOG_ERROR("Invalid handle"); \
        return SEC_RESULT_INVALID_HANDLE; \
    }

#define CHECK_EXACT(call, value, label) \
    if ((call) != value) \
    { \
        SEC_LOG_ERROR(#call " returned error"); \
        goto label; \
    }

#define SEC_KEYSTORAGE_FILE_DEFAULT_DIR "/tmp/sec_key/file"
#define SEC_CERTIFICATESTORAGE_FILE_DEFAULT_DIR "/tmp/sec_cert/file"
#define SEC_BUNDLESTORAGE_FILE_DEFAULT_DIR "/tmp/sec_bundle/file"

SEC_SIZE g_sec_security_num_processors = 0;

#if !defined(OPTEE_DEMO)
int SecOpenSSL_DisablePassphrasePrompt(char *buf, int size, int rwflag, void *u)
{
    return 0;
}

Sec_Result _Sec_SignCertificateData(Sec_ProcessorHandle *proc,
        _Sec_CertificateData *cert_store)
{
    Sec_KeyHandle *keyHandle = NULL;
    Sec_MacHandle *macHandle = NULL;
    SEC_SIZE macSize;

    CHECK_HANDLE(proc);

    CHECK_EXACT(SecKey_GetInstance(proc, SEC_OBJECTID_CERTSTORE_KEY, &keyHandle),
            SEC_RESULT_SUCCESS, error);
    CHECK_EXACT(
            SecMac_GetInstance(proc, SEC_MACALGORITHM_HMAC_SHA256, keyHandle, &macHandle),
            SEC_RESULT_SUCCESS, error);
    CHECK_EXACT(
            SecMac_Update(macHandle, cert_store->cert, cert_store->cert_len),
            SEC_RESULT_SUCCESS, error);
    SecMac_Release(macHandle, cert_store->mac, &macSize);
    macHandle = NULL;
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    return SEC_RESULT_SUCCESS;

    error: if (macHandle != NULL )
        SecMac_Release(macHandle, cert_store->mac, &macSize);
    if (keyHandle != NULL )
        SecKey_Release(keyHandle);

    return SEC_RESULT_FAILURE;
}

Sec_Result _Sec_ValidateCertificateData(Sec_ProcessorHandle *proc,
        _Sec_CertificateData *cert_store)
{
    Sec_KeyHandle *keyHandle = NULL;
    Sec_MacHandle *macHandle = NULL;
    SEC_BYTE macBuffer[SEC_MAC_MAX_LEN];
    SEC_SIZE macSize = 0;

    CHECK_HANDLE(proc);

    CHECK_EXACT(SecKey_GetInstance(proc, SEC_OBJECTID_CERTSTORE_KEY, &keyHandle),
            SEC_RESULT_SUCCESS, error);
    CHECK_EXACT(
            SecMac_GetInstance(proc, SEC_MACALGORITHM_HMAC_SHA256, keyHandle, &macHandle),
            SEC_RESULT_SUCCESS, error);
    CHECK_EXACT(
            SecMac_Update(macHandle, cert_store->cert, cert_store->cert_len),
            SEC_RESULT_SUCCESS, error);
    SecMac_Release(macHandle, macBuffer, &macSize);
    macHandle = NULL;
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    if (SecUtils_Memcmp(macBuffer, cert_store->mac, macSize) != 0)
        return SEC_RESULT_FAILURE;

    return SEC_RESULT_SUCCESS;

    error: if (macHandle != NULL )
        SecMac_Release(macHandle, macBuffer, &macSize);
    if (keyHandle != NULL )
        SecKey_Release(keyHandle);

    return SEC_RESULT_FAILURE;
}

Sec_Result _Sec_WrapKeyBuffer(Sec_ProcessorHandle *proc,
        _Sec_ClearKeyBuffer *clear, SEC_BYTE *wrapped, SEC_BYTE *iv_in)
{
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE];
    AES_KEY aes_key;

    AES_set_encrypt_key(proc->kwk, sizeof(proc->kwk) * 8, &aes_key);

    CHECK_EXACT(RAND_bytes(iv, SEC_AES_BLOCK_SIZE), 1, error);
    memcpy(iv_in, iv, SEC_AES_BLOCK_SIZE);

    AES_cbc_encrypt((const SEC_BYTE *) clear, wrapped,
            sizeof(_Sec_ClearKeyBuffer), &aes_key, iv, AES_ENCRYPT);

    return SEC_RESULT_SUCCESS;
    error: return SEC_RESULT_FAILURE;
}

Sec_Result _Sec_UnwrapKeyBuffer(Sec_ProcessorHandle *proc,
        SEC_BYTE *wrapped, _Sec_ClearKeyBuffer *clear, SEC_BYTE *iv_in)
{
    SEC_BYTE iv[SEC_AES_BLOCK_SIZE];
    AES_KEY aes_key;

    memcpy(iv, iv_in, SEC_AES_BLOCK_SIZE);

    AES_set_decrypt_key(proc->kwk, sizeof(proc->kwk) * 8, &aes_key);

    AES_cbc_encrypt((const SEC_BYTE *) wrapped,
            (SEC_BYTE *) clear, sizeof(_Sec_ClearKeyBuffer), &aes_key, iv,
            AES_DECRYPT);

    return SEC_RESULT_SUCCESS;
}

RSA *_Sec_RSAFromBinary(Sec_RSARawPrivateKey *binary, Sec_KeyType key_type)
{
    RSA *rsa = NULL;
    SEC_SIZE key_len = SecKey_GetKeyLenForKeyType(key_type);

    switch (key_type)
    {
        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
            rsa = RSA_new();
            rsa->n = BN_bin2bn(binary->n, key_len, NULL );
            rsa->e = BN_bin2bn(binary->e, 4, NULL );
            rsa->d = BN_bin2bn(binary->d, key_len, NULL );
            break;

        case SEC_KEYTYPE_RSA_1024_PUBLIC:
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            rsa = RSA_new();
            rsa->n = BN_bin2bn(binary->n, key_len, NULL );
            rsa->e = BN_bin2bn(binary->e, 4, NULL );
            break;

        default:
            SEC_LOG_ERROR("Not an RSA key");
            break;
    }

    return rsa;
}

void _Sec_FindRAMKeyData(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id,
        _Sec_RAMKeyData **data, _Sec_RAMKeyData **parent)
{
    *parent = NULL;
    *data = secProcHandle->ram_keys;

    while ((*data) != NULL )
    {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

void _Sec_FindRAMBundleData(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id,
        _Sec_RAMBundleData **data, _Sec_RAMBundleData **parent)
{
    *parent = NULL;
    *data = secProcHandle->ram_bundles;

    while ((*data) != NULL)
    {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

void _Sec_FindRAMCertificateData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, _Sec_RAMCertificateData **data,
        _Sec_RAMCertificateData **parent)
{
    *parent = NULL;
    *data = secProcHandle->ram_certs;

    while ((*data) != NULL )
    {
        if (object_id == (*data)->object_id)
            return;

        *parent = (*data);
        *data = (*data)->next;
    }

    *parent = NULL;
}

Sec_Result _Sec_Aes_CTR(SEC_BYTE *key, SEC_SIZE keySize, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BYTE* output, SEC_SIZE* outputSize,
        SEC_BYTE *iv, SEC_SIZE ivSize)
{
    SEC_BYTE ivec[16];
    SEC_SIZE num = 0;
    SEC_BYTE ecount[16] =
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    AES_KEY aes_key;

    *outputSize = 0;

    if (ivSize != 16)
    {
        SEC_LOG_ERROR("Invalid iv size");
        return SEC_RESULT_FAILURE;
    }

    memcpy(ivec, iv, 16);

    if (0 != AES_set_encrypt_key(key, keySize * 8, &aes_key))
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_FAILURE;
    }

    /* enc and dec operations are the same */
    AES_ctr128_encrypt(input, output, inputSize, &aes_key, ivec, ecount, &num);
    *outputSize = inputSize;

    return SEC_RESULT_SUCCESS;
}

Sec_Result _Sec_SymetricCipher(const EVP_CIPHER *type, SEC_BOOL enc, int padding,
        SEC_BYTE* key, SEC_SIZE keySize, SEC_BYTE* input, SEC_SIZE inputSize,
        SEC_BYTE* output, SEC_SIZE* outputSize, SEC_BYTE* iv, SEC_SIZE ivSize)
{
    int out_len;
    EVP_CIPHER_CTX e_ctx;

    *outputSize = 0;
    EVP_CIPHER_CTX_init(&e_ctx);

    if (enc)
    {
        CHECK_EXACT(EVP_EncryptInit(&e_ctx, type, key, iv), 1, cleanup_error);
        CHECK_EXACT(EVP_CIPHER_CTX_set_key_length(&e_ctx, keySize), 1,
                cleanup_error);
        CHECK_EXACT(EVP_CIPHER_CTX_set_padding(&e_ctx, padding), 1,
                cleanup_error);
        CHECK_EXACT(
                EVP_EncryptUpdate(&e_ctx, output, &out_len, input, inputSize),
                1, cleanup_error);
        *outputSize += out_len;
        CHECK_EXACT(EVP_EncryptFinal(&e_ctx, output+out_len, &out_len), 1,
                cleanup_error);
        *outputSize += out_len;
    }
    else
    {
        CHECK_EXACT(EVP_DecryptInit(&e_ctx, type, key, iv), 1, cleanup_error);
        CHECK_EXACT(EVP_CIPHER_CTX_set_key_length(&e_ctx, keySize), 1,
                cleanup_error);
        CHECK_EXACT(EVP_CIPHER_CTX_set_padding(&e_ctx, padding), 1,
                cleanup_error);
        CHECK_EXACT(
                EVP_DecryptUpdate(&e_ctx, output, &out_len, input, inputSize),
                1, cleanup_error);
        *outputSize += out_len;
        CHECK_EXACT(EVP_DecryptFinal(&e_ctx, output+out_len, &out_len), 1,
                cleanup_error);
        *outputSize += out_len;
    }

    CHECK_EXACT(EVP_CIPHER_CTX_cleanup(&e_ctx), 1, error);

    return SEC_RESULT_SUCCESS;

    cleanup_error: SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
    CHECK_EXACT(EVP_CIPHER_CTX_cleanup(&e_ctx), 1, error);

    error: return SEC_RESULT_FAILURE;
}

Sec_Result _Sec_ProcessKeyContainer(Sec_ProcessorHandle *proc,
        _Sec_KeyData *key_data, Sec_KeyContainer data_type, void *data,
        SEC_SIZE data_len, SEC_OBJECTID objectId)
{
    _Sec_ClearKeyBuffer clear;
    Sec_KeyType key_type;
    BIO *bio = NULL;
    RSA *rsa = NULL;

    if (data_type == SEC_KEYCONTAINER_RAW_AES_128)
    {
        if (data_len != 16)
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }
        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = SEC_KEYTYPE_AES_128;
        memcpy(clear.symetric_key, data, 16);
        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_AES_256)
    {
        if (data_len != 32)
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }
        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = SEC_KEYTYPE_AES_256;
        memcpy(clear.symetric_key, data, 32);
        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_HMAC_128)
    {
        if (data_len != 16)
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }
        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = SEC_KEYTYPE_HMAC_128;
        memcpy(clear.symetric_key, data, 16);
        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_HMAC_160)
    {
        if (data_len != 20)
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }
        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = SEC_KEYTYPE_HMAC_160;
        memcpy(clear.symetric_key, data, 20);
        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_HMAC_256)
    {
        if (data_len != 32)
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }
        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = SEC_KEYTYPE_HMAC_256;
        memcpy(clear.symetric_key, data, 32);
        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_RSA_1024
            || data_type == SEC_KEYCONTAINER_RAW_RSA_2048)
    {
        if (data_len != sizeof(Sec_RSARawPrivateKey))
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type =
                (data_type == SEC_KEYCONTAINER_RAW_RSA_1024) ?
                        SEC_KEYTYPE_RSA_1024 : SEC_KEYTYPE_RSA_2048;

        rsa = SecUtils_RSAFromPrivBinary((Sec_RSARawPrivateKey *) data);
        if (rsa == NULL
                || (SEC_SIZE) RSA_size(rsa)
                        != SecKey_GetKeyLenForKeyType(key_data->info.key_type))
        {
            SEC_RSA_FREE(rsa);
            SEC_LOG_ERROR("Invalid RSA key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        SecUtils_RSAToPrivBinary(rsa, &clear.rsa_key);
        SEC_RSA_FREE(rsa);

        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC
            || data_type == SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC)
    {
        if (data_len != sizeof(Sec_RSARawPublicKey))
        {
            SEC_LOG_ERROR("Invalid key container length");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type =
                (data_type == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC) ?
                        SEC_KEYTYPE_RSA_1024_PUBLIC :
                        SEC_KEYTYPE_RSA_2048_PUBLIC;

        rsa = SecUtils_RSAFromPubBinary((Sec_RSARawPublicKey *) data);
        if (rsa == NULL
                || (SEC_SIZE) RSA_size(rsa)
                        != SecKey_GetKeyLenForKeyType(key_data->info.key_type))
        {
            SEC_RSA_FREE(rsa);
            SEC_LOG_ERROR("Invalid RSA key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        SecUtils_RSAToPrivBinary(rsa, &clear.rsa_key);
        SEC_RSA_FREE(rsa);

        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_PEM_RSA_1024
            || data_type == SEC_KEYCONTAINER_PEM_RSA_2048)
    {
        key_type =
                (data_type == SEC_KEYCONTAINER_PEM_RSA_1024) ?
                        SEC_KEYTYPE_RSA_1024 : SEC_KEYTYPE_RSA_2048;
        bio = BIO_new_mem_buf(data, data_len);
        rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa,
                SecOpenSSL_DisablePassphrasePrompt, NULL );
        SEC_BIO_FREE(bio);
        bio = NULL;

        if (rsa == NULL
                || (SEC_SIZE) RSA_size(rsa) != SecKey_GetKeyLenForKeyType(key_type))
        {
            SEC_RSA_FREE(rsa);
            SEC_LOG_ERROR("Invalid RSA key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = key_type;
        SecUtils_RSAToPrivBinary(rsa, &clear.rsa_key);
        SEC_RSA_FREE(rsa);

        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC
            || data_type == SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC)
    {
        key_type =
                (data_type == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC) ?
                        SEC_KEYTYPE_RSA_1024_PUBLIC :
                        SEC_KEYTYPE_RSA_2048_PUBLIC;

        bio = BIO_new_mem_buf(data, data_len);
        rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, SecOpenSSL_DisablePassphrasePrompt,
                NULL );
        SEC_BIO_FREE(bio);
        bio = NULL;

        if (rsa == NULL
                || (SEC_SIZE) RSA_size(rsa) != SecKey_GetKeyLenForKeyType(key_type))
        {
            SEC_RSA_FREE(rsa);
            SEC_LOG_ERROR("Invalid RSA key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(key_data, 0, sizeof(_Sec_KeyData));
        key_data->info.key_type = key_type;
        SecUtils_RSAToPrivBinary(rsa, &clear.rsa_key);
        SEC_RSA_FREE(rsa);

        goto ok;
    }

    if (data_type == SEC_KEYCONTAINER_SOC)
    {
    }

    /* NEW: other containers */

    SEC_LOG_ERROR("Unimplemented key container type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;

    ok:
    /* encrypt key buffer */
    _Sec_WrapKeyBuffer(proc, &clear, key_data->data, key_data->info.iv);
    SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_SUCCESS;
}

Sec_Result _Sec_ProcessCertificateContainer(Sec_ProcessorHandle *proc,
        _Sec_CertificateData *cert_data, Sec_CertificateContainer data_type,
        void *data, SEC_SIZE data_len)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;

    if (data_type == SEC_CERTIFICATECONTAINER_X509_DER)
    {
        bio = BIO_new_mem_buf(data, data_len);
        x509 = d2i_X509_bio(bio, NULL );
        SEC_BIO_FREE(bio);
        bio = NULL;

        if (x509 == NULL )
        {
            SEC_X509_FREE(x509);
            SEC_LOG_ERROR("Invalid X509 key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(cert_data, 0, sizeof(_Sec_CertificateData));
        cert_data->cert_len = SecUtils_X509ToDer(x509, cert_data->cert);
        SEC_X509_FREE(x509);
        return _Sec_SignCertificateData(proc, cert_data);
    }

    if (data_type == SEC_CERTIFICATECONTAINER_X509_PEM)
    {
        bio = BIO_new_mem_buf(data, data_len);
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL );
        SEC_BIO_FREE(bio);
        bio = NULL;

        if (x509 == NULL )
        {
            SEC_X509_FREE(x509);
            SEC_LOG_ERROR("Invalid X509 key container");
            return SEC_RESULT_INVALID_PARAMETERS;
        }

        memset(cert_data, 0, sizeof(_Sec_CertificateData));
        cert_data->cert_len = SecUtils_X509ToDer(x509, cert_data->cert);
        SEC_X509_FREE(x509);
        return _Sec_SignCertificateData(proc, cert_data);
    }

    /* NEW: other containers */

    SEC_LOG_ERROR("Unimplemented certificate container type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result _Sec_RetrieveBundleData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc *location, _Sec_BundleData *bundleData)
{
    char file_name_bundle[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMBundleData *ram_bundle = NULL;
    _Sec_RAMBundleData *ram_bundle_parent = NULL;

    CHECK_HANDLE(secProcHandle);

    /* check in RAM */
    _Sec_FindRAMBundleData(secProcHandle, object_id, &ram_bundle, &ram_bundle_parent);
    if (ram_bundle != NULL)
    {
        memcpy(bundleData, &(ram_bundle->bundle_data), sizeof(_Sec_BundleData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in file system */
    snprintf(file_name_bundle, sizeof(file_name_bundle), "%s" SEC_BUNDLE_FILENAME_PATTERN,
            secProcHandle->bundlestorage_file_dir, object_id);
    if (SecUtils_FileExists(file_name_bundle))
    {
        if (SecUtils_ReadFile(file_name_bundle, bundleData->bundle,
                sizeof(bundleData->bundle), &bundleData->bundle_len) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not read one of the bundle files");
            return SEC_RESULT_FAILURE;
        }

        *location = SEC_STORAGELOC_FILE;

        return SEC_RESULT_SUCCESS;
    }

    /* check OEM provisioned location */
#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    return SEC_RESULT_NO_SUCH_ITEM;
}

Sec_Result _Sec_RetrieveKeyData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc *location, _Sec_KeyData *keyData)
{
    char file_name_key[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMKeyData *ram_key = NULL;
    _Sec_RAMKeyData *ram_key_parent = NULL;
    SEC_SIZE data_read;

    CHECK_HANDLE(secProcHandle);

    /* check in RAM */
    _Sec_FindRAMKeyData(secProcHandle, object_id, &ram_key, &ram_key_parent);
    if (ram_key != NULL )
    {
        memcpy(keyData, &(ram_key->key_data), sizeof(_Sec_KeyData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in file system */
    snprintf(file_name_key, sizeof(file_name_key), "%s" SEC_KEY_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
            object_id);
    snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_KEYINFO_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
            object_id);
    if (SecUtils_FileExists(file_name_key) && SecUtils_FileExists(file_name_info))
    {
        if (SecUtils_ReadFile(file_name_key, keyData->data, sizeof(keyData->data), &data_read) != SEC_RESULT_SUCCESS
                || SecUtils_ReadFile(file_name_info, &keyData->info, sizeof(keyData->info), &data_read) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not read one of the key files");
            return SEC_RESULT_FAILURE;
        }

        if (data_read != sizeof(keyData->info))
        {
            SEC_LOG_ERROR("File is not of the correct size");
            return SEC_RESULT_FAILURE;
        }

        *location = SEC_STORAGELOC_FILE;

        return SEC_RESULT_SUCCESS;
    }

#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    return SEC_RESULT_NO_SUCH_ITEM;
}

Sec_Result _Sec_RetrieveCertificateData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc *location,
        _Sec_CertificateData *certData)
{
    char file_name_cert[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMCertificateData *ram_cert = NULL;
    _Sec_RAMCertificateData *ram_cert_parent = NULL;
    SEC_SIZE data_read;

    CHECK_HANDLE(secProcHandle);

    /* check in RAM */
    _Sec_FindRAMCertificateData(secProcHandle, object_id, &ram_cert,
            &ram_cert_parent);
    if (ram_cert != NULL )
    {
        memcpy(certData, &(ram_cert->cert_data), sizeof(_Sec_CertificateData));
        *location = SEC_STORAGELOC_RAM;
        return SEC_RESULT_SUCCESS;
    }

    /* check in file system */
    snprintf(file_name_cert, sizeof(file_name_cert), "%s" SEC_CERT_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
            object_id);
    snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
            object_id);
    if (SecUtils_FileExists(file_name_cert) && SecUtils_FileExists(file_name_info))
    {
        if (SecUtils_ReadFile(file_name_cert, certData->cert, sizeof(certData->cert), &certData->cert_len) != SEC_RESULT_SUCCESS
                || SecUtils_ReadFile(file_name_info, certData->mac, sizeof(certData->mac), &data_read) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not read one of the certificate files");
            return SEC_RESULT_FAILURE;
        }

        if (data_read != sizeof(certData->mac))
        {
            SEC_LOG_ERROR("File is not of the correct size");
            return SEC_RESULT_FAILURE;
        }

        *location = SEC_STORAGELOC_FILE;

        return SEC_RESULT_SUCCESS;
    }

#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    return SEC_RESULT_NO_SUCH_ITEM;
}

Sec_Result _Sec_StoreBundleData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location, _Sec_BundleData *bundleData)
{
    _Sec_RAMBundleData *ram_bundle;
    char file_name_bundle[SEC_MAX_FILE_PATH_LEN];

    if (location == SEC_STORAGELOC_RAM)
    {
        ram_bundle = calloc(1, sizeof(_Sec_RAMBundleData));
        if (NULL == ram_bundle)
        {
            SEC_LOG_ERROR("malloc failed");
            return SEC_RESULT_FAILURE;
        }
        ram_bundle->object_id = object_id;
        memcpy(&(ram_bundle->bundle_data), bundleData, sizeof(_Sec_BundleData));
        ram_bundle->next = secProcHandle->ram_bundles;
        secProcHandle->ram_bundles = ram_bundle;

        return SEC_RESULT_SUCCESS;
    }

    if (location == SEC_STORAGELOC_FILE)
    {
        snprintf(file_name_bundle, sizeof(file_name_bundle), "%s" SEC_BUNDLE_FILENAME_PATTERN,
                secProcHandle->bundlestorage_file_dir, object_id);

        if (SecUtils_WriteFile(file_name_bundle, bundleData->bundle,
                bundleData->bundle_len) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not write one of the bundle files");
            SecUtils_RmFile(file_name_bundle);
            return SEC_RESULT_FAILURE;
        }

        return SEC_RESULT_SUCCESS;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result _Sec_StoreKeyData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location, _Sec_KeyData *keyData)
{
    _Sec_RAMKeyData *ram_key;
    char file_name_key[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];

    if (location == SEC_STORAGELOC_RAM
            || location == SEC_STORAGELOC_RAM_SOFT_WRAPPED)
    {
        ram_key = calloc(1, sizeof(_Sec_RAMKeyData));
        if (NULL == ram_key)
        {
            SEC_LOG_ERROR("malloc failed");
            return SEC_RESULT_FAILURE;
        }
        ram_key->object_id = object_id;
        memcpy(&(ram_key->key_data), keyData, sizeof(_Sec_KeyData));
        ram_key->next = secProcHandle->ram_keys;
        secProcHandle->ram_keys = ram_key;

        return SEC_RESULT_SUCCESS;
    }
    else if (location == SEC_STORAGELOC_FILE
            || location == SEC_STORAGELOC_FILE_SOFT_WRAPPED)
    {
        snprintf(file_name_key, sizeof(file_name_key), "%s" SEC_KEY_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
                object_id);
        snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_KEYINFO_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
                object_id);

        if (SecUtils_WriteFile(file_name_key, keyData->data, sizeof(keyData->data)) != SEC_RESULT_SUCCESS
                || SecUtils_WriteFile(file_name_info, &keyData->info, sizeof(keyData->info)) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not write one of the key files");
            SecUtils_RmFile(file_name_key);
            SecUtils_RmFile(file_name_info);
            return SEC_RESULT_FAILURE;
        }

        return SEC_RESULT_SUCCESS;
    }
    else if (location == SEC_STORAGELOC_OEM)
    {
        SEC_LOG_ERROR("Cannot store keys in SEC_STORAGELOC_OEM on this platform");
        return SEC_RESULT_FAILURE;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result _Sec_StoreCertificateData(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location,
        _Sec_CertificateData *certData)
{
    _Sec_RAMCertificateData *ram_cert;
    char file_name_cert[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];

    if (location == SEC_STORAGELOC_RAM)
    {
        ram_cert = calloc(1, sizeof(_Sec_RAMCertificateData));
        if (NULL == ram_cert)
        {
            SEC_LOG_ERROR("malloc failed");
            return SEC_RESULT_FAILURE;
        }
        ram_cert->object_id = object_id;
        memcpy(&(ram_cert->cert_data), certData, sizeof(_Sec_CertificateData));
        ram_cert->next = secProcHandle->ram_certs;
        secProcHandle->ram_certs = ram_cert;

        return SEC_RESULT_SUCCESS;
    }
    else if (location == SEC_STORAGELOC_FILE)
    {
        snprintf(file_name_cert, sizeof(file_name_cert), "%s" SEC_CERT_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
                object_id);
        snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
                object_id);

        if (SecUtils_WriteFile(file_name_cert, certData->cert, certData->cert_len) != SEC_RESULT_SUCCESS
                || SecUtils_WriteFile(file_name_info, certData->mac, sizeof(certData->mac)) != SEC_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("Could not write one of the cert files");
            SecUtils_RmFile(file_name_cert);
            SecUtils_RmFile(file_name_info);
        }

        return SEC_RESULT_SUCCESS;
    }
    else if (location == SEC_STORAGELOC_OEM)
    {
        SEC_LOG_ERROR("Cannot store cert files in SEC_STORAGELOC_OEM on this platform");
        return SEC_RESULT_FAILURE;
    }

    SEC_LOG_ERROR("Unimplemented location type");
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result _Sec_SetStorageDir(const char *provided_dir, const char *default_dir,
        char *output_dir)
{
    const char * dir_to_use;
    size_t len;

    if (provided_dir == NULL || strlen(provided_dir) == 0)
        dir_to_use = default_dir;
    else
        dir_to_use = provided_dir;

    len = strlen(dir_to_use);
    if (len >= (SEC_MAX_FILE_PATH_LEN - 2))
        return SEC_RESULT_FAILURE;

    snprintf(output_dir, SEC_MAX_FILE_PATH_LEN, "%s", dir_to_use);

    if (output_dir[len - 1] != '/' && output_dir[len - 1] != '\\')
    {
        output_dir[len] = '/';
        output_dir[len + 1] = '\0';
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result _Sec_ProvisionBaseKey(Sec_ProcessorHandle *secProcHandle, SEC_BYTE *nonce)
{
    /* constants */
    const char *inputDerivationStr = "sivSha1";
    Sec_DigestAlgorithm digestAlgorithm = SEC_DIGESTALGORITHM_SHA1;
    const char *cipherAlgorithmStr = "aesEcbNone";
    Sec_CipherAlgorithm cipherAlgorithm = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
    Sec_CipherMode cipherMode = SEC_CIPHERMODE_ENCRYPT;
    Sec_KeyType keyType = SEC_KEYTYPE_AES_128;

    int i;
    SEC_SIZE keySize;
    Sec_KeyHandle *tempKey = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;
    SEC_SIZE cipher_output_len;
    SEC_BYTE cipher_output[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE *cipher_key = secProcHandle->ssk;
    SEC_OBJECTID temp_key_id = SEC_OBJECTID_INVALID;
    SEC_BYTE c1[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE c2[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE c3[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE c4[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE *c[] = { c1, c2, c3, c4 };

    SecKey_Delete(secProcHandle, SEC_OBJECTID_BASE_KEY_AES);
    SecKey_Delete(secProcHandle, SEC_OBJECTID_BASE_KEY_MAC);

    keySize = SecKey_GetKeyLenForKeyType(keyType);

    res = SecKey_ComputeBaseKeyLadderInputs(secProcHandle, inputDerivationStr, cipherAlgorithmStr,
            nonce, digestAlgorithm, keySize, c1, c2, c3, c4);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecKey_ComputeBaseKeyLadderInputs failed");
        goto done;
    }

    for (i = 1; i <= 4; i++)
    {
        /* encrypt digest */
        temp_key_id = SecKey_ObtainFreeObjectId(secProcHandle, SEC_OBJECTID_RESERVED_BASE, SEC_OBJECTID_RESERVED_TOP);
        if (temp_key_id == SEC_OBJECTID_INVALID)
        {
            res = SEC_RESULT_FAILURE;
            SEC_LOG_ERROR("SecKey_ObtainFreeObjectId failed");
            goto done;
        }
        res = SecKey_Provision(secProcHandle, temp_key_id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_RAW_AES_128, cipher_key, keySize);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        res = SecKey_GetInstance(secProcHandle, temp_key_id, &tempKey);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        res = SecCipher_SingleInput(secProcHandle, cipherAlgorithm, cipherMode, tempKey, NULL,
                c[i-1], keySize, cipher_output, sizeof(cipher_output), &cipher_output_len);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        SecKey_Release(tempKey);
        tempKey = NULL;

        cipher_key = cipher_output;
    }

    res = SecKey_Provision(secProcHandle, SEC_OBJECTID_BASE_KEY_AES,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_RAW_AES_128, cipher_key, keySize);

    if (res == SEC_RESULT_SUCCESS)
    {
        res = SecKey_Provision(secProcHandle, SEC_OBJECTID_BASE_KEY_MAC,
                SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_KEYCONTAINER_RAW_HMAC_128,
                cipher_key, keySize);
    }

    done:
    if (tempKey != NULL)
        SecKey_Release(tempKey);
    SecKey_Delete(secProcHandle, temp_key_id);

    return res;
}

Sec_Result SecProcessor_PrintInfo(Sec_ProcessorHandle* secProcHandle)
{
    SEC_BYTE deviceId[SEC_DEVICEID_LEN];

    if (SEC_RESULT_SUCCESS == SecProcessor_GetDeviceId(secProcHandle, deviceId))
    {
        SEC_PRINT("device id: "); SecUtils_PrintHex(deviceId, SEC_DEVICEID_LEN); SEC_PRINT("\n");
    }
    else
    {
        SEC_PRINT("device id: unknown\n");
    }

    SEC_PRINT("platform: SEC_PLATFORM_OPENSSL\n");
    SEC_PRINT("version: %s\n", SEC_API_VERSION);

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecProcessor_GetInstance(Sec_ProcessorHandle** secProcHandle,
        Sec_ProcessorInitParams* socInitParams)
{
    SEC_BYTE kwk[] = { 0x55, 0x4E, 0x46, 0x63, 0x3D, 0x0A, 0x50, 0x4F,
                       0x53, 0x54, 0x0A, 0x2F, 0x69, 0x64, 0x70, 0x2F };
    *secProcHandle = NULL;

    if (g_sec_security_num_processors > 0)
    {
        SEC_LOG_ERROR("Only one SecProcessor instance can be active at a time");
        goto error;
    }

    /* setup openssl stuff */
    SecUtils_InitOpenSSL();

    /* create handle */
    *secProcHandle = calloc(1, sizeof(Sec_ProcessorHandle));
    if (NULL == *secProcHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }

    /* setup key and cert directories */
    CHECK_EXACT(
            _Sec_SetStorageDir(socInitParams->keystorage_file_dir, SEC_KEYSTORAGE_FILE_DEFAULT_DIR, (*secProcHandle)->keystorage_file_dir),
            SEC_RESULT_SUCCESS, error);
    SecUtils_MkDir((*secProcHandle)->keystorage_file_dir);

    CHECK_EXACT(
            _Sec_SetStorageDir(socInitParams->certstorage_file_dir, SEC_CERTIFICATESTORAGE_FILE_DEFAULT_DIR, (*secProcHandle)->certstorage_file_dir),
            SEC_RESULT_SUCCESS, error);
    SecUtils_MkDir((*secProcHandle)->certstorage_file_dir);

    CHECK_EXACT(
            _Sec_SetStorageDir(socInitParams->bundlestorage_file_dir, SEC_BUNDLESTORAGE_FILE_DEFAULT_DIR, (*secProcHandle)->bundlestorage_file_dir),
            SEC_RESULT_SUCCESS, error);
    SecUtils_MkDir((*secProcHandle)->bundlestorage_file_dir);

    /* device id */
    memcpy((*secProcHandle)->device_id, socInitParams->device_id,
            SEC_DEVICEID_LEN);

    /* ssk */
    memcpy((*secProcHandle)->ssk, socInitParams->ssk,
            sizeof(socInitParams->ssk));

    /* generate key wrapping key */
    memcpy((*secProcHandle)->kwk, kwk, 16);

#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    /* derive certificate mac key */
    SecKey_Generate(*secProcHandle, SEC_OBJECTID_CERTSTORE_KEY, SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_FILE);

    ++g_sec_security_num_processors;

    return SEC_RESULT_SUCCESS;

    error: if ((*secProcHandle) != NULL )
    {
#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif
        SEC_FREE(*secProcHandle);
        *secProcHandle = NULL;
    }
    return SEC_RESULT_FAILURE;
}

Sec_Result SecProcessor_GetDeviceId(Sec_ProcessorHandle* secProcHandle,
        SEC_BYTE *deviceId)
{
    CHECK_HANDLE(secProcHandle);

    memcpy(deviceId, secProcHandle->device_id,
            sizeof(secProcHandle->device_id));
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecProcessor_Release(Sec_ProcessorHandle *secProcHandle)
{
    if (NULL == secProcHandle)
        return SEC_RESULT_SUCCESS;

    /* release ram keys */
    while (secProcHandle->ram_keys != NULL )
    {
        SecKey_Delete(secProcHandle, secProcHandle->ram_keys->object_id);
    }

    /* release ram bundles */
    while (secProcHandle->ram_bundles != NULL)
    {
        SecBundle_Delete(secProcHandle, secProcHandle->ram_bundles->object_id);
    }

    /* release ram certs */
    while (secProcHandle->ram_certs != NULL )
    {
        SecCertificate_Delete(secProcHandle,
                secProcHandle->ram_certs->object_id);
    }

    ERR_free_strings();

#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    SEC_FREE(secProcHandle);
    --g_sec_security_num_processors;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCipher_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, Sec_KeyHandle* key,
        SEC_BYTE *iv, Sec_CipherHandle** cipherHandle)
{
    _Sec_KeyData *key_data;
    Sec_CipherHandle localHandle;
    const EVP_CIPHER *evp_cipher;
    _Sec_ClearKeyBuffer clear;
    int padding = 0;

    CHECK_HANDLE(secProcHandle);

    memset(&localHandle, 0, sizeof(localHandle));

    if (SEC_RESULT_SUCCESS
            != SecCipher_IsValidKey(key->key_data.info.key_type, algorithm, mode,
                    iv))
    {
        SEC_LOG_ERROR("Invalid key used for specified algorithm");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    /* unwrap key */
    key_data = &(key->key_data);
    _Sec_UnwrapKeyBuffer(secProcHandle, key_data->data, &clear, key_data->info.iv);

    switch (algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
            if (algorithm == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING
                    || algorithm == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING)
            {
                if (key->key_data.info.key_type == SEC_KEYTYPE_AES_128)
                    evp_cipher = EVP_aes_128_ecb();
                else
                    evp_cipher = EVP_aes_256_ecb();
            }
            else if (algorithm == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING
                    || algorithm == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING)
            {
                if (key->key_data.info.key_type == SEC_KEYTYPE_AES_128)
                    evp_cipher = EVP_aes_128_cbc();
                else
                    evp_cipher = EVP_aes_256_cbc();
            }

            EVP_CIPHER_CTX_init(&localHandle.evp_ctx);

            if (1
                    != EVP_CipherInit_ex(&localHandle.evp_ctx, evp_cipher, NULL,
                            NULL, NULL, (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
            {
                SEC_LOG_ERROR("EVP_CipherInit failed");
                goto error;
            }

            if (1 != EVP_CIPHER_CTX_set_padding(&localHandle.evp_ctx, padding))
            {
                SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
                goto error;
            }

            if (1
                    != EVP_CipherInit_ex(&localHandle.evp_ctx, NULL, NULL,
                            clear.symetric_key, iv,
                            (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
            {
                SEC_LOG_ERROR("EVP_CipherInit failed");
                goto error;
            }

            break;

        case SEC_CIPHERALGORITHM_AES_CTR:
            memset(&localHandle.ctr_ctx, 0, sizeof(localHandle.ctr_ctx));
            memcpy(localHandle.ctr_ctx.ivec, iv, 16);

            if (0
                    != AES_set_encrypt_key(clear.symetric_key,
                            SecKey_GetKeyLen(key) * 8,
                            &localHandle.ctr_ctx.aes_key))
            {
                SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
                goto error;
            }
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            break;

            /* NEW: other cipher algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            goto unimplemented;
    }

    *cipherHandle = calloc(1, sizeof(Sec_CipherHandle));
    if (NULL == *cipherHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    memcpy(*cipherHandle, &localHandle, sizeof(localHandle));
    (*cipherHandle)->algorithm = algorithm;
    (*cipherHandle)->mode = mode;
    (*cipherHandle)->key_handle = key;

    SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_SUCCESS;
    error: SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_FAILURE;
    unimplemented: SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_ProcessFragmented(Sec_CipherHandle* cipherHandle, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_BYTE* output, SEC_SIZE outputSize,
        SEC_SIZE *bytesWritten, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod)
{
    SEC_SIZE lbw;
    Sec_Result res;

    CHECK_HANDLE(cipherHandle);

    *bytesWritten = 0;

    res = SecCipher_CheckFragmentedInputOutputSizes(cipherHandle->algorithm,
            cipherHandle->mode, cipherHandle->key_handle->key_data.info.key_type,
            inputSize, outputSize, lastInput, fragmentOffset, fragmentSize, fragmentPeriod);
    if (res != SEC_RESULT_SUCCESS)
        return res;

    switch (cipherHandle->algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CTR:
            if (input != output)
            {
                memcpy(output, input, inputSize);
            }
            *bytesWritten = inputSize;

            while (inputSize > 0)
            {
                if (SEC_RESULT_SUCCESS != SecCipher_Process(cipherHandle, output+fragmentOffset, fragmentSize,
                        lastInput && (inputSize == fragmentPeriod), output+fragmentOffset, fragmentSize, &lbw))
                {
                    SEC_LOG_ERROR("SecCipher_Process failed");
                    return SEC_RESULT_FAILURE;
                }
                output += fragmentPeriod;
                inputSize -= fragmentPeriod;
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

Sec_Result SecCipher_Process(Sec_CipherHandle* cipherHandle, SEC_BYTE* input,
        SEC_SIZE inputSize, SEC_BOOL lastInput, SEC_BYTE* output,
        SEC_SIZE outputSize, SEC_SIZE *bytesWritten)
{
    RSA *rsa;
    int out_len;
    SEC_BYTE aes_pad_vals[SEC_AES_BLOCK_SIZE];
    SEC_BYTE aes_padded_block[SEC_AES_BLOCK_SIZE];
    SEC_BYTE pad_val;
    int openssl_res;
    int padding;
    Sec_Result res;
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(cipherHandle);

    *bytesWritten = 0;

    if (cipherHandle->last != 0)
    {
        SEC_LOG_ERROR("Last block has already been processed");
        return SEC_RESULT_FAILURE;
    }
    cipherHandle->last = lastInput;

    res = SecCipher_CheckInputOutputSizes(cipherHandle->algorithm,
            cipherHandle->mode, cipherHandle->key_handle->key_data.info.key_type,
            inputSize, outputSize, lastInput);
    if (res != SEC_RESULT_SUCCESS)
        return res;

    switch (cipherHandle->algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
            if (1
                    != EVP_CipherUpdate(&cipherHandle->evp_ctx, output,
                            &out_len, input, inputSize))
            {
                SEC_LOG_ERROR("EVP_CipherUpdate failed");
                return SEC_RESULT_FAILURE;
            }
            *bytesWritten += out_len;
            out_len = 0;

            if (lastInput
                    && 1
                            != EVP_CipherFinal_ex(&cipherHandle->evp_ctx,
                                    &output[*bytesWritten], &out_len))
            {
                SEC_LOG_ERROR("EVP_CipherFinal failed");
                return SEC_RESULT_FAILURE;
            }
            *bytesWritten += out_len;

            break;

        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            /* process all blocks except for the last, partial one */
            if (1
                    != EVP_CipherUpdate(&cipherHandle->evp_ctx, output,
                            &out_len, input, (inputSize / 16) * 16))
            {
                SEC_LOG_ERROR("EVP_CipherUpdate failed");
                return SEC_RESULT_FAILURE;
            }
            *bytesWritten += out_len;
            out_len = 0;

            if (lastInput && (cipherHandle->mode == SEC_CIPHERMODE_ENCRYPT || cipherHandle->mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM))
            {
                /* create padded block */
                SecCipher_PadAESPKCS7Block(&input[(inputSize / 16) * 16],
                        inputSize % SEC_AES_BLOCK_SIZE, aes_padded_block);

                /* process padded block */
                if (1
                        != EVP_CipherUpdate(&cipherHandle->evp_ctx,
                                &output[(inputSize / 16) * 16], &out_len,
                                aes_padded_block, SEC_AES_BLOCK_SIZE))
                {
                    SEC_LOG_ERROR("EVP_CipherUpdate failed");
                    return SEC_RESULT_FAILURE;
                }
                *bytesWritten += out_len;
                out_len = 0;

                if (lastInput
                        && 1
                                != EVP_CipherFinal_ex(&cipherHandle->evp_ctx,
                                        &output[*bytesWritten], &out_len))
                {
                    SEC_LOG_ERROR("EVP_CipherFinal failed");
                    return SEC_RESULT_FAILURE;
                }
                *bytesWritten += out_len;
            }
            else if (lastInput && (cipherHandle->mode == SEC_CIPHERMODE_DECRYPT || cipherHandle->mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM))
            {
                if (lastInput
                        && 1
                                != EVP_CipherFinal(&cipherHandle->evp_ctx,
                                        &output[*bytesWritten], &out_len))
                {
                    SEC_LOG_ERROR("EVP_CipherFinal failed");
                    return SEC_RESULT_FAILURE;
                }
                *bytesWritten += out_len;

                /* check padding */
                pad_val = output[*bytesWritten - 1];
                if (pad_val > SEC_AES_BLOCK_SIZE || pad_val == 0)
                {
                    SEC_LOG_ERROR("Invalid pad value encountered");
                    return SEC_RESULT_INVALID_PADDING;
                }

                memset(aes_pad_vals, pad_val, sizeof(aes_pad_vals));
                if (SecUtils_Memcmp(aes_pad_vals, &output[*bytesWritten - pad_val],
                        pad_val) != 0)
                {
                    SEC_LOG_ERROR("Invalid pad value encountered");
                    return SEC_RESULT_INVALID_PADDING;
                }

                /* remove pading values from output */
                *bytesWritten -= pad_val;
            }
            break;

        case SEC_CIPHERALGORITHM_AES_CTR:
            AES_ctr128_encrypt(input, output, inputSize,
                    &(cipherHandle->ctr_ctx.aes_key),
                    cipherHandle->ctr_ctx.ivec, cipherHandle->ctr_ctx.ecount,
                    &(cipherHandle->ctr_ctx.num));
            *bytesWritten = inputSize;
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            _Sec_UnwrapKeyBuffer(cipherHandle->key_handle->proc,
                    cipherHandle->key_handle->key_data.data, &clear, cipherHandle->key_handle->key_data.info.iv);
            rsa = _Sec_RSAFromBinary(&clear.rsa_key,
                    cipherHandle->key_handle->key_data.info.key_type);
            SecUtils_Memset(&clear, 0, sizeof(clear));
            if (NULL == rsa)
            {
                SEC_LOG_ERROR("Could not load RSA key from KeyData");
                return SEC_RESULT_FAILURE;
            }

            if (cipherHandle->algorithm
                    == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING)
            {
                padding = RSA_PKCS1_PADDING;
            }
            else
            {
                padding = RSA_PKCS1_OAEP_PADDING;
            }

            if (cipherHandle->mode == SEC_CIPHERMODE_ENCRYPT || cipherHandle->mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM)
            {
                openssl_res = RSA_public_encrypt(inputSize, input, output,
                        rsa, padding);
            }
            else
            {
                openssl_res = RSA_private_decrypt(inputSize, input, output,
                        rsa, padding);
            }

            SEC_RSA_FREE(rsa);

            if (openssl_res < 0)
            {
                SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
                return SEC_RESULT_FAILURE;
            }

            *bytesWritten = openssl_res;

            break;

            /* NEW: other cipher algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_Release(Sec_CipherHandle* cipherHandle)
{
    CHECK_HANDLE(cipherHandle);

    switch (cipherHandle->algorithm)
    {
        case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
        case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
        case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
            if (EVP_CIPHER_CTX_cleanup(&(cipherHandle->evp_ctx)) != 1)
            {
                SEC_LOG_ERROR("EVP_CIPHER_CTX_cleanup failed");
            }
            break;

        case SEC_CIPHERALGORITHM_AES_CTR:
            SecUtils_Memset(&cipherHandle->ctr_ctx, 0, sizeof(cipherHandle->ctr_ctx));
            break;

        case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
        case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
            break;

            /* NEW: other cipher algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented cipher algorithm");
            goto unimplemented;
    }

    SEC_FREE(cipherHandle);
    return SEC_RESULT_SUCCESS;

    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}
#endif

Sec_Result SecDigest_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_DigestAlgorithm algorithm, Sec_DigestHandle** digestHandle)
{
#if !defined(OPTEE_DEMO)
    CHECK_HANDLE(secProcHandle);
#endif

    *digestHandle = calloc(1, sizeof(Sec_DigestHandle));
    if (NULL == *digestHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*digestHandle)->algorithm = algorithm;

/* 
 * SHA init functions are not exposed in GP Internal API, only TEE_DigestUpdate
 * and TEE_DigestDoFinal, which will do this in lower levels.
 */
#if !defined(OPTEE_DEMO)
    switch (algorithm)
    {
        case SEC_DIGESTALGORITHM_SHA1:
            if (1 != SHA1_Init(&((*digestHandle)->sha1_ctx)))
            {
                SEC_FREE(*digestHandle);
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_DIGESTALGORITHM_SHA256:
            if (1 != SHA256_Init(&((*digestHandle)->sha256_ctx)))
            {
                SEC_FREE(*digestHandle);
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            SEC_LOG_ERROR("Unimplemented digest algorithm");
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecDigest_Update(Sec_DigestHandle* digestHandle, SEC_BYTE* input,
        SEC_SIZE inputSize)
{
    CHECK_HANDLE(digestHandle);
#if !defined(OPTEE_DEMO)

    comcast_ta_digest(digestHandle->algorithm, input, inputSize);
    switch (digestHandle->algorithm)
    {
        case SEC_DIGESTALGORITHM_SHA1:
            if (1 != SHA1_Update(&(digestHandle->sha1_ctx), input, inputSize))
            {
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_DIGESTALGORITHM_SHA256:
            if (1
                    != SHA256_Update(&(digestHandle->sha256_ctx), input,
                            inputSize))
            {
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

#if !defined(OPTEE_DEMO)
Sec_Result SecDigest_UpdateWithKey(Sec_DigestHandle* digestHandle,
        Sec_KeyHandle *key)
{
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(digestHandle);

    _Sec_UnwrapKeyBuffer(key->proc, key->key_data.data, &clear, key->key_data.info.iv);

    switch (digestHandle->algorithm)
    {
        case SEC_DIGESTALGORITHM_SHA1:
            if (1
                    != SHA1_Update(&(digestHandle->sha1_ctx),
                            clear.symetric_key, SecKey_GetKeyLen(key)))
            {
                SecUtils_Memset(&clear, 0, sizeof(clear));
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_DIGESTALGORITHM_SHA256:
            if (1
                    != SHA256_Update(&(digestHandle->sha256_ctx),
                            clear.symetric_key, SecKey_GetKeyLen(key)))
            {
                SecUtils_Memset(&clear, 0, sizeof(clear));
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_SUCCESS;
}
#endif

/*
 * Had to change this so it accepts input data here. The reason for this is that
 * we're only going to do a single call to secure world. This would need to be
 * changed in a real situation. Either by adding a single
 * "do_hash_in_secure_world function" to this RDK Crypto API. Or you have to
 * cache input data from the SecDigest_Update(...) call either in the client
 * running normal world or down in the secure world.
 */
Sec_Result SecDigest_Release(Sec_DigestHandle* digestHandle,
        SEC_BYTE* digestOutput, SEC_SIZE* digestSize, SEC_BYTE* input,
        SEC_SIZE inputSize)
{
    CHECK_HANDLE(digestHandle);

    switch (digestHandle->algorithm)
    {
        case SEC_DIGESTALGORITHM_SHA1:
            *digestSize = 20;
#if !defined(OPTEE_DEMO)
            if (1 != SHA1_Final(digestOutput, &(digestHandle->sha1_ctx)))
            {
                return SEC_RESULT_FAILURE;
            }
#endif
            break;

        case SEC_DIGESTALGORITHM_SHA256:
            *digestSize = 32;
#if !defined(OPTEE_DEMO)
            if (1 != SHA256_Final(digestOutput, &(digestHandle->sha256_ctx)))
            {
                return SEC_RESULT_FAILURE;
            }
#endif
            break;

        default:
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    comcast_ta_digest(digestHandle->algorithm, input, inputSize, digestOutput, *digestSize);

    SEC_FREE(digestHandle);
    return SEC_RESULT_SUCCESS;
}

#if !defined(OPTEE_DEMO)
Sec_Result SecSignature_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* key, Sec_SignatureHandle** signatureHandle)
{
    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            != SecSignature_IsValidKey(key->key_data.info.key_type, algorithm, mode))
    {
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *signatureHandle = calloc(1, sizeof(Sec_SignatureHandle));
    if (NULL == *signatureHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*signatureHandle)->algorithm = algorithm;
    (*signatureHandle)->mode = mode;
    (*signatureHandle)->key_handle = key;

    return SEC_RESULT_SUCCESS;
}

Sec_Result _SecSignature_Sign(Sec_SignatureHandle* signatureHandle,
        SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE* signatureSize)
{
    RSA *rsa = NULL;
    Sec_KeyHandle *key_handle;
    _Sec_KeyData *key_data;
    int res;
    int digest;
    SEC_SIZE sig_size;
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(signatureHandle);

    key_handle = signatureHandle->key_handle;
    key_data = &(key_handle->key_data);

    /* TODO digest only */
    if (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
            || signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST)
    {
        SEC_LOG_ERROR("Unimplemented feature");
        return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    switch (signatureHandle->algorithm)
    {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
            if (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
                    || signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST)
            {
                digest = NID_sha1;
            }
            else
            {
                digest = NID_sha256;
            }

            _Sec_UnwrapKeyBuffer(key_handle->proc, key_data->data,
                    &clear, key_data->info.iv);
            rsa = _Sec_RSAFromBinary(&clear.rsa_key, key_data->info.key_type);
            SecUtils_Memset(&clear, 0, sizeof(clear));

            if (NULL == rsa)
            {
                SEC_LOG_ERROR("Could not load RSA key from KeyData");
                goto error;
            }

            res = RSA_sign(digest, input, inputSize, signature, &sig_size, rsa);
            *signatureSize = sig_size;

            SEC_RSA_FREE(rsa);

            if (0 == res)
            {
                SEC_LOG_ERROR("RSA_sign failed");
                goto error;
            }
            break;

            /* NEW: other signature algorithms */
        default:
            SEC_LOG_ERROR("Unimplemented signature algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    error: return SEC_RESULT_FAILURE;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result _SecSignature_Validate(Sec_SignatureHandle* signatureHandle,
        SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize)
{
    RSA *rsa = NULL;
    Sec_KeyHandle *key_handle;
    _Sec_KeyData *key_data;
    int res;
    int digest;
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(signatureHandle);

    key_handle = signatureHandle->key_handle;
    key_data = &(key_handle->key_data);

    switch (signatureHandle->algorithm)
    {
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
        case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
            if (signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
                    || signatureHandle->algorithm == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST)
                digest = NID_sha1;
            else
                digest = NID_sha256;

            _Sec_UnwrapKeyBuffer(key_handle->proc, key_data->data,
                    &clear, key_data->info.iv);
            rsa = _Sec_RSAFromBinary(&clear.rsa_key, key_data->info.key_type);
            SecUtils_Memset(&clear, 0, sizeof(clear));

            if (NULL == rsa)
            {
                SEC_LOG_ERROR("Could not load RSA key from KeyData");
                goto error;
            }

            *signatureSize = RSA_size(rsa);

            res = RSA_verify(digest, input, inputSize, signature,
                    *signatureSize, rsa);

            SEC_RSA_FREE(rsa);

            if (1 != res)
                goto verify_failed;

            break;

            /* NEW: add new signature algorithms here */
        default:
            SEC_LOG_ERROR("Unimplemented signature algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    error: return SEC_RESULT_FAILURE;
    verify_failed: return SEC_RESULT_VERIFICATION_FAILED;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecSignature_Process(Sec_SignatureHandle* signatureHandle,
        SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize)
{
    Sec_Result res;
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;

    CHECK_HANDLE(signatureHandle);

    /* calculate digest */
    res = SecDigest_SingleInput(signatureHandle->key_handle->proc,
            SecSignature_GetDigestAlgorithm(signatureHandle->algorithm),
            input, inputSize, digest, &digest_len);
    if (res != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecDigest_SingleInput failed");
        return res;
    }

    if (signatureHandle->mode == SEC_SIGNATUREMODE_SIGN)
    {
        return _SecSignature_Sign(signatureHandle, digest, digest_len,
                signature, signatureSize);
    }
    else
    {
        return _SecSignature_Validate(signatureHandle, digest, digest_len,
                signature, signatureSize);
    }
}

Sec_Result SecSignature_Release(Sec_SignatureHandle* signatureHandle)
{
    CHECK_HANDLE(signatureHandle);
    SEC_FREE(signatureHandle);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecMac_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_MacAlgorithm algorithm, Sec_KeyHandle* key,
        Sec_MacHandle** macHandle)
{
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            != SecMac_IsValidKey(key->key_data.info.key_type, algorithm))
    {
        SEC_LOG_ERROR("Not a valid mac key");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    *macHandle = calloc(1, sizeof(Sec_MacHandle));
    if (NULL == *macHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*macHandle)->algorithm = algorithm;
    (*macHandle)->key_handle = key;

    _Sec_UnwrapKeyBuffer(secProcHandle, key->key_data.data, &clear, key->key_data.info.iv);

    switch (algorithm)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            HMAC_CTX_init(&((*macHandle)->hmac_ctx));
            HMAC_Init(&((*macHandle)->hmac_ctx), clear.symetric_key,
                    SecKey_GetKeyLen(key), (algorithm == SEC_MACALGORITHM_HMAC_SHA1) ? EVP_sha1() : EVP_sha256());
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            CMAC_CTX_init(&((*macHandle)->cmac_ctx));
            if (1
                    != CMAC_Init(&((*macHandle)->cmac_ctx), clear.symetric_key,
                            SecKey_GetKeyLen(key), EVP_aes_128_ecb(), NULL ))
            {
                SEC_LOG_ERROR("CMAC_Init failed");
                SEC_FREE(*macHandle);
                SecUtils_Memset(&clear, 0, sizeof(clear));
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            SEC_LOG_ERROR("Unimplemented mac algorithm");
            SecUtils_Memset(&clear, 0, sizeof(clear));
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    SecUtils_Memset(&clear, 0, sizeof(clear));

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecMac_Update(Sec_MacHandle* macHandle, SEC_BYTE* input,
        SEC_SIZE inputSize)
{
    CHECK_HANDLE(macHandle);

    switch (macHandle->algorithm)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            HMAC_Update(&macHandle->hmac_ctx, input, inputSize);
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            CMAC_Update(&macHandle->cmac_ctx, input, inputSize);
            break;

        default:
            SEC_LOG_ERROR("Unimplemented mac algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecMac_UpdateWithKey(Sec_MacHandle* macHandle,
        Sec_KeyHandle *keyHandle)
{
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(macHandle);

    _Sec_UnwrapKeyBuffer(keyHandle->proc, keyHandle->key_data.data,
            &clear, keyHandle->key_data.info.iv);

    switch (macHandle->algorithm)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            HMAC_Update(&macHandle->hmac_ctx, clear.symetric_key,
                    SecKey_GetKeyLen(keyHandle));
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            CMAC_Update(&macHandle->cmac_ctx, clear.symetric_key,
                    SecKey_GetKeyLen(keyHandle));
            break;

        default:
            SEC_LOG_ERROR("Unimplemented mac algorithm");
            goto unimplemented;
    }

    SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_SUCCESS;
    unimplemented: SecUtils_Memset(&clear, 0, sizeof(clear));
    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecMac_Release(Sec_MacHandle* macHandle, SEC_BYTE* macBuffer,
        SEC_SIZE* macSize)
{
    SEC_SIZE out_len;

    CHECK_HANDLE(macHandle);

    switch (macHandle->algorithm)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
        case SEC_MACALGORITHM_HMAC_SHA256:
            HMAC_Final(&(macHandle->hmac_ctx), macBuffer, &out_len);
            *macSize = out_len;
            HMAC_CTX_cleanup(&(macHandle->hmac_ctx));
            break;

        case SEC_MACALGORITHM_CMAC_AES_128:
            CMAC_Final(&macHandle->cmac_ctx, macBuffer, &out_len);
            *macSize = out_len;
            break;

        default:
            SEC_LOG_ERROR("Unimplemented mac algorithm");
            return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    }

    SEC_FREE(macHandle);
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecRandom_GetInstance(Sec_ProcessorHandle* secProcHandle,
        Sec_RandomAlgorithm algorithm, Sec_RandomHandle** randomHandle)
{
    CHECK_HANDLE(secProcHandle);

    *randomHandle = calloc(1, sizeof(Sec_RandomHandle));
    if (NULL == *randomHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*randomHandle)->algorithm = algorithm;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecRandom_Process(Sec_RandomHandle* randomHandle, SEC_BYTE* output,
        SEC_SIZE outputSize)
{
    CHECK_HANDLE(randomHandle);

    switch (randomHandle->algorithm)
    {
        case SEC_RANDOMALGORITHM_TRUE:
            CHECK_EXACT(RAND_bytes(output, outputSize), 1, error);
            break;

        case SEC_RANDOMALGORITHM_PRNG:
            CHECK_EXACT(RAND_pseudo_bytes(output, outputSize), 1, error);
            break;

        default:
            SEC_LOG_ERROR("Unimplemented random algorithm");
            goto unimplemented;
    }

    return SEC_RESULT_SUCCESS;
    error: return SEC_RESULT_FAILURE;
    unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecRandom_Release(Sec_RandomHandle* randomHandle)
{
    CHECK_HANDLE(randomHandle);
    SEC_FREE(randomHandle);
    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecCertificate_List(Sec_ProcessorHandle *proc, SEC_OBJECTID *items, SEC_SIZE maxNumItems)
{
    _Sec_RAMCertificateData *cert;
    SEC_SIZE numItems = 0;

    /* look in RAM */
    cert = proc->ram_certs;
    while (cert != NULL)
    {
        numItems = SecUtils_UpdateItemList(items, maxNumItems, numItems, cert->object_id);
        cert = cert->next;
    }

    /* look in file system */
    numItems = SecUtils_UpdateItemListFromDir(items, maxNumItems, numItems, proc->certstorage_file_dir, SEC_CERT_FILENAME_EXT);

    /* look in OEM memory */
#ifdef SEC_ENABLE_OEM_PROVISIONING
#endif

    return numItems;
}

Sec_Result SecCertificate_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_CertificateHandle** certHandle)
{
    Sec_Result result;
    _Sec_CertificateData cert_data;
    Sec_StorageLoc location;

    CHECK_HANDLE(secProcHandle);

    if (object_id == SEC_OBJECTID_INVALID)
    {
        SEC_LOG_ERROR("Invalid object_id");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    result = _Sec_RetrieveCertificateData(secProcHandle, object_id, &location,
            &cert_data);
    if (result != SEC_RESULT_SUCCESS)
    {
        return result;
    }

    result = _Sec_ValidateCertificateData(secProcHandle, &cert_data);
    if (result != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("_Sec_ValidateCertificateData failed");
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    *certHandle = calloc(1, sizeof(Sec_CertificateHandle));
    if (NULL == *certHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*certHandle)->object_id = object_id;
    memcpy(&((*certHandle)->cert_data), &cert_data,
            sizeof(_Sec_CertificateData));
    (*certHandle)->location = location;
    (*certHandle)->proc = secProcHandle;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCertificate_Provision(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location,
        Sec_CertificateContainer data_type, SEC_BYTE *data, SEC_SIZE data_len)
{
    _Sec_CertificateData cert_data;
    Sec_Result result;
    Sec_CertificateHandle *certHandle;

    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            == SecCertificate_GetInstance(secProcHandle, object_id,
                    &certHandle)
                    && certHandle->location != SEC_STORAGELOC_OEM)
    {
        SecCertificate_Release(certHandle);
        return SEC_RESULT_ITEM_ALREADY_PROVISIONED;
    }

    result = _Sec_ProcessCertificateContainer(secProcHandle, &cert_data,
            data_type, data, data_len);
    if (SEC_RESULT_SUCCESS != result)
        return result;

    return _Sec_StoreCertificateData(secProcHandle, object_id, location,
            &cert_data);
}

Sec_Result SecCertificate_Delete(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id)
{
    char file_name[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMCertificateData *ram_cert = NULL;
    _Sec_RAMCertificateData *ram_cert_parent = NULL;
    SEC_SIZE certs_found = 0;
    SEC_SIZE certs_deleted = 0;

    CHECK_HANDLE(secProcHandle);

    /* ram */
    _Sec_FindRAMCertificateData(secProcHandle, object_id, &ram_cert,
            &ram_cert_parent);
    if (ram_cert != NULL )
    {
        if (ram_cert_parent == NULL )
            secProcHandle->ram_certs = ram_cert->next;
        else
            ram_cert_parent->next = ram_cert->next;

        SecUtils_Memset(ram_cert, 0, sizeof(_Sec_RAMCertificateData));

        SEC_FREE(ram_cert);

        ++certs_found;
        ++certs_deleted;
    }

    /* file system */
    snprintf(file_name, sizeof(file_name), "%s" SEC_CERT_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
            object_id);
    if (SecUtils_FileExists(file_name))
    {
        SecUtils_RmFile(file_name);
        ++certs_found;

        if (!SecUtils_FileExists(file_name))
            ++certs_deleted;
    }

    snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_CERTINFO_FILENAME_PATTERN, secProcHandle->certstorage_file_dir,
            object_id);
    if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_info))
    {
        SecUtils_RmFile(file_name_info);
    }

    /* soc */

    if (certs_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (certs_found != certs_deleted)
        return SEC_RESULT_ITEM_NON_REMOVABLE;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCertificate_ExtractPublicKey(Sec_CertificateHandle* cert_handle,
        Sec_RSARawPublicKey *public_key)
{
    _Sec_CertificateData *cert_data;
    X509 *x509 = NULL;
    EVP_PKEY *evp_key = NULL;
    RSA *rsa = NULL;

    CHECK_HANDLE(cert_handle);

    cert_data = &(cert_handle->cert_data);

    x509 = SecUtils_DerToX509(cert_data->cert, cert_data->cert_len);

    if (NULL == x509)
    {
        SEC_LOG_ERROR(
                "Could not load X509 certificate from _Sec_CertificateData");
        goto error;
    }

    evp_key = X509_get_pubkey(x509);
    if (evp_key == NULL )
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL )
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    SecUtils_Uint32ToBEBytes(RSA_size(rsa), public_key->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, public_key->n, SecUtils_BEBytesToUint32(public_key->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, public_key->e, 4);

    SEC_EVPPKEY_FREE(evp_key);
    evp_key = NULL;
    SEC_RSA_FREE(rsa);
    rsa = NULL;
    SEC_X509_FREE(x509);
    x509 = NULL;

    return SEC_RESULT_SUCCESS;

    error: if (x509 != NULL )
        SEC_X509_FREE(x509);
    if (evp_key != NULL )
        SEC_EVPPKEY_FREE(evp_key);
    if (rsa != NULL )
        SEC_RSA_FREE(rsa);
    return SEC_RESULT_FAILURE;
}

Sec_Result _Sec_VerifyCertificateWithRSA(Sec_CertificateHandle* cert_handle,
        RSA* rsa)
{
    EVP_PKEY *evp_key = NULL;
    X509 *x509 = NULL;
    int verify_res;

    x509 = SecUtils_DerToX509(&cert_handle->cert_data.cert,
            cert_handle->cert_data.cert_len);

    if (x509 == NULL )
    {
        SEC_LOG_ERROR("SecUtils_DerToX509 failed");
        goto error;
    }

    if (rsa == NULL )
    {
        SEC_LOG_ERROR("_Sec_ReadRSAPublic failed");
        goto error;
    }

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto error;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_X509_FREE(x509);
    SEC_EVPPKEY_FREE(evp_key);

    if (1 != verify_res)
    {
        SEC_LOG_ERROR("X509_verify failed");
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;

    error: if (x509 != NULL )
        SEC_X509_FREE(x509);
    if (evp_key != NULL )
        SEC_EVPPKEY_FREE(evp_key);

    return SEC_RESULT_FAILURE;
}

Sec_Result SecCertificate_Verify(Sec_CertificateHandle* cert_handle,
        Sec_KeyHandle* key_handle)
{
    Sec_RSARawPublicKey rsaPubKey;

    CHECK_HANDLE(cert_handle);
    CHECK_HANDLE(key_handle);

    if (SEC_RESULT_SUCCESS != SecKey_ExtractPublicKey(key_handle, &rsaPubKey))
    {
        SEC_LOG_ERROR("SecKey_ExtractPublicKey failed");
        return SEC_RESULT_FAILURE;

    }

    return SecCertificate_VerifyWithRawPublicKey(cert_handle, &rsaPubKey);
}

Sec_Result SecCertificate_VerifyWithRawPublicKey(
        Sec_CertificateHandle* cert_handle, Sec_RSARawPublicKey* public_key)
{
    X509 *x509 = NULL;
    Sec_Result res;

    CHECK_HANDLE(cert_handle);

    x509 = SecUtils_DerToX509(&cert_handle->cert_data.cert,
            cert_handle->cert_data.cert_len);

    if (x509 == NULL)
    {
        SEC_LOG_ERROR("SecUtils_DerToX509 failed");
        return SEC_RESULT_FAILURE;
    }

    res = SecUtils_VerifyX509WithRawPublicKey(x509, public_key);
    SEC_X509_FREE(x509);

    return res;
}

Sec_Result SecCertificate_Export(Sec_CertificateHandle* cert_handle,
        SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    CHECK_HANDLE(cert_handle);

    if (buffer_len < cert_handle->cert_data.cert_len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer, cert_handle->cert_data.cert,
            cert_handle->cert_data.cert_len);
    *written = cert_handle->cert_data.cert_len;
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecCertificate_Release(Sec_CertificateHandle* certHandle)
{
    CHECK_HANDLE(certHandle);
    SEC_FREE(certHandle);
    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecKey_GetKeyLen(Sec_KeyHandle *keyHandle)
{
    return SecKey_GetKeyLenForKeyType(keyHandle->key_data.info.key_type);
}

Sec_Result SecKey_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_KeyHandle **keyHandle)
{
    Sec_Result result;
    _Sec_KeyData key_data;
    Sec_StorageLoc location;

    CHECK_HANDLE(secProcHandle);

    if (object_id == SEC_OBJECTID_INVALID)
        return SEC_RESULT_INVALID_PARAMETERS;

    result = _Sec_RetrieveKeyData(secProcHandle, object_id, &location,
            &key_data);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    *keyHandle = calloc(1, sizeof(Sec_KeyHandle));
    if (NULL == *keyHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*keyHandle)->object_id = object_id;
    memcpy(&((*keyHandle)->key_data), &key_data, sizeof(_Sec_KeyData));
    (*keyHandle)->location = location;
    (*keyHandle)->proc = secProcHandle;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractPublicKey(Sec_KeyHandle* key_handle,
        Sec_RSARawPublicKey *public_key)
{
    RSA *rsa = NULL;
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(key_handle);

    _Sec_UnwrapKeyBuffer(key_handle->proc, key_handle->key_data.data,
            &clear, key_handle->key_data.info.iv);
    rsa = _Sec_RSAFromBinary(&clear.rsa_key, key_handle->key_data.info.key_type);
    SecUtils_Memset(&clear, 0, sizeof(clear));
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("Could not load RSA key from KeyData");
        return SEC_RESULT_FAILURE;
    }

    SecUtils_Uint32ToBEBytes(RSA_size(rsa), public_key->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, public_key->n, SecUtils_BEBytesToUint32(public_key->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, public_key->e, 4);

    SEC_RSA_FREE(rsa);
    rsa = NULL;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_Generate(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_KeyType keyType, Sec_StorageLoc location)
{
    Sec_KeyHandle *keyHandle;
    _Sec_KeyData key_data;
    RSA *rsa = NULL;
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            == SecKey_GetInstance(secProcHandle, object_id, &keyHandle)
            && keyHandle->location != SEC_STORAGELOC_OEM)
    {
        SecKey_Release(keyHandle);
        return SEC_RESULT_ITEM_ALREADY_PROVISIONED;
    }

    switch (keyType)
    {
        case SEC_KEYTYPE_AES_128:
        case SEC_KEYTYPE_AES_256:
        case SEC_KEYTYPE_HMAC_128:
        case SEC_KEYTYPE_HMAC_160:
        case SEC_KEYTYPE_HMAC_256:
            CHECK_EXACT(
                    RAND_bytes(clear.symetric_key, SecKey_GetKeyLenForKeyType(keyType)),
                    1, error);
            _Sec_WrapKeyBuffer(secProcHandle, &clear, key_data.data, key_data.info.iv);
            SecUtils_Memset(&clear, 0, sizeof(clear));
            key_data.info.key_type = keyType;
            return _Sec_StoreKeyData(secProcHandle, object_id, location,
                    &key_data);

        case SEC_KEYTYPE_RSA_1024:
        case SEC_KEYTYPE_RSA_2048:
            rsa = RSA_generate_key(SecKey_GetKeyLenForKeyType(keyType) * 8,
                    65537, NULL, NULL );
            if (rsa == NULL )
            {
                SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
                goto error;
            }

            /* write private */
            key_data.info.key_type = keyType;
            SecUtils_RSAToPrivBinary(rsa, &clear.rsa_key);

            SEC_RSA_FREE(rsa);
            rsa = NULL;

            _Sec_WrapKeyBuffer(secProcHandle, &clear, key_data.data, key_data.info.iv);
            SecUtils_Memset(&clear, 0, sizeof(clear));

            return _Sec_StoreKeyData(secProcHandle, object_id, location,
                    &key_data);

            /* new: add new key types */

        default:
            break;
    }

    return SEC_RESULT_UNIMPLEMENTED_FEATURE;
    error: if (rsa != NULL )
        SEC_RSA_FREE(rsa);
    return SEC_RESULT_FAILURE;
}

Sec_Result SecKey_Provision(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location, Sec_KeyContainer data_type,
        SEC_BYTE *data, SEC_SIZE data_len)
{
    _Sec_KeyData key_data;
    Sec_Result result;
    Sec_KeyHandle *keyHandle;

    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            == SecKey_GetInstance(secProcHandle, object_id, &keyHandle)
            && keyHandle->location != SEC_STORAGELOC_OEM)
    {
        SecKey_Release(keyHandle);
        return SEC_RESULT_ITEM_ALREADY_PROVISIONED;
    }

    result = _Sec_ProcessKeyContainer(secProcHandle, &key_data, data_type, data,
            data_len, object_id);
    if (SEC_RESULT_SUCCESS != result)
        return result;

    return _Sec_StoreKeyData(secProcHandle, object_id, location, &key_data);
}

Sec_Result SecKey_Delete(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id)
{
    char file_name[SEC_MAX_FILE_PATH_LEN];
    char file_name_info[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMKeyData *ram_key = NULL;
    _Sec_RAMKeyData *ram_key_parent = NULL;
    SEC_SIZE keys_found = 0;
    SEC_SIZE keys_deleted = 0;

    CHECK_HANDLE(secProcHandle);

    /* ram */
    _Sec_FindRAMKeyData(secProcHandle, object_id, &ram_key, &ram_key_parent);
    if (ram_key != NULL )
    {
        if (ram_key_parent == NULL )
            secProcHandle->ram_keys = ram_key->next;
        else
            ram_key_parent->next = ram_key->next;

        SecUtils_Memset(ram_key, 0, sizeof(_Sec_RAMKeyData));

        SEC_FREE(ram_key);

        ++keys_found;
        ++keys_deleted;
    }

    /* file system */
    snprintf(file_name, sizeof(file_name), "%s" SEC_KEY_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
            object_id);
    if (SecUtils_FileExists(file_name))
    {
        SecUtils_RmFile(file_name);
        ++keys_found;

        if (!SecUtils_FileExists(file_name))
            ++keys_deleted;
    }

    snprintf(file_name_info, sizeof(file_name_info), "%s" SEC_KEYINFO_FILENAME_PATTERN, secProcHandle->keystorage_file_dir,
            object_id);
    if (!SecUtils_FileExists(file_name) && SecUtils_FileExists(file_name_info))
    {
        SecUtils_RmFile(file_name_info);
    }

    /* soc */

    if (keys_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (keys_found != keys_deleted)
        return SEC_RESULT_ITEM_NON_REMOVABLE;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_Release(Sec_KeyHandle* keyHandle)
{
    CHECK_HANDLE(keyHandle);

    SEC_FREE(keyHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_KeyType _Sec_GetOutputMacKeyType(Sec_MacAlgorithm alg)
{
    switch (alg)
    {
        case SEC_MACALGORITHM_HMAC_SHA1:
            return SEC_KEYTYPE_HMAC_160;
        case SEC_MACALGORITHM_HMAC_SHA256:
            return SEC_KEYTYPE_HMAC_256;
        case SEC_MACALGORITHM_CMAC_AES_128:
            return SEC_KEYTYPE_AES_128;
        default:
            break;
    }

    return SEC_KEYTYPE_NUM;
}

Sec_Result SecKey_Derive_HKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *salt, SEC_SIZE saltSize, SEC_BYTE *info, SEC_SIZE infoSize)
{
    int r, i;
    SEC_SIZE key_length;
    SEC_BYTE out_key[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_SIZE digest_length;
    SEC_BYTE prk[SEC_MAC_MAX_LEN];
    SEC_SIZE prk_len;
    SEC_BYTE t[SEC_MAC_MAX_LEN];
    SEC_SIZE t_len = 0;
    SEC_SIZE cp_len;
    Sec_KeyHandle *base_key = NULL;
    Sec_KeyHandle *prk_key = NULL;
    Sec_MacHandle *mac_handle = NULL;
    SEC_BYTE loop;
    SEC_OBJECTID temp_key_id = SEC_OBJECTID_INVALID;

    if (!SecKey_IsSymetric(type_derived))
    {
        SEC_LOG_ERROR("Only symetric keys can be derived");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    /* provision base key */
    CHECK_EXACT(_Sec_ProvisionBaseKey(secProcHandle, nonce), SEC_RESULT_SUCCESS,
            error);

    key_length = SecKey_GetKeyLenForKeyType(type_derived);
    digest_length = SecDigest_GetDigestLenForAlgorithm(
            SecMac_GetDigestAlgorithm(macAlgorithm));

    CHECK_EXACT(
            SecKey_GetInstance(secProcHandle, SEC_OBJECTID_BASE_KEY_MAC, &base_key),
            SEC_RESULT_SUCCESS, error);

    /* Extract */
    CHECK_EXACT(
            SecMac_SingleInput(secProcHandle, macAlgorithm, base_key, salt, saltSize, prk, &prk_len),
            SEC_RESULT_SUCCESS, error);

    SecKey_Release(base_key);
    base_key = NULL;

    temp_key_id = SecKey_ObtainFreeObjectId(secProcHandle, SEC_OBJECTID_RESERVED_BASE, SEC_OBJECTID_RESERVED_TOP);
    if (temp_key_id == SEC_OBJECTID_INVALID)
    {
        SEC_LOG_ERROR("SecKey_ObtainFreeObjectId failed");
        goto error;
    }
    CHECK_EXACT(
            SecKey_Provision(secProcHandle, temp_key_id, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SecUtils_RawContainer( _Sec_GetOutputMacKeyType(macAlgorithm)), prk, prk_len),
            SEC_RESULT_SUCCESS, error);

    CHECK_EXACT(
            SecKey_GetInstance(secProcHandle, temp_key_id, &prk_key),
            SEC_RESULT_SUCCESS, error);

    /* Expand */
    r = key_length / digest_length
            + ((key_length % digest_length == 0) ? 0 : 1);

    for (i = 1; i <= r; i++)
    {
        loop = i;

        if (i == r)
            cp_len = key_length % digest_length;
        else
            cp_len = digest_length;

        if (SEC_RESULT_SUCCESS
                != SecMac_GetInstance(secProcHandle, macAlgorithm, prk_key,
                        &mac_handle))
            goto error;

        if (t_len > 0
                && SEC_RESULT_SUCCESS != SecMac_Update(mac_handle, t, t_len))
            goto error;

        if (SEC_RESULT_SUCCESS != SecMac_Update(mac_handle, info, infoSize))
            goto error;

        if (SEC_RESULT_SUCCESS != SecMac_Update(mac_handle, &loop, 1))
            goto error;

        if (SEC_RESULT_SUCCESS != SecMac_Release(mac_handle, t, &t_len))
        {
            mac_handle = NULL;
            goto error;
        }

        memcpy(out_key + (i - 1) * digest_length, t, cp_len);
    }

    SecKey_Release(prk_key);
    prk_key = NULL;
    SecKey_Delete(secProcHandle, temp_key_id);

    /* store key */
    CHECK_EXACT(
            SecKey_Provision(secProcHandle, object_id_derived, loc_derived, SecUtils_RawContainer(type_derived), out_key, key_length),
            SEC_RESULT_SUCCESS, error);

    SecUtils_Memset(out_key, 0, sizeof(out_key));
    SecUtils_Memset(prk, 0, sizeof(prk));
    SecUtils_Memset(t, 0, sizeof(t));

    return SEC_RESULT_SUCCESS;

    error: if (mac_handle != NULL )
        SecMac_Release(mac_handle, t, &t_len);
    if (base_key != NULL )
        SecKey_Release(base_key);
    if (prk_key != NULL )
        SecKey_Release(prk_key);
    SecKey_Delete(secProcHandle, temp_key_id);

    SecUtils_Memset(out_key, 0, sizeof(out_key));
    SecUtils_Memset(prk, 0, sizeof(prk));
    SecUtils_Memset(t, 0, sizeof(t));

    return SEC_RESULT_FAILURE;
}

Sec_Result SecKey_Derive_ConcatKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_DigestAlgorithm digestAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *otherInfo, SEC_SIZE otherInfoSize)
{
    int i;
    SEC_BYTE loop[] =
        { 0, 0, 0, 0 };
    SEC_BYTE hash[SEC_DIGEST_MAX_LEN];
    SEC_SIZE key_length;
    SEC_SIZE digest_length;
    int r;
    Sec_KeyHandle *base_key = NULL;
    _Sec_ClearKeyBuffer derived_clear;
    Sec_DigestHandle *digestHandle = NULL;
    Sec_Result res;

    if (!SecKey_IsSymetric(type_derived))
    {
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    /* provision base key */
    CHECK_EXACT(_Sec_ProvisionBaseKey(secProcHandle, nonce), SEC_RESULT_SUCCESS,
            error);

    key_length = SecKey_GetKeyLenForKeyType(type_derived);
    digest_length = SecDigest_GetDigestLenForAlgorithm(digestAlgorithm);
    r = key_length / digest_length
            + ((key_length % digest_length == 0) ? 0 : 1);

    CHECK_EXACT(
            SecKey_GetInstance(secProcHandle, SEC_OBJECTID_BASE_KEY_AES, &base_key),
            SEC_RESULT_SUCCESS, error);

    for (i = 1; i <= r; ++i)
    {
        loop[3] = i;

        CHECK_EXACT(
                SecDigest_GetInstance(secProcHandle, digestAlgorithm, &digestHandle),
                SEC_RESULT_SUCCESS, error);
        CHECK_EXACT( SecDigest_Update(digestHandle, loop, sizeof(loop)),
                SEC_RESULT_SUCCESS, error);
        CHECK_EXACT( SecDigest_UpdateWithKey(digestHandle, base_key),
                SEC_RESULT_SUCCESS, error);
        CHECK_EXACT(
                SecDigest_Update(digestHandle, otherInfo, otherInfoSize),
                SEC_RESULT_SUCCESS, error);

        res = SecDigest_Release(digestHandle, hash, &digest_length);
        digestHandle = NULL;
        if (res != SEC_RESULT_SUCCESS)
            goto error;

        if (i < r || (key_length % digest_length == 0))
        {
            memcpy(derived_clear.symetric_key + digest_length * (i - 1), hash,
                    digest_length);
        }
        else
        {
            memcpy(derived_clear.symetric_key + digest_length * (i - 1), hash,
                    key_length % digest_length);
        }
    }

    SecKey_Release(base_key);
    base_key = NULL;

    /* compute digest over the key */
    /*
     if (keyDigestOutput != NULL )
     {
     CHECK_EXACT(
     SecDigest_GetInstance(secProcHandle, keyDigestAlgorithm, &digestHandle),
     SEC_RESULT_SUCCESS, error);
     CHECK_EXACT(
     SecDigest_Update(digestHandle, derived_clear.symetric_key, key_length),
     SEC_RESULT_SUCCESS, error);
     res = SecDigest_Release(digestHandle, keyDigestOutput, keyDigestSize);
     digestHandle = NULL;
     if (res != SEC_RESULT_SUCCESS)
     goto error;
     }
     */

    /* store key */
    CHECK_EXACT(
            SecKey_Provision(secProcHandle, object_id_derived, loc_derived, SecUtils_RawContainer(type_derived), derived_clear.symetric_key, key_length),
            SEC_RESULT_SUCCESS, error);

    SecUtils_Memset(&derived_clear, 0, sizeof(derived_clear));

    return SEC_RESULT_SUCCESS;

    error: SecUtils_Memset(&derived_clear, 0, sizeof(derived_clear));
    if (base_key != NULL )
        SecKey_Release(base_key);
    /*
     if (digestHandle != NULL )
     SecDigest_Release(digestHandle, keyDigestOutput, keyDigestSize);
     */

    return SEC_RESULT_FAILURE;
}

Sec_Result SecKey_Derive_PBEKDF(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_KeyType type_derived,
        Sec_StorageLoc loc_derived, Sec_MacAlgorithm macAlgorithm,
        SEC_BYTE *nonce,
        SEC_BYTE *salt, SEC_SIZE saltSize, SEC_SIZE numIterations)
{
    SEC_BYTE out_key[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_SIZE out_key_length;
    Sec_KeyHandle *base_key = NULL;
    SEC_SIZE base_key_len;
    _Sec_ClearKeyBuffer clear;
    int openssl_res = 0;
    Sec_Result res;
    const EVP_MD *digest = NULL;

    if (!SecKey_IsSymetric(type_derived))
    {
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    /* provision base key */
    if (SEC_RESULT_SUCCESS != _Sec_ProvisionBaseKey(secProcHandle, nonce))
    {
        SEC_LOG_ERROR("Could not provision base key");
        return SEC_RESULT_FAILURE;
    }

    out_key_length = SecKey_GetKeyLenForKeyType(type_derived);

    if (SEC_RESULT_SUCCESS
            != SecKey_GetInstance(secProcHandle, SEC_OBJECTID_BASE_KEY_MAC,
                    &base_key))
        return SEC_RESULT_FAILURE;

    _Sec_UnwrapKeyBuffer(secProcHandle, base_key->key_data.data, &clear, base_key->key_data.info.iv);
    base_key_len = SecKey_GetKeyLen(base_key);

    SecKey_Release(base_key);
    base_key = NULL;

    if (macAlgorithm == SEC_MACALGORITHM_HMAC_SHA1)
        digest = EVP_sha1();
    else
        digest = EVP_sha256();

    openssl_res = PKCS5_PBKDF2_HMAC((const char *) clear.symetric_key,
            base_key_len, salt, saltSize, numIterations, digest, out_key_length,
            out_key);
    SecUtils_Memset(&clear, 0, sizeof(clear));
    if (!openssl_res)
    {
        SEC_LOG_ERROR("PKCS5_PBKDF2_HMAC failed");
        return SEC_RESULT_FAILURE;
    }

    /* store key */
    res = SecKey_Provision(secProcHandle, object_id_derived, loc_derived,
            SecUtils_RawContainer(type_derived), out_key, out_key_length);
    SecUtils_Memset(out_key, 0, sizeof(out_key));

    return res;
}

Sec_Result SecKey_Derive_VendorAes128(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id_derived, Sec_StorageLoc loc_derived, SEC_BYTE *input, SEC_SIZE input_len)
{
    SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
    SEC_SIZE digest_len;
    Sec_CipherAlgorithm cipherAlgorithm = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
    Sec_CipherMode cipherMode = SEC_CIPHERMODE_ENCRYPT;
    Sec_KeyType keyType = SEC_KEYTYPE_AES_128;
    int i;
    SEC_SIZE keySize;
    Sec_KeyHandle *tempKey = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;
    SEC_SIZE cipher_output_len;
    SEC_BYTE cipher_output[SEC_SYMETRIC_KEY_MAX_LEN];
    SEC_BYTE *cipher_key = secProcHandle->ssk;
    SEC_OBJECTID temp_key_id = SEC_OBJECTID_INVALID;
    SEC_BYTE c1[16];
    SEC_BYTE c2[16];
    SEC_BYTE *c[] = { c1, c2 };

    if (SEC_RESULT_SUCCESS != SecDigest_SingleInput(secProcHandle, SEC_DIGESTALGORITHM_SHA256,
            input, input_len, digest, &digest_len))
    {
        SEC_LOG_ERROR("SecDigest_SingleInput failed");
        return SEC_RESULT_FAILURE;
    }

    keySize = SecKey_GetKeyLenForKeyType(keyType);

    /* setup key ladder inputs */
    memcpy(c1, digest, 16);
    memcpy(c2, digest+16, 16);

    for (i = 1; i <= 2; i++)
    {
        /* encrypt digest */
        temp_key_id = SecKey_ObtainFreeObjectId(secProcHandle, SEC_OBJECTID_RESERVED_BASE, SEC_OBJECTID_RESERVED_TOP);
        if (temp_key_id == SEC_OBJECTID_INVALID)
        {
            res = SEC_RESULT_FAILURE;
            SEC_LOG_ERROR("SecKey_ObtainFreeObjectId failed");
            goto done;
        }
        res = SecKey_Provision(secProcHandle, temp_key_id, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_RAW_AES_128, cipher_key, keySize);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        res = SecKey_GetInstance(secProcHandle, temp_key_id, &tempKey);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        res = SecCipher_SingleInput(secProcHandle, cipherAlgorithm, cipherMode, tempKey, NULL,
                c[i-1], keySize, cipher_output, sizeof(cipher_output), &cipher_output_len);
        if (SEC_RESULT_SUCCESS != res)
            goto done;
        SecKey_Release(tempKey);
        tempKey = NULL;

        cipher_key = cipher_output;
    }

    res = SecKey_Provision(secProcHandle, object_id_derived,
            loc_derived, SEC_KEYCONTAINER_RAW_AES_128, cipher_key, keySize);

    done:
    if (tempKey != NULL)
        SecKey_Release(tempKey);
    SecKey_Delete(secProcHandle, temp_key_id);

    return res;
}

Sec_KeyType SecKey_GetKeyType(Sec_KeyHandle* keyHandle)
{
    if (keyHandle == NULL)
        return SEC_KEYTYPE_NUM;

    return keyHandle->key_data.info.key_type;
}

Sec_Result SecOpenSSL_ExtractRawSymetricFromKeyHandle(Sec_KeyHandle *key_handle, SEC_BYTE *rawKey, SEC_SIZE *keyLen)
{
    _Sec_ClearKeyBuffer clear;

    CHECK_HANDLE(key_handle);

    if (!SecKey_IsSymetric(SecKey_GetKeyType(key_handle)))
    {
        SEC_LOG_ERROR("Specified key is not symetric");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    _Sec_UnwrapKeyBuffer(key_handle->proc, key_handle->key_data.data, &clear, key_handle->key_data.info.iv);

    *keyLen = SecKey_GetKeyLen(key_handle);
    memcpy(rawKey, clear.symetric_key, *keyLen);

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpenSSL_ExtractRawPrivRSAFromKeyHandle(Sec_KeyHandle *key_handle, Sec_RSARawPrivateKey *raw)
{
    _Sec_ClearKeyBuffer clear;
    Sec_KeyType keyType;

    CHECK_HANDLE(key_handle);

    keyType = SecKey_GetKeyType(key_handle);

    if (keyType != SEC_KEYTYPE_RSA_1024
            && keyType != SEC_KEYTYPE_RSA_2048)
    {
        SEC_LOG_ERROR("Specified key is not private RSA");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    _Sec_UnwrapKeyBuffer(key_handle->proc, key_handle->key_data.data, &clear, key_handle->key_data.info.iv);
    memcpy(raw, &(clear.rsa_key), sizeof(Sec_RSARawPrivateKey));

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOpenSSL_ExtractRawPubRSAFromKeyHandle(Sec_KeyHandle *key_handle, Sec_RSARawPublicKey *raw)
{
    _Sec_ClearKeyBuffer clear;
    Sec_KeyType keyType;

    CHECK_HANDLE(key_handle);

    keyType = SecKey_GetKeyType(key_handle);

    if (keyType != SEC_KEYTYPE_RSA_1024
            && keyType != SEC_KEYTYPE_RSA_2048
            && keyType != SEC_KEYTYPE_RSA_1024_PUBLIC
            && keyType != SEC_KEYTYPE_RSA_2048_PUBLIC)
    {
        SEC_LOG_ERROR("Specified key is not a public RSA");
        return SEC_RESULT_INVALID_PARAMETERS;
    }

    _Sec_UnwrapKeyBuffer(key_handle->proc, key_handle->key_data.data, &clear, key_handle->key_data.info.iv);
    memcpy(raw->n, clear.rsa_key.n, sizeof(raw->n));
    memcpy(raw->e, clear.rsa_key.e, sizeof(raw->e));
    memcpy(raw->modulus_len_be, clear.rsa_key.modulus_len_be, sizeof(raw->modulus_len_be));

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ComputeBaseKeyDigest(Sec_ProcessorHandle* secProcHandle, SEC_BYTE *nonce,
        Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len)
{
    Sec_KeyHandle *base_key = NULL;
    SEC_SIZE base_key_len;
    _Sec_ClearKeyBuffer clear;
    Sec_Result res;

    /* provision base key */
    if (SEC_RESULT_SUCCESS != _Sec_ProvisionBaseKey(secProcHandle, nonce))
    {
        SEC_LOG_ERROR("Could not provision base key");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
            != SecKey_GetInstance(secProcHandle, SEC_OBJECTID_BASE_KEY_MAC,
                    &base_key))
    {
        return SEC_RESULT_FAILURE;
    }

    _Sec_UnwrapKeyBuffer(secProcHandle, base_key->key_data.data, &clear, base_key->key_data.info.iv);
    base_key_len = SecKey_GetKeyLen(base_key);
    SecKey_Release(base_key);
    base_key = NULL;

    res = SecDigest_SingleInput(secProcHandle, alg, clear.symetric_key, base_key_len, digest, digest_len);

    SecUtils_Memset(&clear, 0, sizeof(clear));

    return res;
}

Sec_ProcessorHandle* SecKey_GetProcessor(Sec_KeyHandle* key)
{
    if (key == NULL)
        return NULL;

    return key->proc;
}

Sec_Result SecBundle_GetInstance(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_BundleHandle **bundleHandle)
{
    Sec_Result result;
    Sec_StorageLoc location;
    _Sec_BundleData bundle_data;

    *bundleHandle = NULL;

    CHECK_HANDLE(secProcHandle);

    if (object_id == SEC_OBJECTID_INVALID)
        return SEC_RESULT_INVALID_PARAMETERS;

    result = _Sec_RetrieveBundleData(secProcHandle, object_id, &location,
            &bundle_data);
    if (result != SEC_RESULT_SUCCESS)
        return result;

    *bundleHandle = calloc(1, sizeof(Sec_BundleHandle));
    if (NULL == *bundleHandle)
    {
        SEC_LOG_ERROR("malloc failed");
        return SEC_RESULT_FAILURE;
    }
    (*bundleHandle)->object_id = object_id;
    memcpy(&((*bundleHandle)->bundle_data), &bundle_data, sizeof(_Sec_BundleData));
    (*bundleHandle)->location = location;
    (*bundleHandle)->proc = secProcHandle;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecBundle_Provision(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id, Sec_StorageLoc location,
        SEC_BYTE *data, SEC_SIZE data_len)
{
    _Sec_BundleData bundle_data;
    Sec_BundleHandle *bundleHandle;

    CHECK_HANDLE(secProcHandle);

    if (SEC_RESULT_SUCCESS
            == SecBundle_GetInstance(secProcHandle, object_id, &bundleHandle)
            && bundleHandle->location != SEC_STORAGELOC_OEM)
    {
        SecBundle_Release(bundleHandle);
        return SEC_RESULT_ITEM_ALREADY_PROVISIONED;
    }

    if (location == SEC_STORAGELOC_OEM)
    {
        SEC_LOG_ERROR(
                "Cannot provision individual bundles into SEC_STORAGELOC_OEM storage on this platform");
        return SEC_RESULT_FAILURE;
    }

    if (data_len > SEC_BUNDLE_MAX_LEN)
    {
        SEC_LOG_ERROR("Input bundle is too large");
        return SEC_RESULT_FAILURE;
    }

    memcpy(bundle_data.bundle, data, data_len);
    bundle_data.bundle_len = data_len;

    return _Sec_StoreBundleData(secProcHandle, object_id, location, &bundle_data);
}

Sec_Result SecBundle_Delete(Sec_ProcessorHandle* secProcHandle, SEC_OBJECTID object_id)
{
    char file_name[SEC_MAX_FILE_PATH_LEN];
    _Sec_RAMBundleData *ram_bundle = NULL;
    _Sec_RAMBundleData *ram_bundle_parent = NULL;
    SEC_SIZE bundles_found = 0;
    SEC_SIZE bundles_deleted = 0;

    CHECK_HANDLE(secProcHandle);

    /* ram */
    _Sec_FindRAMBundleData(secProcHandle, object_id, &ram_bundle, &ram_bundle_parent);
    if (ram_bundle != NULL)
    {
        if (ram_bundle_parent == NULL)
            secProcHandle->ram_bundles = ram_bundle->next;
        else
            ram_bundle_parent->next = ram_bundle->next;

        SecUtils_Memset(ram_bundle, 0, sizeof(_Sec_RAMBundleData));

        SEC_FREE(ram_bundle);

        ++bundles_found;
        ++bundles_deleted;
    }

    /* file system */
    snprintf(file_name, sizeof(file_name), "%s" SEC_BUNDLE_FILENAME_PATTERN,
            secProcHandle->bundlestorage_file_dir, object_id);
    if (SecUtils_FileExists(file_name))
    {
        SecUtils_RmFile(file_name);
        ++bundles_found;

        if (!SecUtils_FileExists(file_name))
            ++bundles_deleted;
    }

    if (bundles_found == 0)
        return SEC_RESULT_NO_SUCH_ITEM;

    if (bundles_found != bundles_deleted)
    {
        SEC_LOG_ERROR(
                "Could not delete the specified bundle.  It is stored in a non-removable location.");
        return SEC_RESULT_ITEM_NON_REMOVABLE;
    }

    return SEC_RESULT_SUCCESS;
}


Sec_Result SecBundle_Export(Sec_BundleHandle* bundle_handle,
        SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    CHECK_HANDLE(bundle_handle);

    if (buffer_len < bundle_handle->bundle_data.bundle_len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer, bundle_handle->bundle_data.bundle,
            bundle_handle->bundle_data.bundle_len);
    *written = bundle_handle->bundle_data.bundle_len;
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecBundle_Release(Sec_BundleHandle* bundleHandle)
{
    CHECK_HANDLE(bundleHandle);

    SEC_FREE(bundleHandle);

    return SEC_RESULT_SUCCESS;
}
#endif
