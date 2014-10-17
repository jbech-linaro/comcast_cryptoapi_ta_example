/*
 * Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * liABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <err.h>
#include <comcast_crypto_gp_ta.h>
#include <sec_security.h>
#include <sec_security_openssl.h>
#include <tee_client_api.h>

#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32

void dump_hash(const char *message, uint8_t *hash, size_t len)
{
	size_t i;

	printf("Hash of message: '%s' is:\n", message);
	for (i = 0; i < len; i++)
		printf("%02x", hash[i]);
	printf("\n");
}

/*
 * This function does the actual communication with the TEE. This buffer (the
 * message) will be hashed, and then returned back from secure world and will be
 * stored in the argument variable called digest.
 */
TEEC_Result comcast_ta_digest(Sec_DigestAlgorithm alg, void *buffer,
			      size_t buffer_size, void *digest,
			      size_t digest_len)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;

	/*
	 * This is what makes the call communicate with a certain Trusted
	 * Application. In this case, the demo Comcast TA (see also
	 * comcast_crypto_gp_ta.h, those must be the same UUID).
	 */
	TEEC_UUID uuid = COMCAST_CRYPTO_EXAMPLE_TA;
	uint32_t err_origin;
	char *message = buffer;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	printf("Opening the session to Comcast RDK TA\n");
	/*
	 * Open a session to the Comcast Crypto TA (this corresponds to the
	 * function TA_OpenSessionEntryPoint() in the TA).
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	/*
	 * Here we are stating that the first parameter should be a buffer and
	 * it should be considered as an input buffer, this is where we provide
	 * the message to be hashed. The second parameter is also a buffer,
	 * however this is configured as an output buffer and this will be used
	 * for storing the final digest (i.e, the resulting hash).
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = (void *)message;
	op.params[0].tmpref.size = strlen(message);
	
	op.params[1].tmpref.buffer = (void *)digest;
	op.params[1].tmpref.size = digest_len;

	/*
	 * Execute the hash function in the TA by invoking it using either the
	 * TAF_SHA1 or TAF_SHA256 id (see the corresponding function
	 * TA_InvokeCommandEntryPoint() in the TA).
	 */
	printf("Invoking a function in Comcast RDK TA\n");
	switch(alg) {
	case SEC_DIGESTALGORITHM_SHA1:
		res = TEEC_InvokeCommand(&sess, TAF_SHA1, &op, &err_origin);
		break;
	case SEC_DIGESTALGORITHM_SHA256:
		res = TEEC_InvokeCommand(&sess, TAF_SHA256, &op, &err_origin);
		break;
	default:
		printf("Algorithm not supported\n");
		res = TEEC_ERROR_BAD_PARAMETERS;
	}

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* We're done with the TA, close the session ... */
	TEEC_CloseSession(&sess);

	/* ... and destroy the context. */
	TEEC_FinalizeContext(&ctx);

	return res;
}

int main(int argc, char *argv[])
{
	Sec_ProcessorHandle sec_proc_handle;
	Sec_DigestHandle *digest_handle = NULL;
	SEC_SIZE digest_size = 0;
	SEC_BYTE *message = (SEC_BYTE *)"abc";
	Sec_Result res;
	uint8_t digest[SEC_DIGEST_MAX_LEN];
	memset(digest, 0, sizeof(digest));

	/*
	 * First example: SHA1 hash done in secure world, initiated from Comcast
	 * Crypto API's.
	 *
	 * There is one problem when trying to show this and that because there
	 * is no 1:1 mapping between the involved interfaces. Comcast Crypto API
	 * uses init, update and final for the hashes (which is what you
	 * normally do in hashing), whilst GlobalPlatform Internal API only
	 * presents/exposes two functions for the same in the so called "GP
	 * Internal API". Those functions are TEE_DigestUpdate and
	 * TEE_DoDigestFinal. Based on this "limitation" and to be able to
	 * demonstrate how to open up the communication from Comcast Crypto API
	 * to secure world, we had to put a few ifdefs in the code coming from
	 * Comcast Crypto API. Also, due to this, the actual call to secure
	 * world will only be done in SecDigest_Release. As a concept/reference
	 * this is working, but for production this needs to be handled in
	 * another way.
	 */
	res =  SecDigest_GetInstance(&sec_proc_handle, SEC_DIGESTALGORITHM_SHA1,
				     &digest_handle);
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_GetInstance failed with code 0x%x", res);

	res = SecDigest_Update(digest_handle, NULL, 0);
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_Update failed with code 0x%x", res);

	res = SecDigest_Release(digest_handle, (SEC_BYTE *)digest,
				&digest_size, message, strlen((char *)message));
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_Release failed with code 0x%x", res);

	dump_hash((const char *)message, digest, digest_size);

	/*
	 * Second example: SHA256 hash done in secure world, initiated from
	 * Comcast Crypto API's.
	 */
	memset(digest, 0, sizeof(digest));
	res =  SecDigest_GetInstance(&sec_proc_handle, SEC_DIGESTALGORITHM_SHA256,
				     &digest_handle);
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_GetInstance failed with code 0x%x", res);

	res = SecDigest_Update(digest_handle, NULL, 0);
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_Update failed with code 0x%x", res);

	res = SecDigest_Release(digest_handle, (SEC_BYTE *)digest,
				&digest_size, message, strlen((char *)message));
	if (res != SEC_RESULT_SUCCESS)
		errx(1, "SecDigest_Release failed with code 0x%x", res);

	dump_hash((const char *)message, digest, digest_size);

	return 0;
}
