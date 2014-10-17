#ifndef _COMCAST_CRYPTO_GP_CLIENT_H
#define _COMCAST_CRYPTO_GP_CLIENT_H
#include <tee_client_api.h>
#include <sec_security.h>

TEEC_Result comcast_ta_digest(Sec_DigestAlgorithm alg, void *buffer,
			      size_t buffer_size, void *digest,
			      size_t digest_len);

#endif
