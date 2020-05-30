/*
 *  Copyright (C) 2019 Vasyl Gello <vasek.gello@gmail.com>
 *  This file is part of cryptopass - https://github.com/basilgello/cryptopass
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  See LICENSE for more information
 */

#include "libcryptopass.h"

#include <base64/base64.h>
#include <fastpbkdf2/fastpbkdf2.h>

#include <stdlib.h>
#include <string.h>

char cryptopass(const char *masterpassword, const unsigned char *salt,
		char *derivedpassword, unsigned int derivedcapacity)
{
	unsigned char digest[32]; /* 32 bytes for SHA-256 */

	char *b64_digest = NULL;
	size_t b64_len = 0;

	/* Some sanity checks */

	if (!masterpassword || !salt || !derivedpassword || !derivedcapacity)
		return 0;

	/* Instantiate the digest and password arrays */

	memset(digest, 0, 32);

	/*
	   Digest the PBKDF2-HMAC-SHA256-5000 from
	   master password and salt
	*/

	fastpbkdf2_hmac_sha256(masterpassword, strlen(masterpassword), salt,
			       strlen(salt), 5000, /* iterations */
			       digest, 32 /* sizeof(digest) */);

	/* Encode the digest with Base64 */

	b64_digest = base64_encode(digest, 32, &b64_len);

	if (b64_len < derivedcapacity) {
		free(b64_digest);
		b64_digest = NULL;
		b64_len = 0;
		return 0;
	}

	/* Copy requested amount of bytes into output array */

	strncpy(derivedpassword, b64_digest, derivedcapacity);

	/* Clean up */

	free(b64_digest);

	b64_digest = NULL;
	b64_len = 0;

	return 1;
}
