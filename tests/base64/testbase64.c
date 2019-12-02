/*
 *  Copyright (C) 2019 Vasyl Gello <vasek.gello@gmail.com>
 *  This file is part of cryptopass - https://github.com/basilgello/cryptopass
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  See LICENSE for more information
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <base64/base64.h>

typedef struct {
	unsigned int input_length;
	char *input;
	char *output;
} testitem;

int main(int argc, char **argv)
{
	// RFC 4648

	// BASE64("") = ""
	// BASE64("f") = "Zg=="
	// BASE64("fo") = "Zm8="
	// BASE64("foo") = "Zm9v"
	// BASE64("foob") = "Zm9vYg=="
	// BASE64("fooba") = "Zm9vYmE="
	// BASE64("foobar") = "Zm9vYmFy"

	const testitem const testvector[] = { { 0, "", "" },
					      { 1, "f", "Zg==" },
					      { 2, "fo", "Zm8=" },
					      { 3, "foo", "Zm9v" },
					      { 4, "foob", "Zm9vYg==" },
					      { 5, "fooba", "Zm9vYmE=" },
					      { 6, "foobar", "Zm9vYmFy" } };

	unsigned int counter = 0;
	size_t b64_len = 0;
	char *encoded = NULL;
	char *decoded = NULL;

	for (counter = 0; counter < sizeof(testvector) / sizeof(testitem);
	     counter++) {
		fprintf(stderr, "Processing %d: '%s' -> '%s':\n", counter,
			testvector[counter].input, testvector[counter].output);

		b64_len = 0;
		encoded = base64_encode(testvector[counter].input,
					testvector[counter].input_length,
					&b64_len);

		if (!encoded) {
			fprintf(stderr, "ERROR: Could not encode '%s'!\n",
				testvector[counter].input);

			return 1;
		}

		// Special case: empty input returns empty output

		if (!b64_len && !testvector[counter].input_length)
			continue;

		// Jouni malinen's Base64 encoder adds newline at the end
		// of encoded string

		encoded[--b64_len] = '\0';

		if (strcmp(encoded, testvector[counter].output)) {
			fprintf(stderr,
				"ERROR: Encoding '%s' produces '%s', expected '%s'!\n",
				testvector[counter].input, encoded,
				testvector[counter].output);

			free(encoded);
			encoded = NULL;

			return 1;
		}

		decoded = base64_decode(encoded, strlen(encoded), &b64_len);

		if (!decoded) {
			fprintf(stderr, "ERROR: Could not decode '%s'!\n",
				testvector[counter].input);

			return 1;
		}

		if (strcmp(decoded, testvector[counter].input)) {
			fprintf(stderr,
				"ERROR: Decoding '%s' produces '%s', expected '%s'!\n",
				encoded, decoded, testvector[counter].input);

			free(encoded);
			free(decoded);

			encoded = NULL;
			decoded = NULL;

			return 1;
		}
	}

	free(encoded);
	free(decoded);

	encoded = NULL;
	decoded = NULL;

	return 0;
}
