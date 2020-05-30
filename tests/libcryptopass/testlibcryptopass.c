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

#include <libcryptopass/libcryptopass.h>

typedef struct {
	char *master_password;
	char *salt;
	unsigned int derived_password_length;
	char *derived_password;
} testitem;

int main(int argc, char **argv)
{
	const testitem const testvector[] = {
		{ "testpassword", "testlogin@testdomain.com", 25, "efpbGPH4wUw//pgDaPfvR7eak" },
		{ "d0d1d2d3d4d5d6d7d8d9d0", "some@random", 20, "UJrRaF7DjVo359niCGxL" }
	};

	char generated_password[40];
	unsigned int counter = 0;

	for (counter = 0; counter < sizeof(testvector) / sizeof(testitem);
	     counter++) {
		fprintf(stderr,
			"Processing %d: { '%s', '%s', '%u' } -> '%s':\n",
			counter,
			testvector[counter].master_password,
			testvector[counter].salt,
			testvector[counter].derived_password_length,
			testvector[counter].derived_password);

		memset(generated_password, 0, sizeof(generated_password));

		if (!cryptopass(testvector[counter].master_password,
			testvector[counter].salt,
			generated_password,
			testvector[counter].derived_password_length)) {
			fprintf(stderr, "ERROR: cryptopass() returned error!\n");

			return 1;

		}

		if (strncmp(generated_password,
			testvector[counter].derived_password,
			testvector[counter].derived_password_length)) {
			fprintf(stderr,
				"ERROR: Produced password '%s', expected '%s'!\n",
				generated_password,
				testvector[counter].derived_password);

			return 1;
		}
	}

	return 0;
}
