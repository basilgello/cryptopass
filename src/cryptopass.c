/*
 *  Copyright (C) 2019 Vasyl Gello <vasek.gello@gmail.com>
 *  This file is part of cryptopass - https://github.com/basilgello/cryptopass
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  See LICENSE for more information
 */

#ifdef NO_CONFIGURE_BUILD
#define PACKAGE_NAME "cryptopass"
#define PACKAGE_VERSION "1.0"
#define PACKAGE_BUGREPORT "vasek.gello@gmail.com"
#else
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#include <base64/base64.h>
#include <fastpbkdf2/fastpbkdf2.h>

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

int main(int argc, char **argv)
{
	const int DEFAULT_PASSWORD_LENGTH = 25;
	const int MAX_PASSWORD_LENGTH = 32;

	const int MAX_INPUT_SIZE = 128;
	const int PASSWORD_BUFFER_SIZE = 40;
	const int PASSWORD_LENGTH_BUFFER_SIZE = 8;

	const int SALT_BUFFER_SIZE = 2 * MAX_INPUT_SIZE + 8;

	int counter = 0;
	struct termios tp, save;

	char masterpassword[MAX_INPUT_SIZE];
	size_t masterpasslen = 0;
	char *mp = NULL;

	char username[MAX_INPUT_SIZE];
	size_t usernamelen = 0;

	char domain[MAX_INPUT_SIZE];
	size_t domainlen = 0;

	char salt[SALT_BUFFER_SIZE];
	size_t saltlen = 0;

	char passlenbuf[PASSWORD_LENGTH_BUFFER_SIZE];
	size_t passlenbuflen = 0;

	char derivedpassword[PASSWORD_BUFFER_SIZE];
	size_t derivedpasswordlen = DEFAULT_PASSWORD_LENGTH;

	/* Print usage if "-h" or "--help" specified */

	if (argc >= 2) {
		if (!strncmp(argv[1], "-h", 2) ||
		    !strncmp(argv[1], "--help", 6)) {
			fprintf(stderr,
				"Usage: cryptopass [username] [domain] [derivedpasswordlen]\n");

			return 0;
		}

		if (!strncmp(argv[1], "-v", 2) ||
		    !strncmp(argv[1], "--version", 9)) {
			fprintf(stderr,
				"%s %s\nCopyright (C) 2019-2020 Vasyl Gello <%s>\n",
				PACKAGE_NAME, PACKAGE_VERSION,
				PACKAGE_BUGREPORT);

			return 0;
		}
	}

	/* Instantiate arrays */

	memset(derivedpassword, 0, PASSWORD_BUFFER_SIZE);
	memset(domain, 0, MAX_INPUT_SIZE);
	memset(masterpassword, 0, MAX_INPUT_SIZE);
	memset(passlenbuf, 0, PASSWORD_LENGTH_BUFFER_SIZE);
	memset(salt, 0, SALT_BUFFER_SIZE);
	memset(username, 0, MAX_INPUT_SIZE);

	/* Get username */

	if (argc < 2) {
		printf("Username: ");

		if (fgets(username, MAX_INPUT_SIZE - 1, stdin)) {
			usernamelen = strlen(username);

			if (username[usernamelen - 1] == '\n')
				username[--usernamelen] = '\0';
			if (username[usernamelen - 1] == '\r')
				username[--usernamelen] = '\0';

			if (!usernamelen) {
				fprintf(stderr, "ERROR: Empty username!\n");

				return 1;
			}
		}
	} else {
		usernamelen = strlen(argv[1]);

		if (!usernamelen) {
			fprintf(stderr, "ERROR: Empty username!\n");

			return 1;
		}

		if (usernamelen >= MAX_INPUT_SIZE) {
			fprintf(stderr,
				"WARNING: Username truncated to %d bytes!\n",
				MAX_INPUT_SIZE - 1);

			usernamelen = MAX_INPUT_SIZE - 1;
		}

		memcpy(username, argv[1], usernamelen);

		if (username[usernamelen - 1] == '\n')
			username[--usernamelen] = '\0';
		if (username[usernamelen - 1] == '\r')
			username[--usernamelen] = '\0';
	}

	/* Get domain name */

	if (argc < 3) {
		printf("Domain: ");

		if (fgets(domain, MAX_INPUT_SIZE - 1, stdin)) {
			domainlen = strlen(domain);

			if (domain[domainlen - 1] == '\n')
				domain[--domainlen] = '\0';
			if (domain[domainlen - 1] == '\r')
				domain[--domainlen] = '\0';

			if (!domainlen) {
				fprintf(stderr, "ERROR: Empty domain!\n");

				return 1;
			}
		}

	} else {
		domainlen = strlen(argv[2]);

		if (!domainlen) {
			fprintf(stderr, "ERROR: Empty domain!\n");

			return 1;
		}

		if (domainlen >= MAX_INPUT_SIZE) {
			fprintf(stderr,
				"WARNING: Domain truncated to %d bytes!\n",
				MAX_INPUT_SIZE - 1);

			domainlen = MAX_INPUT_SIZE - 1;
		}

		memcpy(domain, argv[2], domainlen);

		if (domain[domainlen - 1] == '\n')
			domain[--domainlen] = '\0';
		if (domain[domainlen - 1] == '\r')
			domain[--domainlen] = '\0';
	}

	/* Parse and check requested length of derived password */

	if (argc < 4) {
		printf("Password length (1-32, default 25):");

		if (fgets(passlenbuf, PASSWORD_LENGTH_BUFFER_SIZE, stdin)) {
			passlenbuflen = strlen(passlenbuf);

			if (passlenbuf[passlenbuflen - 1] == '\n')
				passlenbuf[--passlenbuflen] = '\0';
			if (passlenbuf[passlenbuflen - 1] == '\r')
				passlenbuf[--passlenbuflen] = '\0';
		}
	}

	if (argc >= 4) {
		passlenbuflen = strlen(argv[3]);

		if (passlenbuflen >= PASSWORD_LENGTH_BUFFER_SIZE) {
			passlenbuflen = PASSWORD_LENGTH_BUFFER_SIZE - 1;
		}

		if (passlenbuflen) {
			strncpy(passlenbuf, argv[3], passlenbuflen);

			if (passlenbuf[passlenbuflen - 1] == '\n')
				passlenbuf[--passlenbuflen] = '\0';
			if (passlenbuf[passlenbuflen - 1] == '\r')
				passlenbuf[--passlenbuflen] = '\0';
		}
	}

	if (!sscanf(passlenbuf, "%ld", &derivedpasswordlen)) {
		fprintf(stderr,
			"WARNING: Requested password length is not an integer between 1 and 32!\n");
		fprintf(stderr, "WARNING: Fallling back to default (%d)!\n",
			DEFAULT_PASSWORD_LENGTH);

		derivedpasswordlen = DEFAULT_PASSWORD_LENGTH;
	}

	if (!derivedpasswordlen || derivedpasswordlen > 32) {
		fprintf(stderr,
			"ERROR: Requested password length can be between 1 and 32!\n");

		return 1;
	}

	/* Make salt concatenating username and domain with '@' */

	saltlen = usernamelen + domainlen + 2;

	strcpy(salt, username);
	strcat(salt, "@");
	strcat(salt, domain);

#ifdef HAVE_TERMIOS_H
	/* Retrieve current terminal settings, turn echoing off */

	if (tcgetattr(0, &tp) == -1) {
		fprintf(stderr, "ERROR: tcgetattr\n");

		return 2;
	}

	save = tp; /* So we can restore settings later */
	tp.c_lflag &= ~ECHO; /* ECHO off, other bits unchanged */
	if (tcsetattr(0, TCSAFLUSH, &tp) == -1) {
		fprintf(stderr, "ERROR: tcsetattr\n");

		return 2;
	}
#endif

	/* Retrieve the master password */

	printf("Enter master password: ");
	fflush(stdout);

	mp = fgets(masterpassword, MAX_INPUT_SIZE - 1, stdin);

	printf("\n");

#ifdef HAVE_TERMIOS_H
	/* Restore original terminal settings */

	if (tcsetattr(0, TCSANOW, &save) == -1) {
		fprintf(stderr, "ERROR: tcsetattr\n");

		return 2;
	}
#endif

	if (!mp) {
		fprintf(stderr, "ERROR: Empty master password!\n");

		return 1;
	}

	masterpasslen = strlen(masterpassword);

	if (masterpassword[masterpasslen - 1] == '\n')
		masterpassword[--masterpasslen] = '\0';
	if (masterpassword[masterpasslen - 1] == '\r')
		masterpassword[--masterpasslen] = '\0';

	if (!masterpasslen) {
		fprintf(stderr, "ERROR: Empty master password!\n");

		return 1;
	}

	/* Make cryptopass of the supplied data */

	if (!cryptopass(masterpassword, salt, derivedpassword,
			derivedpasswordlen)) {
		fprintf(stderr, "ERROR: cryptopass error!\n");

		return 3;
	}

	/* Print the derived password */

	printf("Derived password: %s\n", derivedpassword);

	/* Gracefully exit */

	return 0;
}
