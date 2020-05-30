/*
 *  Copyright (C) 2019 Vasyl Gello <vasek.gello@gmail.com>
 *  This file is part of cryptopass - https://github.com/basilgello/cryptopass
 *
 *  SPDX-License-Identifier: Apache-2.0
 *  See LICENSE for more information
 */

#ifndef _LIBCRYPTOPASS_H_
#define _LIBCRYPTOPASS_H_

char cryptopass(const char *masterpassword, const unsigned char *salt,
		char *derivedpassword, unsigned int derivedcapacity);

#endif // _LIBCRYPTOPASS_H_
