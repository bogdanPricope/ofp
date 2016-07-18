/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_ALG_H__
#define __OFP_IPSEC_ALG_H__

typedef enum {
	 /** No authentication algorithm specified */
	OFP_AUTH_ALG_NULL = 0,
	/** HMAC-MD5 with 96 bit key */
	OFP_AUTH_ALG_MD5_96,
	/** SHA256 with 128 bit key */
	OFP_AUTH_ALG_SHA256_128,
	/** AES128 in Galois/Message Authentication Code */
	OFP_AUTH_ALG_AES128_GMAC,
	OFP_AUTH_ALG_MAX
} ofp_auth_alg_t;

typedef enum {
	/** No cipher algorithm specified */
	OFP_CIPHER_ALG_NULL = 0,
	/** DES */
	OFP_CIPHER_ALG_DES,
	/** Triple DES with cipher block chaining */
	OFP_CIPHER_ALG_3DES_CBC,
	/** AES128 with cipher block chaining */
	OFP_CIPHER_ALG_AES128_CBC,
	/** AES128 in Galois/Counter Mode */
	OFP_CIPHER_ALG_AES128_GCM,
	OFP_CIPHER_ALG_MAX
} ofp_cipher_alg_t;

#endif /*__OFP_IPSEC_ALG_H__ */

