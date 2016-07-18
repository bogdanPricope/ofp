/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IPSEC_CACHE_COMMON_H__
#define __OFPI_IPSEC_CACHE_COMMON_H__

#include "odp.h"
#include "api/ofp_ipsec_common.h"
#include "ofpi_ipsec_alg.h"

struct ofp_ipsec_cache_auth_cipher {
	odp_bool_t			auth_cipher;  /**< Auth/cipher order */

/*Authentication algorithm*/
	ofp_auth_alg_t			auth_alg;
	struct ofp_ipsec_key		auth_key;
	struct auth_entry		auth_alg_desc;

/* Cypher algorithm */
	ofp_cipher_alg_t		cipher_alg;
	struct ofp_ipsec_key		cipher_key;
	struct ofp_ipsec_cipher_iv	cipher_iv;
	struct cipher_entry		cipher_alg_desc;
};

struct ofp_ipsec_cache_processing {
	odp_crypto_op_mode_t		pref_mode;  /**< sync vs async */
};

#endif /*__OFPI_IPSEC_CACHE_COMMON_H__ */


