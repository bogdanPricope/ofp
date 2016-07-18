/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IPSEC_ALG_H__
#define __OFPI_IPSEC_ALG_H__

#include "odp.h"
#include "api/ofp_ipsec_alg.h"

struct auth_entry {
	odp_auth_alg_t odp_name;

	uint32_t key_len;
	uint32_t icv_len;
};

struct cipher_entry {
	odp_cipher_alg_t odp_name;

	uint32_t key_len;
	uint32_t iv_len;
	uint32_t blk_size;
};

int ofp_get_auth_alg(ofp_auth_alg_t, struct auth_entry *);
int ofp_get_cipher_alg(ofp_cipher_alg_t, struct cipher_entry *);
#endif /*__OFPI_IPSEC_ALG_H__ */

