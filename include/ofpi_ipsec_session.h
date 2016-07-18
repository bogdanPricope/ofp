/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_SESSION_H__
#define __OFP_IPSEC_SESSION_H__

#include "odp.h"
#include "ofpi_ipsec_cache_common.h"

int ofp_ipsec_create_session(struct ofp_ipsec_cache_auth_cipher *,
	struct ofp_ipsec_cache_processing *,
	enum ofp_ipsec_direction dir,
	odp_crypto_session_t *);
int ofp_ipsec_destroy_session(odp_crypto_session_t);

#endif /* __OFP_IPSEC_SESSION_H__ */


