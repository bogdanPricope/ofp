/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_SAD_H__
#define __OFP_IPSEC_SAD_H__

#include "odp.h"
#include "ofp_ipsec_common.h"
#include "ofp_ipsec_selectors.h"
#include "ofp_ipsec_alg.h"

enum ofp_sa_liftime {
	OFP_SA_LIFTIME_NOT_SET = 0,
	OFP_SA_LIFTIME_BYTES,
	OFP_SA_LIFTIME_TIME,
	OFP_SA_LIFTIME_BYTES_TIME
};

struct ofp_sad_entry {
	struct ofp_ipsec_selectors	trivial_selectors;
	uint32_t			spi;
	enum ofp_ipsec_protocol		protocol;

	enum ofp_ipsec_mode		incoming_protect_mode;

	odp_bool_t			seq_number_overflow;

	odp_bool_t			auth_cipher;  /**< Auth/cipher order */

/*Authentication algorithm*/
	ofp_auth_alg_t			auth_alg;
	struct ofp_ipsec_key		auth_key;

/* Cypher algorithm */
	ofp_cipher_alg_t		cipher_alg;
	struct ofp_ipsec_key		cipher_key;
	struct ofp_ipsec_cipher_iv	cipher_iv;

#if 0
/* Lifetime*/
	enum ofp_sa_liftime		lifetime_type;
	uint64_t			lifetime_bytes;
	odp_time_t			lifetime_timr;

/* others */
	uint64_t	anti_replay_wdw;
	odp_bool_t	statefull_fragment_check;
	odp_bool_t	bypass_DF;
	uint8_t		DSCP;
	odp_bool_t	bypass_DSCP;
	uint32_t	path_MTU;
#endif /* 0 */

};

void ofp_ipsec_sad_entry_init(struct ofp_sad_entry *);

int ofp_ipsec_sad_add(enum ofp_ipsec_direction	direction,
	struct ofp_sad_entry *sad_entry);
int ofp_ipsec_sad_del(enum ofp_ipsec_direction	direction,
	struct ofp_ipsec_selectors *trivial_selectors,
	uint32_t spi,
	enum ofp_ipsec_protocol protocol);

int ofp_ipsec_sad_flush(void);
int ofp_ipsec_sad_dump(int fd);

int ofp_ipsec_sad_update_cache_out(void);
int ofp_ipsec_sad_update_cache_in(void);

#endif /* __OFP_IPSEC_SAD_H__ */
