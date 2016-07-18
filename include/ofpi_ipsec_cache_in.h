/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_IPSEC_CACHE_IN_H__
#define __OFPI_IPSEC_CACHE_IN_H__

#include "odp.h"
#include "api/ofp_ipsec_common.h"
#include "api/ofp_ipsec_selectors.h"
#include "api/ofp_ipsec_cache_in.h"
#include "ofpi_ipsec_cache_common.h"
#include "ofpi_ipsec_sad.h"

struct ofp_ipsec_cache_in_entry {
/* keys */
	uint32_t			spi;
	enum ofp_ipsec_protocol		protocol;

/* SAD check (post decrypt)*/
	struct ofp_ipsec_selectors	check_selectors;

/* auth/crypto details*/
	enum ofp_ipsec_mode		protect_mode;

	uint32_t			seq_number;
	odp_bool_t			seq_number_overflow;

/* Processing settings*/
	struct ofp_ipsec_cache_processing proc;

/* Authentication and cipher settings */
	struct ofp_ipsec_cache_auth_cipher algs;

/* ODP session */
	odp_crypto_session_t		session;

/* Update lock*/
	odp_rwlock_t update_lock;
};

int ofp_ipsec_cache_in_init_global(void);
int ofp_ipsec_cache_in_term_global(void);
int ofp_ipsec_cache_in_lookup_shared_memory(void);

int ofp_ipsec_cache_in_add(struct ofp_sad_entry *sa);
int ofp_ipsec_cache_in_del(uint32_t spi, enum ofp_ipsec_protocol protocol);
struct ofp_ipsec_cache_in_entry *ofp_ipsec_cache_in_search(uint32_t spi,
	enum ofp_ipsec_protocol protocol);


#ifdef OFP_IPSEC_CACHE_IN_PROTECTED_UPDATE
# define OFP_IPSEC_CACHE_IN_LOCK(_entry) odp_rwlock_write_lock(&_entry->update_lock)
# define OFP_IPSEC_CACHE_IN_UNLOCK(_entry) odp_rwlock_write_unlock(&_entry->update_lock)
#else
# define OFP_IPSEC_CACHE_IN_LOCK(_entry)
# define OFP_IPSEC_CACHE_IN_UNLOCK(_entry)
#endif
#endif /* __OFPI_IPSEC_CACHE_IN_H__ */
