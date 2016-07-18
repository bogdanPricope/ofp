/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_IPSEC_CACHE_OUT_H__
#define __OFPI_IPSEC_CACHE_OUT_H__

#include "odp.h"
#include "api/ofp_config.h"
#include "api/ofp_ipsec_common.h"
#include "api/ofp_ipsec_selectors.h"
#include "api/ofp_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_common.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"


struct ofp_ipsec_cache_out_entry {
	struct ofp_ipsec_selectors	trivial_selectors;

	enum ofp_spd_action		action;

/* Protect info */
	struct {
		uint32_t			spi;
		enum ofp_ipsec_protocol		protocol;
		enum ofp_ipsec_mode		protect_mode;

		uint32_t			seq_number;
		odp_bool_t			seq_number_overflow;

/* Processing settings*/
		struct ofp_ipsec_cache_processing proc;

/* Authentication and cipher settings */
		struct ofp_ipsec_cache_auth_cipher algs;

/* tunnel addresses*/
		struct ofp_ipsec_addr protect_tunnel_src_addr;
		struct ofp_ipsec_addr protect_tunnel_dest_addr;

/* ODP session */
		odp_crypto_session_t		session;
	} _protect;

/* Update lock*/
	odp_rwlock_t update_lock;
};

int ofp_ipsec_cache_out_init_global(void);
int ofp_ipsec_cache_out_term_global(void);
int ofp_ipsec_cache_out_lookup_shared_memory(void);


int ofp_ipsec_cache_out_add(struct ofp_spd_entry *,
	struct ofp_sad_entry *);
int ofp_ipsec_cache_out_del(struct ofp_ipsec_selectors *);
struct ofp_ipsec_cache_out_entry *ofp_ipsec_cache_out_search(
	struct ofp_ipsec_selectors *);

int ofp_ipsec_cache_out_update_on_SP(struct ofp_spd_entry *);

#ifdef OFP_IPSEC_CACHE_OUT_PROTECTED_UPDATE
# define OFP_IPSEC_CACHE_OUT_LOCK(_entry) odp_rwlock_write_lock(&_entry->update_lock)
# define OFP_IPSEC_CACHE_OUT_UNLOCK(_entry) odp_rwlock_write_unlock(&_entry->update_lock)
#else
# define OFP_IPSEC_CACHE_OUT_LOCK(_entry)
# define OFP_IPSEC_CACHE_OUT_UNLOCK(_entry)
#endif

#endif /* __OFPI_IPSEC_CACHE_OUT_H__ */
