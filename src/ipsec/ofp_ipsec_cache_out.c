/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "odp.h"
#include "api/ofp_config.h"
#include "api/ofp_queue.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_session.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_cli.h"

#define SHM_NAME_IPSEC_CACHE_OUT "OfpIPsecCHOutShMem"

#ifdef OFP_STATIC_IPSEC_CACHE_OUT_CONFIG
# define OFP_IPSEC_CACHE_OUT_RWLOCK_INIT(_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_RLOCK(_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_RUNLOCK(_lock)
#else
# define OFP_IPSEC_CACHE_OUT_RWLOCK_INIT(_lock) odp_rwlock_init(&_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(_lock) odp_rwlock_write_lock(&_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(_lock) odp_rwlock_write_unlock(&_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_RLOCK(_lock) odp_rwlock_read_lock(&_lock)
# define OFP_IPSEC_CACHE_OUT_RWLOCK_RUNLOCK(_lock) odp_rwlock_read_unlock(&_lock)
#endif /* OFP_STATIC_IPSEC_CACHE_OUT_CONFIG */

#define	CACHE_OUT_NHASH_LOG2	6
#define	CACHE_OUT_NHASH		(1 << CACHE_OUT_NHASH_LOG2)
#define	CACHE_OUT_HMASK		(CACHE_OUT_NHASH - 1)
#define	CACHE_OUT_HASH(x) ((x) & CACHE_OUT_HMASK)

struct ofp_ipsec_cache_out_list_entry {
	OFP_TAILQ_ENTRY(ofp_ipsec_cache_out_list_entry) tqe;
	struct ofp_ipsec_cache_out_entry entry;
};
OFP_TAILQ_HEAD(ofp_ipsec_cache_out, ofp_ipsec_cache_out_list_entry);

struct ofp_ipsec_cache_out_hash_entry {
	struct ofp_ipsec_cache_out list;
	odp_rwlock_t rwlock;
};

struct ofp_ipsec_cache_out_mem {
	struct ofp_ipsec_cache_out_list_entry entries[OFP_IPSEC_CACHE_OUT_SIZE];
	struct ofp_ipsec_cache_out free_entries;
	odp_rwlock_t free_entries_rwlock;

	struct ofp_ipsec_cache_out_hash_entry hash[CACHE_OUT_NHASH];
};

static __thread struct ofp_ipsec_cache_out_mem *shm;

static int ofp_ipsec_cache_out_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_CACHE_OUT, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_ipsec_cache_out_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_IPSEC_CACHE_OUT) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_ipsec_cache_out_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_CACHE_OUT);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_ipsec_cache_out_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_ipsec_cache_out_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	OFP_TAILQ_INIT(&shm->free_entries);
	OFP_IPSEC_CACHE_OUT_RWLOCK_INIT(shm->free_entries_rwlock);

	for (i = OFP_IPSEC_CACHE_OUT_SIZE - 1; i >= 0; i--)
		OFP_TAILQ_INSERT_HEAD(&shm->free_entries,
			&shm->entries[i], tqe);

	for (i = 0; i < CACHE_OUT_NHASH; i++) {
		OFP_TAILQ_INIT(&shm->hash[i].list);
		OFP_IPSEC_CACHE_OUT_RWLOCK_INIT(shm->hash[i].rwlock);
	}

	return 0;
}

int ofp_ipsec_cache_out_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_ipsec_cache_out_flush(), rc);

	CHECK_ERROR(ofp_ipsec_cache_out_free_shared_memory(), rc);

	return rc;
}


int ofp_ipsec_cache_out_add(struct ofp_spd_entry *sp,
	struct ofp_sad_entry *sa)
{
	struct ofp_ipsec_cache_out_hash_entry *hash_entry = NULL;
	uint32_t hash_key = 0;
	struct ofp_ipsec_selectors *sl;
	struct ofp_ipsec_cache_out_list_entry *new_entry;
	struct ofp_ipsec_conf *conf;

	conf = ofp_ipsec_config_get();
	if (!conf)
		return -1;

	if (sp->action != OFP_SPD_ACTION_PROTECT) {
		OFP_ERR("Invalid entry type.");
		return -1;
	}

	OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(shm->free_entries_rwlock);
	new_entry = OFP_TAILQ_FIRST(&shm->free_entries);
	if (new_entry)
		OFP_TAILQ_REMOVE(&shm->free_entries, new_entry, tqe);
	OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(shm->free_entries_rwlock);

	if (!new_entry) {
		OFP_ERR("Fail to alloc new outbound cache entry: no entry available");
		return -1;
	}

/* Fill the entry */
	memcpy(&new_entry->entry.trivial_selectors, &sa->trivial_selectors,
		sizeof(sa->trivial_selectors));

	new_entry->entry.action = sp->action;

	new_entry->entry._protect.spi = sa->spi;
	new_entry->entry._protect.protocol = sp->protect_protocol;
	new_entry->entry._protect.protect_mode = sp->protect_mode;
	if (new_entry->entry._protect.protect_mode == OFP_IPSEC_MODE_TUNNEL) {
		memcpy(&new_entry->entry._protect.protect_tunnel_src_addr,
			&sp->protect_tunnel_src_addr,
			sizeof (sp->protect_tunnel_src_addr));
		memcpy(&new_entry->entry._protect.protect_tunnel_dest_addr,
			&sp->protect_tunnel_dest_addr,
			sizeof (sp->protect_tunnel_dest_addr));
	}
	new_entry->entry._protect.seq_number = 0;
	new_entry->entry._protect.seq_number_overflow = sa->seq_number_overflow;

	/* Processing settings */
	if (conf->param.async_mode)
		new_entry->entry._protect.proc.pref_mode = ODP_CRYPTO_ASYNC;
	else
		new_entry->entry._protect.proc.pref_mode = ODP_CRYPTO_SYNC;

	/* Algs*/
	new_entry->entry._protect.algs.auth_cipher = sa->auth_cipher;

	/* auth */
	new_entry->entry._protect.algs.auth_alg = sa->auth_alg;
	memcpy(&new_entry->entry._protect.algs.auth_key, &sa->auth_key,
		sizeof(sa->auth_key));
	ofp_get_auth_alg(new_entry->entry._protect.algs.auth_alg,
		&new_entry->entry._protect.algs.auth_alg_desc);

	/* cipher */
	new_entry->entry._protect.algs.cipher_alg = sa->cipher_alg;
	memcpy(&new_entry->entry._protect.algs.cipher_key, &sa->cipher_key,
		sizeof(sa->cipher_key));
	memcpy(&new_entry->entry._protect.algs.cipher_iv, &sa->cipher_iv,
		sizeof(sa->cipher_iv));
	ofp_get_cipher_alg(new_entry->entry._protect.algs.cipher_alg,
		&new_entry->entry._protect.algs.cipher_alg_desc);

	/* session */
	new_entry->entry._protect.session = ODP_CRYPTO_SESSION_INVALID;

	/* update lock*/
#ifdef OFP_IPSEC_CACHE_OUT_PROTECTED_UPDATE
	odp_rwlock_init(&new_entry->entry.update_lock);
#endif /* OFP_IPSEC_CACHE_OUT_PROTECTED_UPDATE */

#ifndef OFP_IPSEC_SESSION_LAZY_CREATE
	if (ofp_ipsec_create_session(&new_entry->entry._protect.algs,
		&new_entry->entry._protect.proc,
		OFP_IPSEC_DIRECTION_OUT,
		&new_entry->entry._protect.session)) {
		OFP_ERR("Failed to create IPsec session.");
		OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, new_entry, tqe);
		OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
		return -1;
	}
#endif /* OFP_IPSEC_SESSION_LAZY_CREATE */

	sl = &new_entry->entry.trivial_selectors;
	hash_key = CACHE_OUT_HASH(sl->dest_addr_ranges.ofp_trivial_range_addr.addr.addr4);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(hash_entry->rwlock);
	OFP_TAILQ_INSERT_TAIL(&hash_entry->list, new_entry, tqe);
	OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(hash_entry->rwlock);

	return 0;
}

int ofp_ipsec_cache_out_del(struct ofp_ipsec_selectors *sl)
{
	int ret = -1;
	struct ofp_ipsec_cache_out_hash_entry *hash_entry = NULL;
	uint32_t hash_key = 0;
	struct ofp_ipsec_cache_out_list_entry *itr;

	hash_key = CACHE_OUT_HASH(sl->dest_addr_ranges.ofp_trivial_range_addr.addr.addr4);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(itr, &hash_entry->list, tqe)
		if (ofp_ipsec_selectors_equal(sl,
			&itr->entry.trivial_selectors))
			break;
	if (itr) {
		OFP_TAILQ_REMOVE(&hash_entry->list, itr, tqe);
		if (ofp_ipsec_destroy_session(itr->entry._protect.session))
			OFP_ERR("Failed to destroy IPsec session spi = %d.",
				itr->entry._protect.spi);
		ret = 0;
	} else {
		ret = -1;
		OFP_ERR("Outbound cache entry not found!");
	}
	OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(hash_entry->rwlock);

	if (itr) {
		OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, itr, tqe);
		OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	}
	return ret;
}

struct ofp_ipsec_cache_out_entry *ofp_ipsec_cache_out_search(struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_cache_out_hash_entry *hash_entry;
	uint32_t hash_key;
	struct ofp_ipsec_cache_out_list_entry *itr;
	struct ofp_ipsec_cache_out_entry *cache_entry = NULL;

	hash_key = CACHE_OUT_HASH(sl_pkt->dest_addr_ranges.ofp_trivial_range_addr.addr.addr4);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_OUT_RWLOCK_RLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(itr, &hash_entry->list, tqe)
		if (ofp_ipsec_selectors_match_sa_pkt(&itr->entry.trivial_selectors,
			sl_pkt)) {
			cache_entry = &itr->entry;
			break;
		}
	OFP_IPSEC_CACHE_OUT_RWLOCK_RUNLOCK(hash_entry->rwlock);

	return cache_entry;
}

static int ofp_ipsec_cache_out_flush_entry(
	struct ofp_ipsec_cache_out_hash_entry * entry)
{
	struct ofp_ipsec_cache_out_list_entry *iter, *titer;

	OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(entry->rwlock);
	OFP_IPSEC_CACHE_OUT_RWLOCK_WLOCK(shm->free_entries_rwlock);

	OFP_TAILQ_FOREACH_SAFE(iter, &entry->list, tqe, titer) {
		if (ofp_ipsec_destroy_session(iter->entry._protect.session))
			OFP_ERR("Failed to destroy IPsec session spi = %d.",
				iter->entry._protect.spi);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);
	}

	OFP_TAILQ_INIT(&entry->list);

	OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	OFP_IPSEC_CACHE_OUT_RWLOCK_WUNLOCK(entry->rwlock);

	return 0;
}

int ofp_ipsec_cache_out_flush(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < CACHE_OUT_NHASH; i++)
		ret += ofp_ipsec_cache_out_flush_entry(&shm->hash[i]);

	return ret;
}

static void ofp_ipsec_cache_out_dump_entry(int fd,
	struct ofp_ipsec_cache_out_hash_entry *hash_entry)
{
	struct ofp_ipsec_cache_out_list_entry *iter;

	OFP_IPSEC_CACHE_OUT_RWLOCK_RLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(iter, &hash_entry->list, tqe) {
		cacheout_dump(fd, &iter->entry);
		ofp_sendf(fd, "\r\n");
	}
	OFP_IPSEC_CACHE_OUT_RWLOCK_RUNLOCK(hash_entry->rwlock);
}

int ofp_ipsec_cache_out_dump(int fd)
{
	int i;

	ofp_sendf(fd, "Outbound Cache Database:\r\n");
	for (i = 0; i < CACHE_OUT_NHASH; i++)
		ofp_ipsec_cache_out_dump_entry(fd, &shm->hash[i]);

	return 0;
}
