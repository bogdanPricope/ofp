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
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_ipsec_session.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_cli.h"

#define SHM_NAME_IPSEC_CACHE_IN "OfpIPsecCHInShMem"

#ifdef OFP_STATIC_IPSEC_CACHE_IN_CONFIG
# define OFP_IPSEC_CACHE_IN_RWLOCK_INIT(_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_RLOCK(_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_RUNLOCK(_lock)
#else
# define OFP_IPSEC_CACHE_IN_RWLOCK_INIT(_lock) odp_rwlock_init(&_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(_lock) odp_rwlock_write_lock(&_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(_lock) odp_rwlock_write_unlock(&_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_RLOCK(_lock) odp_rwlock_read_lock(&_lock)
# define OFP_IPSEC_CACHE_IN_RWLOCK_RUNLOCK(_lock) odp_rwlock_read_unlock(&_lock)
#endif /* OFP_STATIC_IPSEC_CACHE_IN_CONFIG */

#define	CACHE_IN_NHASH_LOG2	6
#define	CACHE_IN_NHASH		(1 << CACHE_IN_NHASH_LOG2)
#define	CACHE_IN_HMASK		(CACHE_IN_NHASH - 1)
#define	CACHE_IN_HASH(x) ((x) & CACHE_IN_HMASK)

struct ofp_ipsec_cache_in_list_entry {
	OFP_TAILQ_ENTRY(ofp_ipsec_cache_in_list_entry) tqe;
	struct ofp_ipsec_cache_in_entry entry;
};
OFP_TAILQ_HEAD(ofp_ipsec_cache_in, ofp_ipsec_cache_in_list_entry);

struct ofp_ipsec_cache_in_hash_entry {
	struct ofp_ipsec_cache_in list;
	odp_rwlock_t rwlock;
};

struct ofp_ipsec_cache_in_mem {
	struct ofp_ipsec_cache_in_list_entry entries[OFP_IPSEC_CACHE_IN_SIZE];
	struct ofp_ipsec_cache_in free_entries;
	odp_rwlock_t free_entries_rwlock;

	struct ofp_ipsec_cache_in_hash_entry hash[CACHE_IN_NHASH];
};

static __thread struct ofp_ipsec_cache_in_mem *shm;

static int ofp_ipsec_cache_in_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_CACHE_IN, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_ipsec_cache_in_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_IPSEC_CACHE_IN) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_ipsec_cache_in_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_CACHE_IN);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_ipsec_cache_in_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_ipsec_cache_in_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	OFP_TAILQ_INIT(&shm->free_entries);
	OFP_IPSEC_CACHE_IN_RWLOCK_INIT(shm->free_entries_rwlock);

	for (i = OFP_IPSEC_CACHE_IN_SIZE - 1; i >= 0; i--)
		OFP_TAILQ_INSERT_HEAD(&shm->free_entries,
			&shm->entries[i], tqe);

	for (i = 0; i < CACHE_IN_NHASH; i++) {
		OFP_TAILQ_INIT(&shm->hash[i].list);
		OFP_IPSEC_CACHE_IN_RWLOCK_INIT(shm->hash[i].rwlock);
	}

	return 0;
}

int ofp_ipsec_cache_in_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_ipsec_cache_in_flush(), rc);

	CHECK_ERROR(ofp_ipsec_cache_in_free_shared_memory(), rc);

	return rc;
}


int ofp_ipsec_cache_in_add(struct ofp_sad_entry *sa)
{
	struct ofp_ipsec_cache_in_list_entry *new_entry;
	struct ofp_ipsec_cache_in_hash_entry *hash_entry = NULL;
	uint32_t hash_key = 0;
	struct ofp_ipsec_conf *conf;

	conf = ofp_ipsec_config_get();
	if (!conf)
		return -1;

	OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(shm->free_entries_rwlock);
	new_entry = OFP_TAILQ_FIRST(&shm->free_entries);
	if (new_entry)
		OFP_TAILQ_REMOVE(&shm->free_entries, new_entry, tqe);
	OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(shm->free_entries_rwlock);

	if (!new_entry) {
		OFP_ERR("Fail to alloc new outbound cache entry: no entry available");
		return -1;
	}

/* Fill the entry */
	new_entry->entry.spi = sa->spi;
	new_entry->entry.protocol = sa->protocol;

	memcpy(&new_entry->entry.check_selectors,
		&sa->trivial_selectors,
		sizeof(new_entry->entry.check_selectors));

	new_entry->entry.protect_mode = sa->incoming_protect_mode;

       new_entry->entry.seq_number = 0;
	new_entry->entry.seq_number_overflow = sa->seq_number_overflow;

	/* Processing settings */
	if (conf->param.async_mode)
		new_entry->entry.proc.pref_mode = ODP_CRYPTO_ASYNC;
	else
		new_entry->entry.proc.pref_mode = ODP_CRYPTO_SYNC;

	/* Algs*/
	new_entry->entry.algs.auth_cipher = sa->auth_cipher;

	/* auth */
	new_entry->entry.algs.auth_alg = sa->auth_alg;
	memcpy(&new_entry->entry.algs.auth_key, &sa->auth_key,
		sizeof(new_entry->entry.algs.auth_key));
	ofp_get_auth_alg(new_entry->entry.algs.auth_alg,
		&new_entry->entry.algs.auth_alg_desc);

	/* cipher */
	new_entry->entry.algs.cipher_alg = sa->cipher_alg;
	memcpy(&new_entry->entry.algs.cipher_key, &sa->cipher_key,
		sizeof(new_entry->entry.algs.cipher_key));
	memcpy(&new_entry->entry.algs.cipher_iv, &sa->cipher_iv,
		sizeof(new_entry->entry.algs.cipher_iv));
	ofp_get_cipher_alg(new_entry->entry.algs.cipher_alg,
		&new_entry->entry.algs.cipher_alg_desc);


	/* session */
	new_entry->entry.session = ODP_CRYPTO_SESSION_INVALID;

	/* update lock*/
#ifdef OFP_IPSEC_CACHE_IN_PROTECTED_UPDATE
	odp_rwlock_init(&new_entry->entry.update_lock);
#endif /* OFP_IPSEC_CACHE_IN_PROTECTED_UPDATE */

#ifndef OFP_IPSEC_SESSION_LAZY_CREATE
	if (ofp_ipsec_create_session(&new_entry->entry.algs,
		&new_entry->entry.proc,
		OFP_IPSEC_DIRECTION_IN,
		&new_entry->entry.session)) {
		OFP_ERR("Failed to create IPsec session.");
		OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, new_entry, tqe);
		OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
		return -1;
	}
#endif /*OFP_IPSEC_SESSION_LAZY_CREATE*/

	hash_key = CACHE_IN_HASH(new_entry->entry.spi);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(hash_entry->rwlock);
	OFP_TAILQ_INSERT_TAIL(&hash_entry->list, new_entry, tqe);
	OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(hash_entry->rwlock);

	return 0;
}

int ofp_ipsec_cache_in_del(uint32_t spi, enum ofp_ipsec_protocol protocol)
{
	int ret = -1;
	struct ofp_ipsec_cache_in_hash_entry *hash_entry = NULL;
	uint32_t hash_key = 0;
	struct ofp_ipsec_cache_in_list_entry *itr = NULL;

	hash_key = CACHE_IN_HASH(spi);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(itr, &hash_entry->list, tqe)
		if (itr->entry.spi == spi && itr->entry.protocol == protocol)
			break;
	if (itr) {
		OFP_TAILQ_REMOVE(&hash_entry->list, itr, tqe);
		if (ofp_ipsec_destroy_session(itr->entry.session))
			OFP_ERR("Failed to destroy IPsec session spi = %d.",
				itr->entry.spi);
		ret = 0;
	} else {
		ret = -1;
		OFP_ERR("inbound cache entry not found!");
	}
	OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(hash_entry->rwlock);

	if (itr) {
		OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, itr, tqe);
		OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	}
	return ret;
}

struct ofp_ipsec_cache_in_entry *ofp_ipsec_cache_in_search(uint32_t spi,
	enum ofp_ipsec_protocol protocol)
{
	struct ofp_ipsec_cache_in_entry *cache_entry = NULL;
	struct ofp_ipsec_cache_in_hash_entry *hash_entry;
	uint32_t hash_key;
	struct ofp_ipsec_cache_in_list_entry *itr;

	hash_key = CACHE_IN_HASH(spi);
	hash_entry = &shm->hash[hash_key];

	OFP_IPSEC_CACHE_IN_RWLOCK_RLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(itr, &hash_entry->list, tqe)
		if (itr->entry.spi == spi && itr->entry.protocol == protocol) {
			cache_entry = &itr->entry;
			break;
		}
	OFP_IPSEC_CACHE_IN_RWLOCK_RUNLOCK(hash_entry->rwlock);

	return cache_entry;
}

static int ofp_ipsec_cache_in_flush_entry(struct ofp_ipsec_cache_in_hash_entry * entry)
{
	struct ofp_ipsec_cache_in_list_entry *iter, *titer;

	OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(entry->rwlock);
	OFP_IPSEC_CACHE_IN_RWLOCK_WLOCK(shm->free_entries_rwlock);

	OFP_TAILQ_FOREACH_SAFE(iter, &entry->list, tqe, titer) {
		if (ofp_ipsec_destroy_session(iter->entry.session))
			OFP_ERR("Failed to destroy IPsec session spi = %d.",
				iter->entry.spi);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);
	}

	OFP_TAILQ_INIT(&entry->list);

	OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	OFP_IPSEC_CACHE_IN_RWLOCK_WUNLOCK(entry->rwlock);

	return 0;
}

int ofp_ipsec_cache_in_flush(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < CACHE_IN_NHASH; i++)
		ret += ofp_ipsec_cache_in_flush_entry(&shm->hash[i]);

	return ret;
}

static void ofp_ipsec_cache_in_dump_entry(int fd,
	struct ofp_ipsec_cache_in_hash_entry *hash_entry)
{
	struct ofp_ipsec_cache_in_list_entry *iter;

	OFP_IPSEC_CACHE_IN_RWLOCK_RLOCK(hash_entry->rwlock);
	OFP_TAILQ_FOREACH(iter, &hash_entry->list, tqe) {
		cachein_dump(fd, &iter->entry);
		ofp_sendf(fd, "\r\n");
	}
	OFP_IPSEC_CACHE_IN_RWLOCK_RUNLOCK(hash_entry->rwlock);
}

int ofp_ipsec_cache_in_dump(int fd)
{
	int i;

	ofp_sendf(fd, "Inbound Cache Database:\r\n");
	for (i = 0; i < CACHE_IN_NHASH; i++)
		ofp_ipsec_cache_in_dump_entry(fd, &shm->hash[i]);

	return 0;
}
