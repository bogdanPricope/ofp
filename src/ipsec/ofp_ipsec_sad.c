/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_config.h"
#include "api/ofp_queue.h"
#include "ofpi_ipsec_sad.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_cli.h"

#define SHM_NAME_IPSEC_SAD "OfpIPsecSADShMem"

#ifdef OFP_STATIC_IPSEC_SAD_CONFIG
# define OFP_IPSEC_SAD_RWLOCK_INIT(_lock)
# define OFP_IPSEC_SAD_RWLOCK_WLOCK(_lock)
# define OFP_IPSEC_SAD_RWLOCK_WUNLOCK(_lock)
# define OFP_IPSEC_SAD_RWLOCK_RLOCK(_lock)
# define OFP_IPSEC_SAD_RWLOCK_RUNLOCK(_lock)
#else
# define OFP_IPSEC_SAD_RWLOCK_INIT(_lock) odp_rwlock_init(&_lock)
# define OFP_IPSEC_SAD_RWLOCK_WLOCK(_lock) odp_rwlock_write_lock(&_lock)
# define OFP_IPSEC_SAD_RWLOCK_WUNLOCK(_lock) odp_rwlock_write_unlock(&_lock)
# define OFP_IPSEC_SAD_RWLOCK_RLOCK(_lock) odp_rwlock_read_lock(&_lock)
# define OFP_IPSEC_SAD_RWLOCK_RUNLOCK(_lock) odp_rwlock_read_unlock(&_lock)
#endif /* OFP_STATIC_IPSEC_SAD_CONFIG */

struct ofp_sad_list_entry {
	OFP_TAILQ_ENTRY(ofp_sad_list_entry) tqe;
	struct ofp_sad_entry entry;
};
OFP_TAILQ_HEAD(ofp_sad, ofp_sad_list_entry);

struct ofp_ipsec_sad_mem {
	struct ofp_sad_list_entry entries[OFP_IPSEC_SAD_SIZE];
	struct ofp_sad free_entries;
	odp_rwlock_t free_entries_rwlock;

	struct {
		struct ofp_sad sad;
		odp_rwlock_t sad_rwlock;
	} sads[OFP_SAD_CNT];
};

static __thread struct ofp_ipsec_sad_mem *shm;

static int ofp_ipsec_sad_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SAD, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_ipsec_sad_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_IPSEC_SAD) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_ipsec_sad_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SAD);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

int ofp_ipsec_sad_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_ipsec_sad_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	for (i = 0; i < OFP_SAD_CNT; i++) {
		OFP_TAILQ_INIT(&shm->sads[i].sad);
		OFP_IPSEC_SAD_RWLOCK_INIT(shm->sads[i].sad_rwlock);
	}

	OFP_TAILQ_INIT(&shm->free_entries);
	OFP_IPSEC_SAD_RWLOCK_INIT(shm->free_entries_rwlock);

	for (i = OFP_IPSEC_SAD_SIZE - 1; i >= 0; i--)
		OFP_TAILQ_INSERT_HEAD(&shm->free_entries,
			&shm->entries[i], tqe);
	return 0;
}

int ofp_ipsec_sad_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_ipsec_sad_free_shared_memory(), rc);

	return rc;
}

int ofp_ipsec_sad_add_local(enum ofp_sad_id sad_id,
	struct ofp_sad_entry *sad_entry)
{
	struct ofp_sad_list_entry *new_entry;
	struct ofp_sad *sad = &shm->sads[sad_id].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[sad_id].sad_rwlock;

	(void)sad_rwlock;
	OFP_IPSEC_SAD_RWLOCK_WLOCK(shm->free_entries_rwlock);
	new_entry = OFP_TAILQ_FIRST(&shm->free_entries);
	if (new_entry)
		OFP_TAILQ_REMOVE(&shm->free_entries, new_entry, tqe);
	OFP_IPSEC_SAD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);

	if (!new_entry) {
		OFP_ERR("Fail to alloc new SAD entry: no entry available");
		return -1;
	}

	memcpy(&new_entry->entry, sad_entry, sizeof(struct ofp_sad_entry));

	OFP_IPSEC_SAD_RWLOCK_WLOCK(*sad_rwlock);
	OFP_TAILQ_INSERT_TAIL(sad, new_entry, tqe);
	OFP_IPSEC_SAD_RWLOCK_WUNLOCK(*sad_rwlock);

	return 0;
}

int ofp_ipsec_sad_del_local(enum ofp_sad_id sad_id,
	struct ofp_ipsec_selectors *trivial_selectors,
	uint32_t spi,
	enum ofp_ipsec_protocol protocol)
{
	int ret = 0;
	struct ofp_sad_list_entry *iter;
	struct ofp_sad *sad = &shm->sads[sad_id].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[sad_id].sad_rwlock;

	(void)sad_rwlock;
	OFP_IPSEC_SAD_RWLOCK_WLOCK(*sad_rwlock);
	OFP_TAILQ_FOREACH(iter, sad, tqe)
		if (iter->entry.spi == spi &&
			iter->entry.protocol == protocol &&
			ofp_ipsec_selectors_equal(
				&iter->entry.trivial_selectors,
				trivial_selectors))
			break;
	if (iter)
		OFP_TAILQ_REMOVE(sad, iter, tqe);
	else {
		OFP_ERR("SAD entry not found.");
		ret = -1;
	}
	OFP_IPSEC_SAD_RWLOCK_WUNLOCK(*sad_rwlock);

	if (iter) {
		OFP_IPSEC_SAD_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);
		OFP_IPSEC_SAD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	}

	return ret;
}

int ofp_ipsec_sad_flush_local(enum ofp_sad_id sad_id)
{
	struct ofp_sad_list_entry *iter, *titer;
	struct ofp_sad *sad = &shm->sads[sad_id].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[sad_id].sad_rwlock;

	OFP_IPSEC_SAD_RWLOCK_WLOCK(*sad_rwlock);
	OFP_IPSEC_SAD_RWLOCK_WLOCK(shm->free_entries_rwlock);

	OFP_TAILQ_FOREACH_SAFE(iter, sad, tqe, titer)
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);

	OFP_TAILQ_INIT(sad);
	OFP_IPSEC_SAD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	OFP_IPSEC_SAD_RWLOCK_WUNLOCK(*sad_rwlock);
	return 0;
}

int ofp_ipsec_sad_dump_local(enum ofp_sad_id sad_id, int fd)
{
	struct ofp_sad_list_entry *iter;
	struct ofp_sad *sad = &shm->sads[sad_id].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[sad_id].sad_rwlock;

	(void)sad_rwlock;
	OFP_IPSEC_SAD_RWLOCK_RLOCK(*sad_rwlock);

	OFP_TAILQ_FOREACH(iter, sad, tqe) {
		sa_dump(fd, &iter->entry,
			sad_id == OFP_SAD_INBOUND? 1:0);
		ofp_sendf(fd, "\r\n");
	}
	OFP_IPSEC_SAD_RWLOCK_RUNLOCK(*sad_rwlock);

	return 0;
}

int ofp_ipsec_sad_add(enum ofp_ipsec_direction	direction,
	struct ofp_sad_entry *sad_entry)
{
	if (direction == OFP_IPSEC_DIRECTION_IN) {
		if (ofp_ipsec_sad_add_local(OFP_SAD_INBOUND, sad_entry)) {
			OFP_ERR("Failed to add inbound SA.");
			return -1;
		}

		if (ofp_ipsec_cache_in_add(sad_entry)) {
			OFP_ERR("Failed to add inbound cache on new SA.");
			ofp_ipsec_sad_del_local(OFP_SAD_INBOUND,
				&sad_entry->trivial_selectors,
				sad_entry->spi,
				sad_entry->incoming_protect_mode);
			return -1;
		}
	} else {
		struct ofp_spd_entry *sp;

		if (ofp_ipsec_sad_add_local(OFP_SAD_OUTBOUND, sad_entry)) {
			OFP_ERR("Failed to add outbound SA.");
			return -1;
		}

		sp = ofp_ipsec_spd_search_local(OFP_SPD_S,
			&sad_entry->trivial_selectors);
		if (!sp)
			return 0;	/* No policy (yet) => OK: no cache */

		if (ofp_ipsec_cache_out_add(sp, sad_entry)) {
			OFP_ERR("Failed to add outbound cache on new SA.");
			ofp_ipsec_sad_del_local(OFP_SAD_OUTBOUND,
				&sad_entry->trivial_selectors,
				sad_entry->spi,
				sad_entry->incoming_protect_mode);
			return -1;
		}
	}

	return 0;
}

int ofp_ipsec_sad_del(enum ofp_ipsec_direction	direction,
	struct ofp_ipsec_selectors *trivial_selectors,
	uint32_t spi,
	enum ofp_ipsec_protocol protocol)
{
	if (direction == OFP_IPSEC_DIRECTION_IN)
		return ofp_ipsec_sad_del_local(OFP_SAD_INBOUND,
			trivial_selectors, spi, protocol);
	else
		return ofp_ipsec_sad_del_local(OFP_SAD_OUTBOUND,
			trivial_selectors, spi, protocol);
}


int ofp_ipsec_sad_update_cache_out(void)
{
	int ret = 0;
	struct ofp_sad *sad = &shm->sads[OFP_SAD_OUTBOUND].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[OFP_SAD_OUTBOUND].sad_rwlock;
	struct ofp_sad_list_entry *iter;
	struct ofp_spd_entry *sp;

	(void)sad_rwlock;
	OFP_IPSEC_SAD_RWLOCK_RLOCK(*sad_rwlock);
	OFP_TAILQ_FOREACH(iter, sad, tqe) {
		sp = ofp_ipsec_spd_search_local(OFP_SPD_S,
			&iter->entry.trivial_selectors);
		if (!sp)
			continue; /* No policy (yet) => OK: no cache */

		if (ofp_ipsec_cache_out_search(&iter->entry.trivial_selectors))
			continue; /* Cache entry exists */

		if (ofp_ipsec_cache_out_add(sp, &iter->entry)) {
			OFP_ERR("Failed to add outbound cache.");
			ret = -1;
			break;
		}
	}
	OFP_IPSEC_SAD_RWLOCK_RUNLOCK(*sad_rwlock);

	return ret;
}

int ofp_ipsec_sad_update_cache_in(void)
{
	int ret = 0;
	struct ofp_sad *sad = &shm->sads[OFP_SAD_INBOUND].sad;
	odp_rwlock_t *sad_rwlock = &shm->sads[OFP_SAD_INBOUND].sad_rwlock;
	struct ofp_sad_list_entry *iter;
	struct ofp_sad_entry *entry;

	(void)sad_rwlock;
	OFP_IPSEC_SAD_RWLOCK_RLOCK(*sad_rwlock);
	OFP_TAILQ_FOREACH(iter, sad, tqe) {
		entry = &iter->entry;

		if (ofp_ipsec_cache_in_search(entry->spi, entry->protocol))
			continue; /* Cache entry exists */

		if (ofp_ipsec_cache_in_add(entry)) {
			OFP_ERR("Failed to add inbound cache on new SA.");
			continue;
		}
	}

	OFP_IPSEC_SAD_RWLOCK_RUNLOCK(*sad_rwlock);
	return ret;
}

void ofp_ipsec_sad_entry_init(struct ofp_sad_entry *sa)
{
	memset(sa, 0, sizeof (*sa));

	ofp_ipsec_selectors_init(&sa->trivial_selectors);

	sa->spi = 0;
	sa->protocol = OFP_IPSEC_PROTOCOL_ESP;
	sa->incoming_protect_mode = OFP_IPSEC_MODE_TUNNEL;
	sa->seq_number_overflow = 1;
	sa->auth_cipher = 1;
	sa->auth_alg = OFP_AUTH_ALG_NULL;
	sa->cipher_alg = OFP_CIPHER_ALG_NULL;
}

int ofp_ipsec_sad_flush(void)
{
	int ret = 0;

	ret += ofp_ipsec_sad_flush_local(OFP_SAD_INBOUND);
	ret += ofp_ipsec_sad_flush_local(OFP_SAD_OUTBOUND);

	return ret;
}

int ofp_ipsec_sad_dump(int fd)
{
	int ret = 0;

	ofp_sendf(fd, "Security Association Database:\r\n");
	ofp_sendf(fd, "SAD inbound:\r\n");
	ret += ofp_ipsec_sad_dump_local(OFP_SAD_INBOUND, fd);
	ofp_sendf(fd, "SAD outbound:\r\n");
	ret += ofp_ipsec_sad_dump_local(OFP_SAD_OUTBOUND, fd);

	return ret;
}
