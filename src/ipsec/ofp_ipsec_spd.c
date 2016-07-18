/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_config.h"
#include "api/ofp_queue.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_cli.h"


#define SHM_NAME_IPSEC_SPD "OfpIPsecSPDShMem"

#ifdef OFP_STATIC_IPSEC_SPD_CONFIG
# define OFP_IPSEC_SPD_RWLOCK_INIT(_lock)
# define OFP_IPSEC_SPD_RWLOCK_WLOCK(_lock)
# define OFP_IPSEC_SPD_RWLOCK_WUNLOCK(_lock)
# define OFP_IPSEC_SPD_RWLOCK_RLOCK(_lock)
# define OFP_IPSEC_SPD_RWLOCK_RUNLOCK(_lock)
#else
# define OFP_IPSEC_SPD_RWLOCK_INIT(_lock) odp_rwlock_init(&_lock)
# define OFP_IPSEC_SPD_RWLOCK_WLOCK(_lock) odp_rwlock_write_lock(&_lock)
# define OFP_IPSEC_SPD_RWLOCK_WUNLOCK(_lock) odp_rwlock_write_unlock(&_lock)
# define OFP_IPSEC_SPD_RWLOCK_RLOCK(_lock) odp_rwlock_read_lock(&_lock)
# define OFP_IPSEC_SPD_RWLOCK_RUNLOCK(_lock) odp_rwlock_read_unlock(&_lock)
#endif /* OFP_STATIC_IPSEC_SPD_CONFIG */


struct ofp_spd_list_entry {
	OFP_TAILQ_ENTRY(ofp_spd_list_entry) tqe;
	struct ofp_spd_entry entry;
};
OFP_TAILQ_HEAD(ofp_spd, ofp_spd_list_entry);

struct ofp_ipsec_spd_mem {
	struct ofp_spd_list_entry entries[OFP_IPSEC_SPD_SIZE];
	struct ofp_spd free_entries;
	odp_rwlock_t free_entries_rwlock;

	struct {
		struct ofp_spd spd;
		odp_rwlock_t spd_rwlock;
	} spds[OFP_SPD_CNT];
};

static __thread struct ofp_ipsec_spd_mem *shm;


static int ofp_ipsec_spd_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC_SPD, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_ipsec_spd_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_IPSEC_SPD) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_ipsec_spd_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_ipsec_spd_alloc_shared_memory());

	memset(shm, 0, sizeof(*shm));

	for (i = 0; i < OFP_SPD_CNT; i++) {
		OFP_TAILQ_INIT(&shm->spds[i].spd);
		OFP_IPSEC_SPD_RWLOCK_INIT(shm->spds[i].spd_rwlock);
	}

	OFP_TAILQ_INIT(&shm->free_entries);
	OFP_IPSEC_SPD_RWLOCK_INIT(shm->free_entries_rwlock);
	for (i = OFP_IPSEC_SPD_SIZE - 1; i >= 0; i--)
		OFP_TAILQ_INSERT_HEAD(&shm->free_entries,
			&shm->entries[i], tqe);

	return 0;
}

int ofp_ipsec_spd_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_ipsec_spd_free_shared_memory(), rc);

	return rc;
}

int ofp_ipsec_spd_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC_SPD);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}


int ofp_ipsec_spd_add_local(enum ofp_spd_id spd_id,
	struct ofp_spd_entry *spd_entry)
{
	struct ofp_spd_list_entry *new_entry;
	struct ofp_spd *spd = &shm->spds[spd_id].spd;
	odp_rwlock_t *spd_rwlock = &shm->spds[spd_id].spd_rwlock;

	(void)spd_rwlock;
	OFP_IPSEC_SPD_RWLOCK_WLOCK(shm->free_entries_rwlock);
	new_entry = OFP_TAILQ_FIRST(&shm->free_entries);
	if (new_entry)
		OFP_TAILQ_REMOVE(&shm->free_entries, new_entry, tqe);
	OFP_IPSEC_SPD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);

	if (!new_entry) {
		OFP_ERR("Fail to alloc new SPD entry: no entry available");
		return -1;
	}

	memcpy(&new_entry->entry, spd_entry, sizeof(struct ofp_spd_entry));

	OFP_IPSEC_SPD_RWLOCK_WLOCK(*spd_rwlock);
	OFP_TAILQ_INSERT_TAIL(spd, new_entry, tqe);
	OFP_IPSEC_SPD_RWLOCK_WUNLOCK(*spd_rwlock);

	return 0;
}

int ofp_ipsec_spd_del_local(enum ofp_spd_id spd_id,
	struct ofp_ipsec_selectors *spd_selectors)
{
	int ret = 0;
	struct ofp_spd_list_entry *iter;
	struct ofp_spd *spd = &shm->spds[spd_id].spd;
	odp_rwlock_t *spd_rwlock = &shm->spds[spd_id].spd_rwlock;

	(void)spd_rwlock;
	OFP_IPSEC_SPD_RWLOCK_WLOCK(*spd_rwlock);
	OFP_TAILQ_FOREACH(iter, spd, tqe)
		if (ofp_ipsec_selectors_equal(&iter->entry.selectors,
			spd_selectors))
			break;
	if (iter)
		OFP_TAILQ_REMOVE(spd, iter, tqe);
	else {
		OFP_ERR("SPD entry not found.");
		ret = -1;
	}
	OFP_IPSEC_SPD_RWLOCK_WUNLOCK(*spd_rwlock);

	if (iter) {
		OFP_IPSEC_SPD_RWLOCK_WLOCK(shm->free_entries_rwlock);
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);
		OFP_IPSEC_SPD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	}
	return ret;
}

int ofp_ipsec_spd_flush_local(enum ofp_spd_id spd_id)
{
	struct ofp_spd_list_entry *iter, *titer;
	struct ofp_spd *spd = &shm->spds[spd_id].spd;
	odp_rwlock_t *spd_rwlock = &shm->spds[spd_id].spd_rwlock;

	OFP_IPSEC_SPD_RWLOCK_WLOCK(*spd_rwlock);
	OFP_IPSEC_SPD_RWLOCK_WLOCK(shm->free_entries_rwlock);

	OFP_TAILQ_FOREACH_SAFE(iter, spd, tqe, titer)
		OFP_TAILQ_INSERT_TAIL(&shm->free_entries, iter, tqe);

	OFP_TAILQ_INIT(spd);
	OFP_IPSEC_SPD_RWLOCK_WUNLOCK(shm->free_entries_rwlock);
	OFP_IPSEC_SPD_RWLOCK_WUNLOCK(*spd_rwlock);
	return 0;
}

struct ofp_spd_entry *ofp_ipsec_spd_search_local(enum ofp_spd_id spd_id,
	struct ofp_ipsec_selectors *pkt_selectors)
{
	struct ofp_spd_entry *ret = NULL;
	struct ofp_spd_list_entry *iter;
	struct ofp_spd *spd = &shm->spds[spd_id].spd;
	odp_rwlock_t *spd_rwlock = &shm->spds[spd_id].spd_rwlock;

	if (!pkt_selectors)
		return NULL;

	(void)spd_rwlock;
	OFP_IPSEC_SPD_RWLOCK_RLOCK(*spd_rwlock);
	OFP_TAILQ_FOREACH(iter, spd, tqe)
		if (ofp_ipsec_selectors_match_sp_pkt(&iter->entry.selectors,
			pkt_selectors))
			break;
	if (iter)
		ret = &iter->entry;
	OFP_IPSEC_SPD_RWLOCK_RUNLOCK(*spd_rwlock);

	return ret;
}

int ofp_ipsec_spd_add(struct ofp_spd_entry *spd_entry)
{
	if (!spd_entry)
		return -1;

	if (spd_entry->direction == OFP_IPSEC_DIRECTION_IN) {
		if (spd_entry->action == OFP_SPD_ACTION_PROTECT) {
			OFP_ERR("Invalid PROTECT action for incoming traffic.");
			return -1;
		}
		return ofp_ipsec_spd_add_local(OFP_SPD_I, spd_entry);
	} else {
		if (spd_entry->action == OFP_SPD_ACTION_PROTECT) {
			int ret = 0;

			if (ofp_ipsec_spd_add_local(OFP_SPD_S, spd_entry))
				return -1;

			if (ofp_ipsec_sad_update_cache_out())
				OFP_ERR("Failed to update outbound cache on new SP.");
			return ret;
		} else
			return ofp_ipsec_spd_add_local(OFP_SPD_O, spd_entry);


	}
	return 0;
}
int ofp_ipsec_spd_del(struct ofp_ipsec_selectors *matching_selectors,
	enum ofp_ipsec_direction direction)
{
	if (!matching_selectors)
		return -1;

	if (direction == OFP_IPSEC_DIRECTION_IN) {
		return ofp_ipsec_spd_del_local(OFP_SPD_I, matching_selectors);
	} else {
		if (!ofp_ipsec_spd_del_local(OFP_SPD_S, matching_selectors))
			return 0;
		if (!ofp_ipsec_spd_del_local(OFP_SPD_O, matching_selectors))
			return 0;
		return -1;
	}
	return 0;
}

int ofp_ipsec_spd_flush(void)
{
	ofp_ipsec_spd_flush_local(OFP_SPD_I);
	ofp_ipsec_spd_flush_local(OFP_SPD_O);
	ofp_ipsec_spd_flush_local(OFP_SPD_S);
	return 0;
}

void ofp_ipsec_spd_entry_init(struct ofp_spd_entry *sp)
{
	memset(sp, 0, sizeof(struct ofp_spd_entry));

	ofp_ipsec_selectors_init(&sp->selectors);

	sp->action = OFP_SPD_ACTION_BYPASS;
	sp->direction = OFP_IPSEC_DIRECTION_IN;
}

int ofp_ipsec_spd_dump_local(enum ofp_spd_id spd_id, int fd)
{
	struct ofp_spd_list_entry *iter;
	struct ofp_spd *spd = &shm->spds[spd_id].spd;
	odp_rwlock_t *spd_rwlock = &shm->spds[spd_id].spd_rwlock;

	(void)spd_rwlock;
	OFP_IPSEC_SPD_RWLOCK_RLOCK(*spd_rwlock);
	OFP_TAILQ_FOREACH(iter, spd, tqe) {
		sp_dump(fd, &iter->entry);
		ofp_sendf(fd, "\r\n");
	}
	OFP_IPSEC_SPD_RWLOCK_RUNLOCK(*spd_rwlock);
	return 0;
}

int ofp_ipsec_spd_dump(int fd)
{
	int ret = 0;

	ofp_sendf(fd, "Security Policy Database:\r\n");
	ofp_sendf(fd, "SPD_I:\r\n");
	ret += ofp_ipsec_spd_dump_local(OFP_SPD_I, fd);
	ofp_sendf(fd, "SPD_O:\r\n");
	ret += ofp_ipsec_spd_dump_local(OFP_SPD_O, fd);
	ofp_sendf(fd, "SPD_S:\r\n");
	ret += ofp_ipsec_spd_dump_local(OFP_SPD_S, fd);

	return ret;
}
