/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_sp_shm.h"
#include "ofpi_shared_mem.h"
#include "ofpi_util.h"

#define SHM_SP_NAME "OfpSPShMem"

__thread struct ofp_sp_shm_mem *shm_sp;

static int ofp_sp_alloc_shared_memory(void)
{
	shm_sp = ofp_shared_memory_alloc(SHM_SP_NAME, sizeof(*shm_sp));
	if (shm_sp == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_sp_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_SP_NAME) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_sp = NULL;

	return rc;
}

static int ofp_sp_lookup_shared_memory(void)
{
	shm_sp = ofp_shared_memory_lookup(SHM_SP_NAME);
	if (shm_sp == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

void ofp_sp_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_SP_NAME, sizeof(*shm_sp));
}

int ofp_sp_init_global(void)
{
	int i;

	HANDLE_ERROR(ofp_sp_alloc_shared_memory());
	memset(shm_sp, 0, sizeof(*shm_sp));

	for (i = 0; i < NUM_NS_SOCKETS; i++) {
		V_sp_nl_sockets[i].vrf = -1;
		V_sp_nl_sockets[i].fd = -1;
	}

	V_sp_nl_sock_cnt = 0;

	odp_rwlock_init(&V_sp_nl_rwlock);

	return 0;
}

int ofp_sp_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_sp_free_shared_memory(), rc);

	return rc;
}

int ofp_sp_init_local(void)
{
	if (ofp_sp_lookup_shared_memory())
		return -1;

	return 0;
}

