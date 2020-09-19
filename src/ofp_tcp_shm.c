/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_init.h"
#include "ofpi_tcp_shm.h"

#define SHM_NAME_TCP_VAR "OfpTcpVarShMem"

/*
 * Data per core
 */
__thread struct ofp_tcp_var_mem *shm_tcp;
__thread struct inpcbhead *shm_tcp_hashtbl;
__thread struct inpcbporthead *shm_tcp_porthashtbl;
__thread struct syncache_head *shm_tcp_syncachehashtbl;

static uint64_t get_shm_tcp_hashtbl_size(void)
{
#ifdef OFP_RSS
	return OFP_MAX_NUM_CPU *
		global_param->tcp.pcb_hashtbl_size *
		sizeof(struct inpcbhead);
#else
	return global_param->tcp.pcb_hashtbl_size *
		sizeof(struct inpcbhead);
#endif /*OFP_RSS*/
}

static uint64_t get_shm_tcp_porthashtbl_size(void)
{
#ifdef OFP_RSS
	return OFP_MAX_NUM_CPU *
		global_param->tcp.pcbport_hashtbl_size *
		sizeof(struct inpcbporthead);
#else
	return global_param->tcp.pcbport_hashtbl_size *
		sizeof(struct inpcbporthead);
#endif /*OFP_RSS*/
}

static uint64_t get_shm_tcp_syncachehashtbl_size(void)
{
	return global_param->tcp.syncache_hashtbl_size *
		sizeof(struct syncache_head);
}

static uint64_t ofp_tcp_var_get_shm_size(void)
{
	return sizeof(*shm_tcp) +
		get_shm_tcp_hashtbl_size() +
		get_shm_tcp_porthashtbl_size() +
		get_shm_tcp_syncachehashtbl_size();
}

static int ofp_tcp_var_alloc_shared_memory(void)
{
	shm_tcp = ofp_shared_memory_alloc(SHM_NAME_TCP_VAR,
					  ofp_tcp_var_get_shm_size());
	if (shm_tcp == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_tcp_var_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_TCP_VAR) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_tcp = NULL;

	return rc;
}

int ofp_tcp_var_lookup_shared_memory(void)
{
	shm_tcp = ofp_shared_memory_lookup(SHM_NAME_TCP_VAR);
	if (shm_tcp == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	shm_tcp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_tcp + shm_tcp->hashtbl_off);
	shm_tcp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_tcp + shm_tcp->porthashtbl_off);
	shm_tcp_syncachehashtbl = (struct syncache_head *)
		((uint8_t *)shm_tcp + shm_tcp->syncachehashtbl_off);

	return 0;
}

void ofp_tcp_var_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_TCP_VAR,
				   ofp_tcp_var_get_shm_size());
}

int ofp_tcp_var_init_global(void)
{
	HANDLE_ERROR(ofp_tcp_var_alloc_shared_memory());
	memset(shm_tcp, 0, (size_t)ofp_tcp_var_get_shm_size());

	shm_tcp->hashtbl_off = sizeof(*shm_tcp);
	shm_tcp->hashtbl_size = (uint32_t)global_param->tcp.pcb_hashtbl_size;

	shm_tcp->porthashtbl_off =
		shm_tcp->hashtbl_off + get_shm_tcp_hashtbl_size();
	shm_tcp->porthashtbl_size =
		(uint32_t)global_param->tcp.pcbport_hashtbl_size;

	shm_tcp->syncachehashtbl_off =
		shm_tcp->porthashtbl_off + get_shm_tcp_porthashtbl_size();
	shm_tcp->syncachehashtbl_size =
		(uint32_t)global_param->tcp.syncache_hashtbl_size;

	shm_tcp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_tcp + shm_tcp->hashtbl_off);
	shm_tcp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_tcp + shm_tcp->porthashtbl_off);
	shm_tcp_syncachehashtbl = (struct syncache_head *)
		((uint8_t *)shm_tcp + shm_tcp->syncachehashtbl_off);

	return 0;
}

int ofp_tcp_var_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_tcp_var_free_shared_memory(), rc);

	return rc;
}
