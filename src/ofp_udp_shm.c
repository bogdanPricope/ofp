/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_udp_shm.h"
#include "ofpi_udp_var.h"

#define SHM_NAME_UDP_VAR "OfpUdpVarShMem"

/*
 * Data per core
 */
__thread struct ofp_udp_var_mem *shm_udp;
__thread struct inpcbhead *shm_udp_hashtbl;
__thread struct inpcbporthead *shm_udp_porthashtbl;

static uint64_t get_shm_udp_hashtbl_size(void)
{
	return global_param->udp.pcb_hashtbl_size *
		sizeof(struct inpcbhead);
}

static uint64_t get_shm_udp_porthashtbl_size(void)
{
	return global_param->udp.pcbport_hashtbl_size *
		sizeof(struct inpcbporthead);
}

static uint64_t ofp_udp_var_get_shm_size(void)
{
	return sizeof(*shm_udp) +
		get_shm_udp_hashtbl_size() +
		get_shm_udp_porthashtbl_size();
}

static int ofp_udp_var_alloc_shared_memory(void)
{
	shm_udp = ofp_shared_memory_alloc(SHM_NAME_UDP_VAR,
					  ofp_udp_var_get_shm_size());
	if (shm_udp == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_udp_var_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_UDP_VAR) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_udp = NULL;
	shm_udp_hashtbl = NULL;
	shm_udp_porthashtbl = NULL;

	return rc;
}

static int ofp_udp_var_lookup_shared_memory(void)
{
	shm_udp = ofp_shared_memory_lookup(SHM_NAME_UDP_VAR);
	if (shm_udp == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	shm_udp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_udp + shm_udp->hashtbl_off);
	shm_udp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_udp + shm_udp->porthashtbl_off);

	return 0;
}

void ofp_udp_var_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_UDP_VAR,
				   ofp_udp_var_get_shm_size());
}

int ofp_udp_var_init_global(void)
{
	HANDLE_ERROR(ofp_udp_var_alloc_shared_memory());
	memset(shm_udp, 0, (size_t)ofp_udp_var_get_shm_size());

	shm_udp->hashtbl_off = sizeof(*shm_udp);
	shm_udp->hashtbl_size = (uint32_t)global_param->udp.pcb_hashtbl_size;

	shm_udp->porthashtbl_off = shm_udp->hashtbl_off +
		get_shm_udp_hashtbl_size();
	shm_udp->porthashtbl_size =
		(uint32_t)global_param->udp.pcbport_hashtbl_size;

	shm_udp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_udp + shm_udp->hashtbl_off);
	shm_udp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_udp + shm_udp->porthashtbl_off);

	V_udp_cksum_enable = 1;
	V_udp_log_in_vain = 0;
	V_udp_blackhole = 0;

	V_udp_sendspace = 9216;		/* really max datagram size */
	V_udp_recvspace = 40 * (1024 + sizeof(struct ofp_sockaddr_in6));

	return 0;
}

int ofp_udp_var_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_udp_var_free_shared_memory(), rc);

	return rc;
}

int ofp_udp_var_init_local(void)
{
	if (ofp_udp_var_lookup_shared_memory())
		return -1;

	if (ofp_udp_init_local_sysctl())
		return -1;

	return 0;
}

