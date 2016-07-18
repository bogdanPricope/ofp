/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_config.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_ipsec_session.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_pkt_processing.h"

#define SHM_NAME_IPSEC "OfpIPsecShMem"

struct ofp_ipsec_mem {
	struct ofp_ipsec_conf config;
};

static __thread struct ofp_ipsec_mem *shm;

static void cleanup_ipsec_compl_queue(odp_queue_t comp_queue);

static int ofp_ipsec_alloc_shared_memory(void)
{
	shm = ofp_shared_memory_alloc(SHM_NAME_IPSEC, sizeof(*shm));
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_ipsec_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_IPSEC) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm = NULL;
	return rc;
}

int ofp_ipsec_init_global(struct ofp_ipsec_config_param *ipsec_config)
{
	HANDLE_ERROR(ofp_ipsec_alloc_shared_memory());

	if (!ipsec_config)
		ofp_ipsec_conf_param_init(&shm->config.param);
	else
		memcpy(&shm->config.param, ipsec_config,
			sizeof (*ipsec_config));
	shm->config.async_queue_idx = 0;
	odp_rwlock_init(&shm->config.async_queue_rwlock);

	HANDLE_ERROR(ofp_ipsec_spd_init_global());

	HANDLE_ERROR(ofp_ipsec_sad_init_global());

	HANDLE_ERROR(ofp_ipsec_cache_out_init_global());

	HANDLE_ERROR(ofp_ipsec_cache_in_init_global());

	return 0;
}

int ofp_ipsec_term_global(void)
{
	int rc = 0;
	uint32_t i;

	CHECK_ERROR(ofp_ipsec_cache_in_term_global(), rc);

	CHECK_ERROR(ofp_ipsec_cache_out_term_global(), rc);

	CHECK_ERROR(ofp_ipsec_sad_term_global(), rc);

	CHECK_ERROR(ofp_ipsec_spd_term_global(), rc);

	for (i = 0; i < shm->config.param.async_queue_cnt; i++) {
		cleanup_ipsec_compl_queue(shm->config.param.async_queues[i]);
		odp_queue_destroy(shm->config.param.async_queues[i]);
	}

	CHECK_ERROR(ofp_ipsec_free_shared_memory(), rc);

	return rc;
}

int ofp_ipsec_lookup_shared_memory(void)
{
	shm = ofp_shared_memory_lookup(SHM_NAME_IPSEC);
	if (shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	HANDLE_ERROR(ofp_ipsec_sad_lookup_shared_memory());

	HANDLE_ERROR(ofp_ipsec_spd_lookup_shared_memory());

	HANDLE_ERROR(ofp_ipsec_cache_out_lookup_shared_memory());

	HANDLE_ERROR(ofp_ipsec_cache_in_lookup_shared_memory());

	return 0;
}

void ofp_ipsec_conf_param_init(struct ofp_ipsec_config_param *param)
{
	memset(param, 0, sizeof (*param));

	param->async_mode = 0;	/* synchronous mode */
	param->async_queue_cnt = 0;
	param->async_queue_alloc = OFP_ASYNC_QUEUE_ALLOC_ROUNDROBIN;
	param->output_pool = ODP_POOL_INVALID;
}

struct ofp_ipsec_conf *ofp_ipsec_config_get(void)
{
	if (!shm)
		return NULL;

	return &shm->config;
}

int ofp_ipsec_boundary_interface_set(struct ofp_ifnet *ifnet, odp_bool_t val)
{
	if (!ifnet)
		return -1;

	ifnet->ipsec_boundary = val;

	return 0;
}

static void cleanup_ipsec_compl_queue(odp_queue_t comp_queue)
{
	odp_event_t evt;
	odp_crypto_compl_t crypto_compl;
	odp_crypto_op_result_t crypto_result;

	while (1) {
		evt = odp_queue_deq(comp_queue);
		if (evt == ODP_EVENT_INVALID)
			break;
		if (odp_event_type(evt) == ODP_EVENT_CRYPTO_COMPL) {
			crypto_compl = odp_crypto_compl_from_event(evt);
			odp_crypto_compl_result(crypto_compl, &crypto_result);
			odp_crypto_compl_free(crypto_compl);
			odp_packet_free(crypto_result.pkt);
		}
	}
}
