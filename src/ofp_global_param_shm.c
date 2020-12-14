/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_global_param_shm.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

#define SHM_NAME_GLOBAL_CONFIG "OfpGlobalConfigShMem"

__thread struct ofp_global_config_mem *shm_global;
__thread ofp_global_param_t *global_param;

static int ofp_global_config_alloc_shared_memory(void)
{
	shm_global = ofp_shared_memory_alloc(SHM_NAME_GLOBAL_CONFIG,
					     sizeof(*shm_global));
	if (shm_global == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	global_param = &shm_global->global_param;
	return 0;
}

static int ofp_global_config_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_GLOBAL_CONFIG) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_global = NULL;
	global_param = NULL;
	return rc;
}

static int ofp_global_config_lookup_shared_memory(void)
{
	shm_global = ofp_shared_memory_lookup(SHM_NAME_GLOBAL_CONFIG);
	if (shm_global == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	global_param = &shm_global->global_param;

	return 0;
}

int ofp_global_param_init_global(ofp_global_param_t *params,
				 odp_instance_t instance,
				 odp_bool_t instance_owner)
{
	HANDLE_ERROR(ofp_global_config_alloc_shared_memory());

	memset(shm_global, 0, sizeof(*shm_global));
	shm_global->is_running = 1;

	V_global_odp_instance = instance;
	V_global_odp_instance_owner = instance_owner;

#ifdef SP
	V_global_nl_thread_is_running = 0;
#endif /* SP */
	shm_global->cli_thread_is_running = 0;

	/* cpu mask for slow path threads */
	odp_cpumask_zero(&V_global_linux_cpumask);
	odp_cpumask_set(&V_global_linux_cpumask, params->linux_core_id);

	V_global_packet_pool = ODP_POOL_INVALID;

	V_global_loglevel = params->loglevel;

	*global_param = *params;

	return 0;
}

int ofp_global_param_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_global_config_free_shared_memory(), rc);

	return rc;
}

int ofp_global_param_init_local(void)
{
	HANDLE_ERROR(ofp_global_config_lookup_shared_memory());

	return 0;
}

struct ofp_global_config_mem *ofp_get_global_config(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;

	return shm_global;
}

void ofp_stop_processing(void)
{
	if (shm_global)
		shm_global->is_running = 0;
}

odp_bool_t *ofp_get_processing_state(void)
{
	if (ofp_global_config_lookup_shared_memory() == -1)
		return NULL;

	return &shm_global->is_running;
}

int ofp_get_parameters(ofp_param_t *params)
{
	if (!params)
		return -1;

	if (ofp_global_config_lookup_shared_memory() == -1)
		return -1;

	memset(params, 0, sizeof(*params));

	params->global_param = *global_param;

	return 0;
}

odp_pool_t ofp_get_packet_pool(void)
{
	if (!shm_global)
		return ODP_POOL_INVALID;

	return V_global_packet_pool;
}

odp_instance_t ofp_get_odp_instance(void)
{
	if (!shm_global)
		return OFP_ODP_INSTANCE_INVALID;

	return V_global_odp_instance;
}

