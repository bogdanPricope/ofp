/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_GLOBAL_PARAM_SHM_H__
#define __OFPI_GLOBAL_PARAM_SHM_H__

#include "odp.h"
#include <odp/helper/odph_api.h>
#include "api/ofp_init.h"
#include "ofpi_vnet.h"

struct ofp_global_config_mem {
	odp_bool_t is_running ODP_ALIGNED_CACHE;

	VNET_DEFINE(odp_instance_t, odp_instance);
	VNET_DEFINE(odp_bool_t, odp_instance_owner);

#ifdef SP
	VNET_DEFINE(odph_odpthread_t, nl_thread);
	VNET_DEFINE(odp_bool_t, nl_thread_is_running);
#endif /* SP */

	VNET_DEFINE(odph_odpthread_t, cli_thread);
	VNET_DEFINE(odp_bool_t, cli_thread_is_running);

	VNET_DEFINE(odp_cpumask_t, linux_cpumask);

	VNET_DEFINE(odp_pool_t, packet_pool);

	VNET_DEFINE(enum ofp_log_level_s, loglevel);

	ofp_global_param_t global_param;
};

extern __thread struct ofp_global_config_mem *shm_global;
extern __thread ofp_global_param_t *global_param;

#define	V_global_is_running	VNET(shm_global->is_running)

#define	V_global_odp_instance	VNET(shm_global->odp_instance)
#define	V_global_odp_instance_owner	VNET(shm_global->odp_instance_owner)

#ifdef SP
#define	V_global_nl_thread	VNET(shm_global->nl_thread)
#define	V_global_nl_thread_is_running	VNET(shm_global->nl_thread_is_running)
#endif /* SP */

#define	V_global_cli_thread	VNET(shm_global->cli_thread)
#define	V_global_cli_thread_is_running	VNET(shm_global->cli_thread_is_running)

#define	V_global_linux_cpumask VNET(shm_global->linux_cpumask)
#define	V_global_packet_pool VNET(shm_global->packet_pool)

#define	V_global_loglevel VNET(shm_global->loglevel)

#define	V_global_param VNET(shm_global->global_param)

int ofp_global_param_init_global(ofp_global_param_t *params,
				 odp_instance_t instance,
				 odp_bool_t instance_owner);
int ofp_global_param_term_global(void);
int ofp_global_param_init_local(void);

struct ofp_global_config_mem *ofp_get_global_config(void);

odp_pool_t ofp_get_packet_pool(void);

#endif /*__OFPI_GLOBAL_PARAM_SHM_H__*/
