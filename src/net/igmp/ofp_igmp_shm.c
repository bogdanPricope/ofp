/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_igmp_shm.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"

#define SHM_NAME_IGMP "OfpIGMPShMem"

__thread struct ofp_igmp_var_mem *ofp_igmp_shm;

void ofp_igmp_var_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_IGMP, sizeof(*ofp_igmp_shm));
}

int ofp_igmp_var_init_global(void)
{
	ofp_igmp_shm = ofp_shared_memory_alloc(SHM_NAME_IGMP,
					       sizeof(*ofp_igmp_shm));
	if (ofp_igmp_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc"
			"(\"" SHM_NAME_IGMP "\") failed");
		return -1;
	}

	odp_memset(ofp_igmp_shm, 0, sizeof(*ofp_igmp_shm));

	V_igmpstat.igps_version = IGPS_VERSION_3;
	V_igmpstat.igps_len = sizeof(struct igmpstat);

	V_igmp_recvifkludge = 1;
	V_igmp_sendra = 1;
	V_igmp_sendlocal = 1;
	V_igmp_v1enable = 1;
	V_igmp_v2enable = 1;
	V_igmp_legacysupp = 0;
	V_igmp_default_version = IGMP_VERSION_3;

	V_interface_timers_running = 0;
	V_state_change_timers_running = 0;
	V_current_state_timers_running = 0;

	V_igmp_gsrdelay = (struct ofp_timeval) {10, 0};
	V_igmp_fasttimo_timer = ODP_TIMER_INVALID;

	V_igmp_raopt = ODP_PACKET_INVALID;
	return 0;
}

int ofp_igmp_var_term_global(void)
{
	ofp_igmp_shm = ofp_shared_memory_lookup(SHM_NAME_IGMP);
	if (!ofp_igmp_shm)
		return 0;

	ofp_igmp_uninit(NULL);

	if (ofp_shared_memory_free(SHM_NAME_IGMP)) {
		OFP_ERR("ofp_shared_memory_free"
			"(\"" SHM_NAME_IGMP "\") failed");
		return -1;
	}

	ofp_igmp_shm = NULL;
	return 0;
}

int ofp_igmp_var_init_local(void)
{
	ofp_igmp_shm = ofp_shared_memory_lookup(SHM_NAME_IGMP);
	if (ofp_igmp_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup"
			"(\"" SHM_NAME_IGMP "\") failed");
		return -1;
	}

	if (ofp_igmp_sysctl_init_local()) {
		OFP_ERR("ofp_igmp_sysctl_init_local failed");
		return -1;
	}

	return 0;
}

