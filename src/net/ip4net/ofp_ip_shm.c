/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_ip_shm.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_in_pcb.h"
#include "ofpi_in_mcast.h"

#define SHM_NAME_IP "OfpIpShMem"

__thread struct ofp_global_ip_state *ofp_ip_shm;

void ofp_ip_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_IP, sizeof(*ofp_ip_shm));
}

int ofp_ip_init_global(void)
{
	ofp_ip_shm = ofp_shared_memory_alloc(SHM_NAME_IP, sizeof(*ofp_ip_shm));
	if (ofp_ip_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc(\"" SHM_NAME_IP "\") failed");
		return -1;
	}
	odp_memset(ofp_ip_shm, 0, sizeof(*ofp_ip_shm));

	odp_atomic_init_u32(&ofp_ip_shm->ip_id, 0);

	V_l2_max_linkhdr = 64;
	V_ip_defttl = 255;

	V_ipport_reservedhigh = OFP_IPPORT_RESERVED - 1;	/* 1023 */
	V_ipport_reservedlow = 0;

	V_ipport_hifirstauto = 1200;	/* sysctl */
	V_ipport_hilastauto = 40000;	/* sysctl */
	V_ipport_lowfirstauto = 1023;
	V_ipport_lowlastauto = 40000;
	V_ipport_firstauto = 1023;
	V_ipport_lastauto = 40000;

	V_ipport_randomized = 1;
	V_ipport_randomcps = 10;
	V_ipport_randomtime = 45;
	V_ipport_stoprandom = 0;
	V_ipport_tcpallocs = 0;

	V_rsvp_on = 0;
	odp_memset(&V_ipstat, 0, sizeof(V_ipstat));
	V_ipforwarding = 0;

#ifdef IPSTEALTH
	V_ipstealth = 0;
#endif /*IPSTEALTH*/

	V_in_mcast_maxgrpsrc = OFP_IP_MAX_GROUP_SRC_FILTER;
	V_in_mcast_maxsocksrc = OFP_IP_MAX_SOCK_SRC_FILTER;
	V_in_mcast_in_mcast_loop = OFP_IP_DEFAULT_MULTICAST_LOOP;

	return 0;
}

int ofp_ip_init_local(void)
{
	ofp_ip_shm = ofp_shared_memory_lookup(SHM_NAME_IP);
	if (ofp_ip_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup(\"" SHM_NAME_IP "\") failed");
		return -1;
	}

	if (ofp_ipport_init_local()) {
		OFP_ERR("ofp_ipport_init_local failed");
		return -1;
	}

	if (ofp_in_mcast_init_local()) {
		OFP_ERR("ofp_in_mcast_init_local failed");
		return -1;
	}

	return 0;
}

int ofp_ip_term_local(void)
{
	ofp_ip_shm = NULL;
	return 0;
}

int ofp_ip_term_global(void)
{
	if (ofp_shared_memory_free(SHM_NAME_IP)) {
		OFP_ERR("ofp_shared_memory_free(\"" SHM_NAME_IP "\") failed");
		return -1;
	}
	return 0;
}
