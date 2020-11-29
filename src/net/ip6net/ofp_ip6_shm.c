/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_ip6_shm.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"

#define SHM_NAME_IP6 "OfpIp6ShMem"

__thread struct ofp_global_ip6_state *ofp_ip6_shm;

void ofp_ip6_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_IP6, sizeof(*ofp_ip6_shm));
}

int ofp_ip6_init_global(void)
{
	ofp_ip6_shm = ofp_shared_memory_alloc(SHM_NAME_IP6,
					      sizeof(*ofp_ip6_shm));
	if (ofp_ip6_shm == NULL) {
		OFP_ERR("ofp_shared_memory_alloc() failed");
		return -1;
	}
	odp_memset(ofp_ip6_shm, 0, sizeof(*ofp_ip6_shm));

	V_ip6_use_defzone = 1;
	V_ip6_v6only = 1;
	V_ip6_auto_flowlabel = 1;
	V_ip6_defhlim = OFP_IPV6_DEFHLIM;

	V_icmp6_rediraccept = 1; /* accept and process redirects */
	V_icmp6_redirtimeout = 10 * 60;	/* 10 minutes */

	return 0;
}

int ofp_ip6_term_global(void)
{
	if (ofp_shared_memory_free(SHM_NAME_IP6)) {
		OFP_ERR("ofp_shared_memory_free() failed");
		return -1;
	}
	ofp_ip6_shm = NULL;
	return 0;
}

int ofp_ip6_init_local(void)
{
	ofp_ip6_shm = ofp_shared_memory_lookup(SHM_NAME_IP6);
	if (ofp_ip6_shm == NULL) {
		OFP_ERR("ofp_shared_memory_lookup() failed");
		return -1;
	}

	return 0;
}

int ofp_ip6_term_local(void)
{
	ofp_ip6_shm = NULL;
	return 0;
}
