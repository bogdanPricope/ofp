/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_IP_SHM_H_
#define _OFPI_IP_SHM_H_

#include "odp.h"
#include "ofpi_vnet.h"
#include "ofpi_ip_var.h"

struct ofp_global_ip_state {
	union {
		odp_atomic_u32_t ip_id;
		uint8_t padding[ODP_CACHE_LINE_SIZE];
	} ODP_ALIGNED_CACHE;

	VNET_DEFINE(int, max_linkhdr);	/* keep hear for now */

	VNET_DEFINE(int, ip_defttl);	/* default IP ttl */

	/*
	* Reserved ports accessible only to root. There are significant
	* security considerations that must be accounted for when changing
	* these, but the security benefits can be great. Please be careful.
	*/

	VNET_DEFINE(int, ipport_reservedhigh);
	VNET_DEFINE(int, ipport_reservedlow);

	VNET_DEFINE(int, ipport_hifirstauto);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_hilastauto);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_lowfirstauto);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_lowlastauto);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_firstauto);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_lastauto);	/* user controlled via sysctl */

	/* Variables dealing with random ephemeral port allocation. */
	VNET_DEFINE(int, ipport_randomized);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_randomcps);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_randomtime);	/* user controlled via sysctl */
	VNET_DEFINE(int, ipport_stoprandom);	/* toggled by ipport_tick */
	VNET_DEFINE(int, ipport_tcpallocs);

	VNET_DEFINE(int, rsvp_on);
	VNET_DEFINE(struct ofp_ipstat, ipstat);
	VNET_DEFINE(int, ipforwarding);		/* ip forwarding */
#ifdef IPSTEALTH
	VNET_DEFINE(int, ipstealth);		/* stealth forwarding */
#endif

	VNET_DEFINE(uint64_t, in_mcast_maxgrpsrc);
	VNET_DEFINE(uint64_t, in_mcast_maxsocksrc);
	VNET_DEFINE(int, in_mcast_loop);
};

extern __thread struct ofp_global_ip_state *ofp_ip_shm;

#define	V_l2_max_linkhdr VNET(ofp_ip_shm->max_linkhdr)

#define	V_ip_id	VNET(ofp_ip_shm->ip_id)
#define	V_ip_defttl	VNET(ofp_ip_shm->ip_defttl)

#define	V_ipport_reservedhigh VNET(ofp_ip_shm->ipport_reservedhigh)
#define	V_ipport_reservedlow VNET(ofp_ip_shm->ipport_reservedlow)

#define	V_ipport_hifirstauto VNET(ofp_ip_shm->ipport_hifirstauto)
#define	V_ipport_hilastauto VNET(ofp_ip_shm->ipport_hilastauto)
#define	V_ipport_lowfirstauto VNET(ofp_ip_shm->ipport_lowfirstauto)
#define	V_ipport_lowlastauto VNET(ofp_ip_shm->ipport_lowlastauto)
#define	V_ipport_firstauto VNET(ofp_ip_shm->ipport_firstauto)
#define	V_ipport_lastauto VNET(ofp_ip_shm->ipport_lastauto)

#define	V_ipport_randomized VNET(ofp_ip_shm->ipport_randomized)
#define	V_ipport_randomcps VNET(ofp_ip_shm->ipport_randomcps)
#define	V_ipport_randomtime VNET(ofp_ip_shm->ipport_randomtime)
#define	V_ipport_stoprandom VNET(ofp_ip_shm->ipport_stoprandom)
#define	V_ipport_tcpallocs VNET(ofp_ip_shm->ipport_tcpallocs)

#define	V_rsvp_on VNET(ofp_ip_shm->rsvp_on)

#define	V_ipstat VNET(ofp_ip_shm->ipstat)
#define	V_ipforwarding VNET(ofp_ip_shm->ipforwarding)

#ifdef IPSTEALTH
#define	V_ipstealth VNET(ofp_ip_shm->ipstealth)
#endif

/* mcast */
#define	V_in_mcast_maxgrpsrc VNET(ofp_ip_shm->in_mcast_maxgrpsrc)
#define	V_in_mcast_maxsocksrc VNET(ofp_ip_shm->in_mcast_maxsocksrc)
#define	V_in_mcast_in_mcast_loop VNET(ofp_ip_shm->in_mcast_loop)

void ofp_ip_init_prepare(void);
int ofp_ip_init_global(void);
int ofp_ip_term_global(void);
int ofp_ip_init_local(void);
int ofp_ip_term_local(void);

#endif /*_OFPI_IP_SHM_H_*/
