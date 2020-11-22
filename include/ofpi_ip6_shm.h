/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IP6_SHM_H__
#define __OFPI_IP6_SHM_H__

#include "odp.h"
#include "ofpi_vnet.h"
#include "ofpi_ip6.h"

struct ofp_global_ip6_state {
	VNET_DEFINE(int, ip6_use_defzone); /* Whether to use the default scope
					    * zone when unspecified */
	VNET_DEFINE(int, ip6_v6only);
	VNET_DEFINE(int, ip6_auto_flowlabel);
	VNET_DEFINE(int, ip6_defhlim);

	VNET_DEFINE(int, icmp6_rediraccept); /* accept/process redirects */
	VNET_DEFINE(int, icmp6_redirtimeout);  /* cache time for
						* redirect routes */
};

extern __thread struct ofp_global_ip6_state *ofp_ip6_shm;

#define	V_ip6_use_defzone   VNET(ofp_ip6_shm->ip6_use_defzone)
#define	V_ip6_v6only		VNET(ofp_ip6_shm->ip6_v6only)
#define	V_ip6_auto_flowlabel VNET(ofp_ip6_shm->ip6_auto_flowlabel)
#define	V_ip6_defhlim		VNET(ofp_ip6_shm->ip6_defhlim)

#define	V_icmp6_rediraccept	VNET(ofp_ip6_shm->icmp6_rediraccept)
#define	V_icmp6_redirtimeout	VNET(ofp_ip6_shm->icmp6_redirtimeout)

void ofp_ip6_init_prepare(void);
int ofp_ip6_init_global(void);
int ofp_ip6_term_global(void);
int ofp_ip6_init_local(void);
int ofp_ip6_term_local(void);
#endif /*__OFPI_IP6_SHM_H__*/
