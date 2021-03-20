/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_IGMP_SHM_H_
#define _OFPI_IGMP_SHM_H_

#include "odp.h"
#include "ofpi_vnet.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_igmp_var.h"

struct ofp_igmp_var_mem {
	VNET_DEFINE(struct igmpstat, igmpstat);
	VNET_DEFINE(int, igmp_recvifkludge);
	VNET_DEFINE(int, igmp_sendra);
	VNET_DEFINE(int, igmp_sendlocal);
	VNET_DEFINE(int, igmp_v1enable);
	VNET_DEFINE(int, igmp_v2enable);
	VNET_DEFINE(int, igmp_legacysupp);
	VNET_DEFINE(int, igmp_default_version);

	VNET_DEFINE(int, interface_timers_running); /* IGMPv3 general
							 * query response */
	VNET_DEFINE(int, state_change_timers_running);	/* IGMPv3 state-change
							 * retransmit */
	VNET_DEFINE(int, current_state_timers_running);	/* IGMPv1/v2 host
							 * report; IGMPv3 g/sg
							 * query response */

	VNET_DEFINE(struct ofp_timeval, igmp_gsrdelay);
	VNET_DEFINE(odp_timer_t, igmp_fasttimo_timer);
	VNET_DEFINE(OFP_LIST_HEAD(, ofp_igmp_ifinfo), igi_head);

	/*VNET_DEFINE(int, if_index);*/

	VNET_DEFINE(odp_rwlock_t, igmp_mtx);
	VNET_DEFINE(odp_packet_t, igmp_raopt);	/* Router Alert option */
};

extern __thread struct ofp_igmp_var_mem *ofp_igmp_shm;

#define	V_igmpstat				VNET(ofp_igmp_shm->igmpstat)
#define	V_igmp_recvifkludge		VNET(ofp_igmp_shm->igmp_recvifkludge)
#define	V_igmp_sendra			VNET(ofp_igmp_shm->igmp_sendra)
#define	V_igmp_sendlocal		VNET(ofp_igmp_shm->igmp_sendlocal)
#define	V_igmp_v1enable			VNET(ofp_igmp_shm->igmp_v1enable)
#define	V_igmp_v2enable			VNET(ofp_igmp_shm->igmp_v2enable)
#define	V_igmp_legacysupp		VNET(ofp_igmp_shm->igmp_legacysupp)
#define	V_igmp_default_version	VNET(ofp_igmp_shm->igmp_default_version)

#define	V_interface_timers_running	\
	VNET(ofp_igmp_shm->interface_timers_running)
#define	V_state_change_timers_running	\
	VNET(ofp_igmp_shm->state_change_timers_running)
#define	V_current_state_timers_running	\
	VNET(ofp_igmp_shm->current_state_timers_running)

#define	V_igmp_gsrdelay		VNET(ofp_igmp_shm->igmp_gsrdelay)
#define	V_igmp_fasttimo_timer	VNET(ofp_igmp_shm->igmp_fasttimo_timer)
#define	V_igi_head		VNET(ofp_igmp_shm->igi_head)
/*#define	V_if_index	VNET(ofp_igmp_shm->if_index)*/

#define	V_igmp_mtx		VNET(ofp_igmp_shm->igmp_mtx)
#define	V_igmp_raopt		VNET(ofp_igmp_shm->igmp_raopt)

void ofp_igmp_var_init_prepare(void);
int ofp_igmp_var_init_global(void);
int ofp_igmp_var_term_global(void);
int ofp_igmp_var_init_local(void);

#endif /* _OFPI_IGMP_SHM_H_ */
