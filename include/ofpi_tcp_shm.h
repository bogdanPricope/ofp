/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_TCP_SHM_H__
#define __OFPI_TCP_SHM_H__

#include "ofpi_in_pcb.h"
#include "ofpi_callout.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_syncache.h"
#include "ofpi_config.h"

#include "api/ofp_timer.h"

/*
 * Shared data format
 */
struct ofp_tcp_var_mem {
#ifdef OFP_RSS
	VNET_DEFINE(struct inpcbhead, ofp_tcb[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl[OFP_MAX_NUM_CPU]);
	odp_timer_t ofp_tcp_slow_timer[OFP_MAX_NUM_CPU];
#else
	VNET_DEFINE(struct inpcbhead, ofp_tcb);/* queue of active tcpcb's */
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl);
	odp_timer_t ofp_tcp_slow_timer;
#endif

	VNET_DEFINE(struct tcp_syncache, tcp_syncache);

	VNET_DEFINE(uma_zone_t, tcp_reass_zone);
	VNET_DEFINE(uma_zone_t, tcp_syncache_zone);
	VNET_DEFINE(uma_zone_t, tcpcb_zone);
	VNET_DEFINE(uma_zone_t, tcptw_zone);
	VNET_DEFINE(uma_zone_t, ofp_sack_hole_zone);

	uint32_t hashtbl_off;
	uint32_t hashtbl_size;

	uint32_t porthashtbl_off;
	uint32_t porthashtbl_size;

	uint32_t syncachehashtbl_off;
	uint32_t syncachehashtbl_size;
};
extern __thread struct ofp_tcp_var_mem *shm_tcp;
extern __thread struct inpcbhead *shm_tcp_hashtbl;
extern __thread struct inpcbporthead *shm_tcp_porthashtbl;
extern __thread struct syncache_head *shm_tcp_syncachehashtbl;

#ifdef OFP_RSS
#define	V_tcb			VNET(shm_tcp->ofp_tcb[odp_cpu_id()])
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo[odp_cpu_id()])
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl[odp_cpu_id()])

#define	V_tcbtbl		VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfotbl	VNET(shm_tcp->ofp_tcbinfo)

#else
#define	V_tcb			VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo)
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl)

#define	V_tcbtbl		VNET(&(shm_tcp->ofp_tcb))
#define	V_tcbinfotbl	VNET(&(shm_tcp->ofp_tcbinfo))
#endif

#define V_tcp_hashtbl		VNET(shm_tcp_hashtbl)
#define V_tcp_hashtbl_size	VNET(shm_tcp->hashtbl_size)

#define V_tcp_porthashtbl	VNET(shm_tcp_porthashtbl)
#define V_tcp_porthashtbl_size	VNET(shm_tcp->porthashtbl_size)

#define V_tcp_syncachehashtbl		VNET(shm_tcp_syncachehashtbl)
#define V_tcp_syncachehashtbl_size	VNET(shm_tcp->syncachehashtbl_size)

#define V_tcp_syncache			VNET(shm_tcp->tcp_syncache)

#define	V_tcp_reass_zone	VNET(shm_tcp->tcp_reass_zone)
#define	V_tcpcb_zone		VNET(shm_tcp->tcpcb_zone)
#define	V_tcptw_zone		VNET(shm_tcp->tcptw_zone)
#define	V_tcp_syncache_zone	VNET(shm_tcp->tcp_syncache_zone)
#define	V_sack_hole_zone	VNET(shm_tcp->ofp_sack_hole_zone)

int ofp_tcp_var_lookup_shared_memory(void);
void ofp_tcp_var_init_prepare(void);
int ofp_tcp_var_init_global(void);
int ofp_tcp_var_term_global(void);

#endif /* __OFPI_TCP_SHM_H__ */

