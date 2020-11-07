/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_UDP_SHM_H__
#define __OFPI_UDP_SHM_H__

#include "ofpi_in_pcb.h"
#include "ofpi_udp_var.h"

/*
 * UDP Shared data
 */
struct ofp_udp_var_mem {
	VNET_DEFINE(struct ofp_udpstat,	udpstat);
	VNET_DEFINE(struct inpcbhead,	udb);
	VNET_DEFINE(struct inpcbinfo,	udbinfo);

	VNET_DEFINE(uint32_t, hashtbl_off);
	VNET_DEFINE(uint32_t, hashtbl_size);

	VNET_DEFINE(uint32_t, porthashtbl_off);
	VNET_DEFINE(uint32_t, porthashtbl_size);

	VNET_DEFINE(int, cksum_enable);
	VNET_DEFINE(int, log_in_vain);
	VNET_DEFINE(int, blackhole);

	VNET_DEFINE(uint64_t, sendspace);
	VNET_DEFINE(uint64_t, recvspace);
};

extern __thread struct ofp_udp_var_mem *shm_udp;
extern __thread struct inpcbhead *shm_udp_hashtbl;
extern __thread struct inpcbporthead *shm_udp_porthashtbl;

#define	V_udpstat	VNET(shm_udp->udpstat)
#define	V_udb		VNET(shm_udp->udb)
#define	V_udbinfo	VNET(shm_udp->udbinfo)

#define V_udp_hashtbl		VNET(shm_udp_hashtbl)
#define V_udp_hashtbl_size	VNET(shm_udp->hashtbl_size)

#define V_udp_porthashtbl	VNET(shm_udp_porthashtbl)
#define V_udp_porthashtbl_size	VNET(shm_udp->porthashtbl_size)

#define V_udp_cksum_enable VNET(shm_udp->cksum_enable)
#define V_udp_log_in_vain VNET(shm_udp->log_in_vain)
#define V_udp_blackhole VNET(shm_udp->blackhole)

#define V_udp_sendspace VNET(shm_udp->sendspace)
#define V_udp_recvspace VNET(shm_udp->recvspace)

void ofp_udp_var_init_prepare(void);
int ofp_udp_var_init_global(void);
int ofp_udp_var_term_global(void);
int ofp_udp_var_init_local(void);

#endif /* __OFPI_UDP_SHM_H__ */
