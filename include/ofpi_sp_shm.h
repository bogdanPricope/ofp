/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_SP_SHM_H__
#define __OFPI_SP_SHM_H__

#include "odp_api.h"
#include "ofpi_netlink.h"
#include "ofpi_vnet.h"

struct ofp_sp_shm_mem {
	/* netlink */
	ofp_netlink_sock_t ns_sockets[NUM_NS_SOCKETS];

	VNET_DEFINE(int, ns_sock_cnt);
};

extern __thread struct ofp_sp_shm_mem *shm_sp;

#define V_sp_netlink_sockets VNET(shm_sp->ns_sockets)
#define V_sp_netlink_sock_cnt VNET(shm_sp->ns_sock_cnt)

void ofp_sp_init_prepare(void);
int ofp_sp_init_global(void);
int ofp_sp_term_global(void);
int ofp_sp_init_local(void);

#endif /*__OFPI_SP_SHM_H__*/

