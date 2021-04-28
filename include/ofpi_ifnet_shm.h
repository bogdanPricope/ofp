/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IFNET_SHM_H__
#define __OFPI_IFNET_SHM_H__

#include "ofpi_ifnet_portconf.h"
#include "ofpi_vnet.h"

#ifdef SP
#define NUM_LINUX_INTERFACES 512
#endif /*SP*/

#define OFP_IFNET_LOCK_READ(name) odp_rwlock_read_lock(\
		&shm_ifnet_port->lock_##name##_rw)
#define OFP_IFNET_UNLOCK_READ(name) odp_rwlock_read_unlock(\
		&shm_ifnet_port->lock_##name##_rw)
#define OFP_IFNET_LOCK_WRITE(name) odp_rwlock_write_lock(\
		&shm_ifnet_port->lock_##name##_rw)
#define OFP_IFNET_UNLOCK_WRITE(name) odp_rwlock_write_unlock(\
		&shm_ifnet_port->lock_##name##_rw)

struct ofp_linux_interface_param {
	uint16_t port;
	uint16_t vlan;
};

struct ofp_ifnet_port_mem {
	VNET_DEFINE(struct ofp_ifnet, ifnet_port[OFP_IFPORT_NUM]);
	VNET_DEFINE(odp_atomic_u32_t, free_port);
	VNET_DEFINE(int, ofp_num_ports);

	VNET_DEFINE(struct ofp_in_ifaddrhead, in_ifaddrhead);
	VNET_DEFINE(odp_rwlock_t, lock_ifaddr_list_rw);
#ifdef INET6
	VNET_DEFINE(struct ofp_in_ifaddrhead, in_ifaddr6head);
	VNET_DEFINE(odp_rwlock_t, lock_ifaddr6_list_rw);
#endif /* INET6 */

#ifdef SP
	VNET_DEFINE(struct ofp_linux_interface_param, linux_interface_table[NUM_LINUX_INTERFACES]);
#endif /* SP */
};

struct ofp_ifnet_vlan_mem {
	VNET_DEFINE(struct ofp_ifnet *, vlan_free_list);
	VNET_DEFINE(odp_rwlock_t, vlan_mtx);
	VNET_DEFINE(struct ofp_ifnet, vlan_ifnet[0]);
};

extern __thread struct ofp_ifnet_port_mem *shm_ifnet_port;
extern __thread struct ofp_ifnet_vlan_mem *shm_ifnet_vlan;

/*shm_ifnet_port*/
#define	V_ifnet_port VNET(shm_ifnet_port->ifnet_port)
#define	V_ifnet_free_port VNET(shm_ifnet_port->free_port)
#define	V_ifnet_num_ports VNET(shm_ifnet_port->ofp_num_ports)

#define	V_ifnet_ifaddrhead VNET(shm_ifnet_port->in_ifaddrhead)
#define	V_ifnet_lock_addr VNET(shm_ifnet_port->lock_ifaddr_list_rw)
#ifdef INET6
	#define	V_ifnet_ifaddr6head VNET(shm_ifnet_port->in_ifaddr6head)
	#define	V_ifnet_lock_addr6 VNET(shm_ifnet_port->lock_ifaddr6_list_rw)
#endif /* INET6 */

#ifdef SP
	#define	V_ifnet_linux_itf VNET(shm_ifnet_port->linux_interface_table)
#endif /* SP */

/*shm_ifnet_vlan*/
#define	V_ifnet_vlan_free_list VNET(shm_ifnet_vlan->vlan_free_list)
#define	V_ifnet_vlan_mtx VNET(shm_ifnet_vlan->vlan_mtx)
#define	V_ifnet_vlan_ifnet VNET(shm_ifnet_vlan->vlan_ifnet)

int ofp_portconf_lookup_shared_memory(void);
void ofp_portconf_init_prepare(void);
int ofp_portconf_init_global(void);
int ofp_portconf_term_global(void);

int ofp_vlan_lookup_shared_memory(void);
void ofp_vlan_init_prepare(void);
int ofp_vlan_init_global(void);
int ofp_vlan_term_global(void);

#endif /* __OFPI_IFNET_SHM_H__ */
