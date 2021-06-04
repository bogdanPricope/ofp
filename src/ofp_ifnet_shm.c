/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_ifnet_shm.h"
#include "ofpi_shared_mem.h"
#include "ofpi_global_param_shm.h"
#include "ofpi_avl.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define SHM_NAME_PORTS "OfpPortconfShMem"
#define SHM_NAME_VLAN "OfpVlanconfShMem"

#define SHM_SIZE_VLAN (sizeof(struct ofp_ifnet_vlan_mem) + \
		       sizeof(struct ofp_ifnet) * global_param->num_vlan)

__thread struct ofp_ifnet_port_mem *shm_ifnet_port;
__thread struct ofp_ifnet_vlan_mem *shm_ifnet_vlan;

/*Wrapper functions over AVL tree*/
static void *new_vlan(int (*compare_fun)(void *compare_arg, void *a, void *b),
		      void *compare_arg)
{
	return avl_tree_new(compare_fun, compare_arg);
}

static void free_vlan(void *root, int (*free_key_fun)(void *arg))
{
	avl_tree_free((avl_tree *)root, free_key_fun);
}

static int vlan_ifnet_compare(void *compare_arg, void *a, void *b)
{
	struct ofp_ifnet *a1 = a;
	struct ofp_ifnet *b1 = b;

	(void)compare_arg;

	return (a1->vlan - b1->vlan);
}

static int ofp_portconf_alloc_shared_memory(void)
{
	shm_ifnet_port = ofp_shared_memory_alloc(SHM_NAME_PORTS,
						 sizeof(*shm_ifnet_port));
	if (shm_ifnet_port == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_portconf_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_PORTS) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_ifnet_port = NULL;

	return rc;
}

void ofp_portconf_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_PORTS, sizeof(*shm_ifnet_port));
}

int ofp_portconf_init_global(void)
{
	int i, j;
	struct ofp_ifnet *ifnet = NULL;

	HANDLE_ERROR(ofp_portconf_alloc_shared_memory());

	memset(shm_ifnet_port, 0, sizeof(*shm_ifnet_port));
	for (i = 0; i < OFP_IFPORT_NUM; i++) {
		V_ifnet_port[i].if_state = OFP_IFT_STATE_FREE;
		V_ifnet_port[i].pktio = ODP_PKTIO_INVALID;

		for (j = 0; j < OFP_PKTOUT_QUEUE_MAX; j++)
			V_ifnet_port[i].out_queue_queue[j] =
				ODP_QUEUE_INVALID;

		V_ifnet_port[i].loopq_def = ODP_QUEUE_INVALID;
#ifdef SP
		V_ifnet_port[i].spq_def = ODP_QUEUE_INVALID;
#endif /*SP*/
		V_ifnet_port[i].pkt_pool = ODP_POOL_INVALID;
	}

	odp_atomic_init_u32(&V_ifnet_free_port, 0);

	V_ifnet_num_ports = OFP_IFPORT_NUM;

	for (i = 0; i < V_ifnet_num_ports; i++) {
		ifnet = &V_ifnet_port[i];

		ifnet->vlan_structs = new_vlan(vlan_ifnet_compare, NULL);
		if (ifnet->vlan_structs == NULL) {
			OFP_ERR("Failed to initialize vlan structures.");
			return -1;
		}
		ifnet->port = i;
		ifnet->vlan = OFP_IFPORT_NET_SUBPORT_ITF;

		switch (i) {
		case OFP_IFPORT_VXLAN:
			ifnet->if_type = OFP_IFT_VXLAN;
			break;
		default:
			ifnet->if_type = OFP_IFT_ETHER;
		};

		ifnet->if_mtu = 1500;
		ifnet->if_state = OFP_IFT_STATE_FREE;
		/* Multicast related */
		OFP_TAILQ_INIT(&ifnet->if_multiaddrs);
		ifnet->if_flags |= OFP_IFF_MULTICAST;
		ifnet->if_afdata[OFP_AF_INET] = &ifnet->ii_inet;
		/* TO DO:
		   V_ifnet_port[i].if_afdata[OFP_AF_INET6] =
		   &V_ifnet_port[i].ii_inet6;
		*/
		/* Set locally administered default mac address.
		   This is needed by vxlan and other
		   virtual interfaces.
		*/
		if (odp_random_data((uint8_t *)ifnet->if_mac,
				    sizeof(ifnet->if_mac), 0) < 0) {
			OFP_ERR("Failed to initialize default MAC address.");
			return -1;
		}
		/* Universally administered and locally administered addresses
		   are distinguished by setting the second least significant bit
		   of the most significant byte of the address.
		*/
		ifnet->if_mac[0] = 0x02;
		/* Port number. */
		ifnet->if_mac[1] = i;
		memset(ifnet->ip_addr_info, 0, sizeof(ifnet->ip_addr_info));
#ifdef SP
		ifnet->sp_itf_mgmt = 1;
		ifnet->sp_status = OFP_SP_UP;
#endif /* SP */
	}

#ifdef SP
	for (i = 0; i < NUM_LINUX_INTERFACES; ++i)
		V_ifnet_linux_itf[i].port = PORT_UNDEF;
#endif /* SP */

	OFP_TAILQ_INIT(&V_ifnet_ifaddrhead);
	odp_rwlock_init(&V_ifnet_lock_addr);
#ifdef INET6
	OFP_TAILQ_INIT(&V_ifnet_ifaddr6head);
	odp_rwlock_init(&V_ifnet_lock_addr6);
#endif /* INET6 */

	return 0;
}

int ofp_portconf_lookup_shared_memory(void)
{
	shm_ifnet_port = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (shm_ifnet_port == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

int ofp_portconf_term_global(void)
{
	int i;
	int rc = 0;

	shm_ifnet_port = ofp_shared_memory_lookup(SHM_NAME_PORTS);
	if (shm_ifnet_port == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	} else {
		for (i = 0; i < V_ifnet_num_ports; ++i)
			if (V_ifnet_port[i].vlan_structs)
				free_vlan(V_ifnet_port[i].vlan_structs,
					  free_key);
	}

	CHECK_ERROR(ofp_portconf_free_shared_memory(), rc);

	return rc;
}

static int ofp_vlan_alloc_shared_memory(void)
{
	shm_ifnet_vlan = ofp_shared_memory_alloc(SHM_NAME_VLAN, SHM_SIZE_VLAN);
	if (shm_ifnet_vlan == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_vlan_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_VLAN) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_ifnet_vlan = NULL;
	return rc;
}

int ofp_vlan_lookup_shared_memory(void)
{
	shm_ifnet_vlan = ofp_shared_memory_lookup(SHM_NAME_VLAN);
	if (shm_ifnet_vlan == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

void ofp_vlan_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_VLAN, SHM_SIZE_VLAN);
}

int ofp_vlan_init_global(void)
{
	int i;

	/* init vlan shared memory */
	HANDLE_ERROR(ofp_vlan_alloc_shared_memory());
	memset(shm_ifnet_vlan, 0, sizeof(*shm_ifnet_vlan));
	for (i = 0; i < global_param->num_vlan; i++) {
		V_ifnet_vlan_ifnet[i].next = (i == global_param->num_vlan - 1) ?
			NULL : &(V_ifnet_vlan_ifnet[i + 1]);
	}
	V_ifnet_vlan_free_list = &(V_ifnet_vlan_ifnet[0]);
	odp_rwlock_init(&V_ifnet_vlan_mtx);

	return 0;
}

int ofp_vlan_term_global(void)
{
	int rc = 0;

	shm_ifnet_vlan = ofp_shared_memory_lookup(SHM_NAME_VLAN);
	if (shm_ifnet_vlan == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		rc = -1;
	}
	CHECK_ERROR(ofp_vlan_free_shared_memory(), rc);

	return rc;
}
