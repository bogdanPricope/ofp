/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "ofpi.h"
#include "ofpi_ifnet_shm.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_ifnet.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_avl.h"

#include "ofpi_queue.h"
#include "ofpi_ioctl.h"
#include "ofpi_if_vxlan.h"
#include "ofpi_ifnet.h"
#include "ofpi_tree.h"
#include "ofpi_sysctl.h"
#include "ofpi_in_var.h"
#include "ofpi_log.h"
#include "ofpi_netlink.h"
#include "ofpi_igmp_var.h"

void ofp_ifnet_print_ip_addrs(struct ofp_ifnet *dev);

static struct ofp_ifnet *ofp_create_subport(struct ofp_ifnet *ifnet_port,
					    uint16_t subport);
static struct ofp_ifnet *ofp_get_subport(struct ofp_ifnet *ifnet_port,
					 uint16_t subport);
static int ofp_del_subport(struct ofp_ifnet *ifnet_port, uint16_t subport);

int ofp_ifport_net_create(char *if_name,
			  odp_pktio_param_t *pktio_param,
			  odp_pktin_queue_param_t *pktin_param,
			  odp_pktout_queue_param_t *pktout_param,
			  int *res_port, uint16_t *res_subport)
{
	int port = 0;
	int res = 0;
	struct ofp_ifnet *ifnet = NULL;

	port = ofp_free_port_alloc();
	if (port == -1)
		return -1;

	ifnet = ofp_get_ifnet(port, (uint16_t)OFP_IFPORT_NET_SUBPORT_ITF, 0);
	if (ifnet == NULL) {
		OFP_ERR("Got ifnet NULL");
		return -1;
	}

	res = ofp_ifnet_net_create(if_name, pktio_param,
				   pktin_param, pktout_param, ifnet);
	if (res != 0) {
		OFP_ERR("Error: Failed to create the interface.");
		return -1;
	}

	if (res_port)
		*res_port = port;

	if (res_subport)
		*res_subport = (uint16_t)OFP_IFPORT_NET_SUBPORT_ITF;

	return res;
}

ofp_ifnet_t ofp_ifport_net_ifnet_get_by_port(int port)
{
	if (!OFP_IFPORT_IS_NET(port))
		return OFP_IFNET_INVALID;

	return (ofp_ifnet_t)ofp_get_ifnet(port, OFP_IFPORT_NET_SUBPORT_ITF, 0);
}

ofp_ifnet_t ofp_ifport_net_ifnet_get_by_name(char *if_name)
{
	int i;
	struct ofp_ifnet *ifnet = NULL;

	for (i = OFP_IFPORT_NET_FIRST; i <= OFP_IFPORT_NET_LAST; i++) {
		ifnet = &V_ifnet_port[i];

		if (ifnet->if_state == OFP_IFT_STATE_USED &&
		    !strcmp(ifnet->if_name, if_name)) {
			return (ofp_ifnet_t)ifnet;
		}
	}

	return OFP_IFNET_INVALID;
}

int ofp_ifport_count(void)
{
	return V_ifnet_num_ports;
}

ofp_ifnet_t ofp_ifport_ifnet_get(int port, uint16_t subport)
{
	struct ofp_ifnet *ifnet = ofp_get_ifnet(port, subport, 0);

	if (!ifnet)
		return OFP_IFNET_INVALID;

	return (ofp_ifnet_t)ifnet;
}

struct ofp_ifnet *ofp_get_ifnet_pktio(odp_pktio_t pktio)
{
	int i;

	for (i = 0; i < OFP_IFPORT_NUM; i++) {
		if (V_ifnet_port[i].if_state == OFP_IFT_STATE_USED &&
		    V_ifnet_port[i].pktio == pktio)
			return &V_ifnet_port[i];
	}

	return NULL;
}

struct ofp_ifnet *ofp_get_port_itf(int port)
{
	if (port < 0 || port >= V_ifnet_num_ports) {
		OFP_DBG("port:%d is outside the valid interval", port);
		return NULL;
	}

	return &V_ifnet_port[port];
}

odp_pktio_t ofp_ifport_net_pktio_get(int port)
{
	struct ofp_ifnet *ifnet = NULL;

	if (!OFP_IFPORT_IS_NET(port))
		return ODP_PKTIO_INVALID;

	ifnet = &V_ifnet_port[port];
	if (ifnet->if_state != OFP_IFT_STATE_USED)
		return ODP_PKTIO_INVALID;

	return ifnet->pktio;
}

odp_queue_t ofp_ifport_net_spq_get(int port)
{
#ifdef SP
	struct ofp_ifnet *ifnet = NULL;

	if (!OFP_IFPORT_IS_NET(port))
		return ODP_QUEUE_INVALID;

	ifnet = &V_ifnet_port[port];
	if (ifnet->if_state != OFP_IFT_STATE_USED)
		return ODP_QUEUE_INVALID;

	return ifnet->spq_def;
#else
	(void)port;

	return ODP_QUEUE_INVALID;
#endif /*SP*/
}

odp_queue_t ofp_ifport_net_loopq_get(int port)
{
	struct ofp_ifnet *ifnet = NULL;

	if (!OFP_IFPORT_IS_NET(port))
		return ODP_QUEUE_INVALID;

	ifnet = &V_ifnet_port[port];
	if (ifnet->if_state != OFP_IFT_STATE_USED)
		return ODP_QUEUE_INVALID;

	return ifnet->loopq_def;
}

static int vlan_iterate_inorder(void *root,
			int (*iterate_fun)(void *key, void *iter_arg),
			void *iter_arg)
{
	return avl_iterate_inorder(root, iterate_fun, iter_arg);
}

static int vlan_cleanup_inorder(void *root,
				int (*iterate_fun)(void *key, void *iter_arg),
				void *iter_arg)
{
	return avl_cleanup_inorder(root, iterate_fun, iter_arg);
}

int vlan_ifnet_insert(void *root, void *elem)
{
	return avl_insert((avl_tree *)root, elem);
}

int vlan_ifnet_delete(void *root, void *elem,
					int (*free_key_fun)(void *arg))
{
	return avl_delete(root, elem, free_key_fun);
}

int ofp_vlan_get_by_key(
	void *root,
	void *key,
	void **value_address
	)
{
	return avl_get_by_key(root, key, value_address);
}

static int vlan_match_ip(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	uint32_t ip = *((uint32_t *)iter_arg);

	if (-1 != ofp_ifnet_ip_find(iface, ip))
		return iface->vlan;
	else
		return 0;
}

int ofp_free_port_alloc(void)
{
	int port = (int)odp_atomic_fetch_inc_u32(&V_ifnet_free_port);
	if (port > OFP_IFPORT_NET_LAST) {
		OFP_ERR("Interfaces are depleted");
		return -1;
	}
	return port;
}

struct ofp_ifnet *ofp_vlan_alloc(void)
{
	odp_rwlock_write_lock(&V_ifnet_vlan_mtx);
	struct ofp_ifnet *vlan = V_ifnet_vlan_free_list;

	if (V_ifnet_vlan_free_list)
		V_ifnet_vlan_free_list = V_ifnet_vlan_free_list->next;

	odp_rwlock_write_unlock(&V_ifnet_vlan_mtx);

	if (vlan == NULL) {
		OFP_ERR("Cannot allocate vlan!");
		return (NULL);
	}

	return vlan;
}

static void ofp_vlan_free(struct ofp_ifnet *vlan)
{
	odp_rwlock_write_lock(&V_ifnet_vlan_mtx);
	vlan->next = V_ifnet_vlan_free_list;
	V_ifnet_vlan_free_list = vlan;
	odp_rwlock_write_unlock(&V_ifnet_vlan_mtx);
}

static void print_eth_stats(odp_pktio_stats_t stats, ofp_print_t *pr)
{
	ofp_print(pr,
		  "\tRX: bytes:%lu packets:%lu dropped:%lu errors:%lu unknown:%lu\r\n",
		  stats.in_octets,
		  stats.in_ucast_pkts,
		  stats.in_discards,
		  stats.in_errors,
		  stats.in_unknown_protos);

	ofp_print(pr,
		  "\tTX: bytes:%lu packets:%lu dropped:%lu error:%lu\r\n\r\n",
		  stats.out_octets,
		  stats.out_ucast_pkts,
		  stats.out_discards,
		  stats.out_errors);
}

static int iter_vlan(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	char buf[16];
	ofp_print_t *pr = (ofp_print_t *)iter_arg;
	odp_pktio_stats_t stats;
	int res;
	uint32_t mask = ~0;


	res = odp_pktio_stats(iface->pktio, &stats);

	mask = odp_cpu_to_be_32(mask << (32 - iface->ip_addr_info[0].masklen));

	if (ofp_if_type(iface) == OFP_IFT_GRE && iface->vlan) {
#ifdef SP
		ofp_print(pr, "gre%d	(%d) slowpath: %s\r\n", iface->vlan,
			  iface->linux_index, iface->sp_status ? "on" : "off");
#else
		ofp_print(pr, "gre%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_print(pr, "	VRF: %d\r\n", iface->vrf);

		ofp_print(pr,
			  "	Link encap:Ethernet	HWaddr: %s\r\n"
			  "	inet addr:%s	P-t-P:%s	Mask:%s\r\n"
#ifdef INET6
			  "	inet6 addr: %s\r\n"
#endif /* INET6 */
			  "	MTU: %d\r\n",
			  ofp_print_mac(iface->if_mac),
			  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			  ofp_print_ip_addr(iface->ip_p2p),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			  iface->if_mtu);

		ofp_print(pr,
			  "	Local: %s	Remote: %s\r\n",
			  ofp_print_ip_addr(iface->ip_local),
			  ofp_print_ip_addr(iface->ip_remote));
		if (res == 0)
			print_eth_stats(stats, pr);
		else
			ofp_print(pr, "\r\n");
		return 0;
	} else if (ofp_if_type(iface) == OFP_IFT_GRE && !iface->vlan) {
		ofp_print(pr, "gre%d\r\n"
			  "	Link not configured\r\n\r\n",
			  iface->vlan);
		return 0;
	}

	if (ofp_if_type(iface) == OFP_IFT_VXLAN) {
#ifdef SP
		ofp_print(pr, "vxlan%d	(%d) slowpath: %s\r\n", iface->vlan,
			  iface->linux_index,
			  iface->sp_status ? "on" : "off");
#else
		ofp_print(pr, "vxlan%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_print(pr, "	VRF: %d\r\n", iface->vrf);

		ofp_print(pr,
			  "	Link encap:Ethernet	HWaddr: %s\r\n"
			  "	inet addr:%s	Bcast:%s	Mask:%s\r\n"
#ifdef INET6
			  "	inet6 addr: %s\r\n"
#endif /* INET6 */
			  "	Group:%s	Iface:%s\r\n"
			  "	MTU: %d\r\n",
			  ofp_print_mac(iface->if_mac),
			  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			  ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->link_local),
#endif /* INET6 */
			  ofp_print_ip_addr(iface->ip_p2p),
			  ofp_port_vlan_to_ifnet_name(iface->physport,
						      iface->physvlan),
			  iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, pr);
		else
			ofp_print(pr, "\r\n");
		return 0;
	}

	if (ofp_if_type(iface) == OFP_IFT_LOOP) {
#ifdef SP
		ofp_print(pr, "lo%d  (%d) slowpath: %s\r\n", iface->vlan,
			  iface->linux_index,
			  iface->sp_status ? "on" : "off");
#else
		ofp_print(pr, "lo%d\r\n", iface->vlan);
#endif /* SP */

		if (iface->vrf)
			ofp_print(pr, "	VRF: %d\r\n", iface->vrf);

		ofp_print(pr,
			  "	Link encap:loopback\r\n"
			  "	inet addr:%s	Bcast:%s	Mask:%s\r\n"
#ifdef INET6
			  "	inet6 addr: %s/%d\r\n"
#endif /* INET6 */
			  "	MTU: %d\r\n",
			  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
			  ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
			  ofp_print_ip_addr(mask),
#ifdef INET6
			  ofp_print_ip6_addr(iface->ip6_addr),
			  iface->ip6_prefix,
#endif /* INET6 */
			  iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, pr);
		else
			ofp_print(pr, "\r\n");
		return 0;
	}

	snprintf(buf, sizeof(buf), ".%d", iface->vlan);

	if (ofp_has_mac(iface->if_mac)) {
#ifdef SP
		ofp_print(pr,
			  "%s%d%s	(%d) (%s) slowpath: %s\r\n",
			  OFP_IFNAME_PREFIX,
			  iface->port,
			  iface->vlan != OFP_IFPORT_NET_SUBPORT_ITF ? buf : "",
			  iface->linux_index,
			  iface->if_name,
			  iface->sp_status ? "on" : "off");
#else
		ofp_print(pr,
			  "%s%d%s	(%s)\r\n",
			  OFP_IFNAME_PREFIX,
			  iface->port,
			  iface->vlan != OFP_IFPORT_NET_SUBPORT_ITF ? buf : "",
			  iface->if_name);
#endif /* SP */

		if (iface->vrf)
			ofp_print(pr, "	VRF: %d\r\n", iface->vrf);

		ofp_print(pr,
			  "	Link encap:Ethernet	HWaddr: %s\r\n",
			  ofp_print_mac(iface->if_mac));

		if (iface->ip_addr_info[0].ip_addr)
			ofp_print(pr,
				  "	inet addr:%s	Bcast:%s	Mask:%s\r\n",
				  ofp_print_ip_addr(iface->ip_addr_info[0].ip_addr),
				  ofp_print_ip_addr(iface->ip_addr_info[0].bcast_addr),
				  ofp_print_ip_addr(mask));

#ifdef INET6
		ofp_print(pr,
			  "	inet6 addr: %s Scope:Link\r\n",
			  ofp_print_ip6_addr(iface->link_local));

		if (ofp_ip6_is_set(iface->ip6_addr))
			ofp_print(pr,
				  "	inet6 addr: %s/%d\r\n",
				  ofp_print_ip6_addr(iface->ip6_addr),
				  iface->ip6_prefix);
#endif /* INET6 */

		ofp_print(pr,
			  "	MTU: %d\r\n",
			  iface->if_mtu);
		if (res == 0)
			print_eth_stats(stats, pr);
		else
			ofp_print(pr, "\r\n");
	} else {
		ofp_print(pr, "%s%d%s\r\n"
			  "	Link not configured\r\n\r\n",
			  OFP_IFNAME_PREFIX,
			  iface->port, iface->vlan ? buf : "");
	}

	return 0;
}

void ofp_ifport_ifnet_show(ofp_print_t *pr)
{
	int i;

	/* fp interfaces */
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_vlan(&V_ifnet_port[i], pr);
		vlan_iterate_inorder(V_ifnet_port[i].vlan_structs,
				     iter_vlan, pr);
	}

	/* gre interfaces */
	if (avl_get_first(V_ifnet_port[OFP_IFPORT_GRE].vlan_structs))
		vlan_iterate_inorder(
			V_ifnet_port[OFP_IFPORT_GRE].vlan_structs,
			iter_vlan, pr);
	else
		ofp_print(pr, "gre\r\n"
				"	Link not configured\r\n\r\n");

	/* vxlan interfaces */
	if (avl_get_first(V_ifnet_port[OFP_IFPORT_VXLAN].vlan_structs))
		vlan_iterate_inorder(
			V_ifnet_port[OFP_IFPORT_VXLAN].vlan_structs,
			iter_vlan, pr);
	else
		ofp_print(pr, "vxlan\r\n"
				"	Link not configured\r\n\r\n");
	/* local interfaces */
	if (avl_get_first(V_ifnet_port[OFP_IFPORT_LOCAL].vlan_structs))
		vlan_iterate_inorder(
			V_ifnet_port[OFP_IFPORT_LOCAL].vlan_structs,
			iter_vlan, pr);
	else
		ofp_print(pr, "lo\r\n"
				"	Link not configured\r\n\r\n");
}

static int iter_vlan_2(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	ofp_print_t *pr = (ofp_print_t *)iter_arg;

	ofp_ifnet_print_ip_info(pr, iface);

	return 0;
}

void ofp_ifport_net_ipv4_addr_show(ofp_print_t *pr)
{
	int i;
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_vlan_2(&V_ifnet_port[i], pr);
		vlan_iterate_inorder(V_ifnet_port[i].vlan_structs,
				     iter_vlan_2, pr);
	}
}

int free_key(void *key)
{
	ofp_vlan_free(key);
	return 1;
}

#ifdef SP
static int exec_sys_call_depending_on_vrf(const char *cmd, uint16_t vrf)
{
	char buf[PATH_MAX];
	int netns, ret;

	OFP_DBG("system(%s) vrf=%d", cmd, vrf);
	if (vrf == 0) {
		return system(cmd);
	}

	/* Does vrf exist? */
	snprintf(buf, sizeof(buf), "/var/run/netns/vrf%d", vrf);
	netns = open(buf, O_RDONLY | O_CLOEXEC);
	if (netns < 0) {
		/* Create a vrf */
		OFP_INFO("Creating network namespace 'vrf%d'...", vrf);
		snprintf(buf, sizeof(buf), "ip netns add vrf%d", vrf);
		ret = system(buf);
		if (ret < 0)
			OFP_WARN("System call failed: '%s'", buf);
		ofp_create_ns_socket(vrf);
	}
	close(netns);

	/* Dummy cmd to create a new namespace? */
	if (cmd == NULL || cmd[0] == 0)
		return 0;

	snprintf(buf, sizeof(buf), "ip netns exec vrf%d %s", vrf, cmd);
	ret = system(buf);
	if (ret < 0)
		OFP_WARN("System call failed: '%s'", buf);
	return ret;
}
#endif /* SP */

const char *ofp_ifport_net_ipv4_up(int port, uint16_t subport_vlan,
				   uint16_t vrf,
				   uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
	uint32_t mask_t;
	char *iname;
#endif /* SP */
	struct ofp_ifnet *data;
	uint32_t mask;

#ifdef SP
	(void)ret;
#endif /*SP*/
	if (!OFP_IFPORT_IS_NET(port))
		return "Wrong port number";

	if (vrf >= global_param->num_vrf)
		return "VRF ID too big";

	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - masklen));

	data = ofp_get_ifnet(port, subport_vlan, 0);

	if (data && data->vrf != vrf) {
#ifdef SP
		if (subport_vlan == OFP_IFPORT_NET_SUBPORT_ITF &&
		    data->vrf == 0) {
			/* Create vrf in not exist using dummy call */
			exec_sys_call_depending_on_vrf("", vrf);
			/* Move to vrf (can be done only once!) */
			iname = ofp_port_vlan_to_ifnet_name(port, OFP_IFPORT_NET_SUBPORT_ITF);
			snprintf(cmd, sizeof(cmd),
				 "ip link set %s netns vrf%d", iname, vrf);
			ret = exec_sys_call_depending_on_vrf(cmd, 0);
		}
#endif /* SP */

		ofp_ifport_ifnet_down(data->port, data->vlan);
		data = ofp_get_ifnet(port, subport_vlan, 1);
	}

	if (subport_vlan != OFP_IFPORT_NET_SUBPORT_ITF) {
		if (data == NULL) {
			data = ofp_get_ifnet(port, subport_vlan, 1);
			data->if_type = OFP_IFT_ETHER;
#ifdef SP
			iname = ofp_port_vlan_to_ifnet_name(port, OFP_IFPORT_NET_SUBPORT_ITF);
			snprintf(cmd, sizeof(cmd),
				 "ip link add name %s.%d link %s type vlan id %d",
				 iname, subport_vlan, iname, subport_vlan);
			ret = exec_sys_call_depending_on_vrf(cmd, 0);

			if (vrf) {
				/* Create vrf if not exist using dummy call */
				exec_sys_call_depending_on_vrf("", vrf);
				/* Move to vrf */
				snprintf(cmd, sizeof(cmd),
					 "ip link set %s.%d netns vrf%d",
					 iname, subport_vlan, vrf);
				ret = exec_sys_call_depending_on_vrf(cmd, 0);
			}
#endif /* SP */
		} else {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf,
					     subport_vlan, port,
					     data->ip_addr_info[0].ip_addr,
					     data->ip_addr_info[0].masklen,
					     0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf,
					     subport_vlan, port,
					     data->ip_addr_info[0].ip_addr, 32,
					     0, 0);
		}
		data->vrf = vrf;
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf,
				     subport_vlan, port,
				     addr, 32, 0,
				     OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf,
				     subport_vlan, port,
				     addr & mask, masklen, 0, OFP_RTF_NET);
		ofp_set_first_ifnet_addr(data, addr, addr | ~mask, masklen);
#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		mask_t = odp_be_to_cpu_32(mask);
		snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %d.%d.%d.%d up",
			 ofp_port_vlan_to_ifnet_name(port, subport_vlan),
			 ofp_print_ip_addr(addr),
			(uint8_t)(mask_t >> 24),
			(uint8_t)(mask_t >> 16),
			(uint8_t)(mask_t >> 8),
			(uint8_t)mask_t);

		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	} else {
		if (data->ip_addr_info[0].ip_addr) {
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf,
					     OFP_IFPORT_NET_SUBPORT_ITF, port,
					     data->ip_addr_info[0].ip_addr,
					     data->ip_addr_info[0].masklen,
					     0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, data->vrf,
					     OFP_IFPORT_NET_SUBPORT_ITF, port,
					     data->ip_addr_info[0].ip_addr, 32,
					     0, 0);
		}

		data->vrf = vrf;

		/* Add interface to the if_addr v4 queue */
		ofp_ifaddr_elem_add(data);
#ifdef INET6
		ofp_mac_to_link_local(data->if_mac, data->link_local);
#endif /* INET6 */

		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf,
				     OFP_IFPORT_NET_SUBPORT_ITF, port,
				     addr, 32, 0, OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf,
				     OFP_IFPORT_NET_SUBPORT_ITF, port,
				     addr & mask, masklen, 0, OFP_RTF_NET);
		ofp_set_first_ifnet_addr(data, addr, addr | ~mask, masklen);

#ifdef SP
		if (vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		mask_t = odp_be_to_cpu_32(mask);
		iname = ofp_port_vlan_to_ifnet_name(port,
						    OFP_IFPORT_NET_SUBPORT_ITF);
		snprintf(cmd, sizeof(cmd), "ifconfig %s %s netmask %d.%d.%d.%d up",
			iname, ofp_print_ip_addr(addr),
			(uint8_t)(mask_t >> 24),
			(uint8_t)(mask_t >> 16),
			(uint8_t)(mask_t >> 8),
			(uint8_t)mask_t);
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
#endif /* SP */
	}

	return NULL;
}

const char *ofp_ifport_net_ipv4_addr_add(int port, uint16_t vlan, uint16_t vrf,
					 uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	uint32_t mask;
	struct ofp_ifnet *data;
	int idx;
	if (!OFP_IFPORT_IS_NET(port))
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan, 0);
	if (NULL == data)
		return "Invalid interface";
	idx = ofp_ifnet_ip_find(data, addr);
	if (-1 == idx) {
		mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - masklen));
		ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port,
			addr, 32, 0,
			OFP_RTF_LOCAL);
		ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port,
			addr & mask, masklen, 0, OFP_RTF_NET);

		idx = ofp_ifnet_ip_find_update_fields(data, addr, masklen, addr | ~mask);
		if (-1 == idx) {
			ofp_set_route_params(OFP_ROUTE_DEL, vrf, vlan, port,
				addr & mask, masklen, 0, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, vrf, vlan, port,
				addr, 32, 0, 0);

			return "Failed to add IP address";
		}
#ifdef SP
		snprintf(cmd, sizeof(cmd), "ip address add %s/%d broadcast %s dev %s",
			ofp_print_ip_addr(addr), masklen, ofp_print_ip_addr(addr | ~mask),
			ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
		if (0 != ret)
			OFP_INFO("Command %s failed\n", cmd);
#endif
	} else
		return "Address already added";

	return NULL;
}

const char *ofp_ifport_net_ipv4_addr_del(int port, uint16_t vlan, int vrf,
					 uint32_t addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
#endif /* SP */
	struct ofp_ifnet *data;
	int idx;
	static char msg[64];

	(void)vrf; /* Suppress unused parameter warning when SP is not enabled. */

	if (!OFP_IFPORT_IS_NET(port))
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan, 0);
	if (NULL == data)
		return "Invalid interface";

	idx = ofp_ifnet_ip_find(data, addr);
	if (-1 != idx) {
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - data->ip_addr_info[idx].masklen));

		if (masklen != data->ip_addr_info[idx].masklen) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, sizeof(msg) , "Provided %d differs from the %d saved\n", masklen, data->ip_addr_info[idx].masklen);
			return msg;
		}
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, data->vlan, port,
			addr & mask , masklen, 0, 0);
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, data->vlan, port,
			addr, 32, 0, 0);

		idx = ofp_ifnet_ip_find(data, addr);
		if (-1 != idx) {
			memset(msg, 0, sizeof(msg));
			snprintf(msg, sizeof(msg) , "Failed to remove %s address\n", ofp_print_ip_addr(addr));
			return msg;
		}
#ifdef SP
		snprintf(cmd, sizeof(cmd),
			"ip addr del %s/%d dev %s",
			ofp_print_ip_addr(addr),
			masklen, ofp_port_vlan_to_ifnet_name(port, vlan));
		ret = exec_sys_call_depending_on_vrf(cmd, vrf);
		if (0 != ret)
			OFP_INFO("Command %s failed\n", cmd);
#endif
		if (0 == data->ip_addr_info[0].ip_addr) {
			/* Remove interface from the if_addr v4 queue */
			ofp_ifaddr_elem_del(data);
		}
	} else {
		return "Address not found!";
	}

	return NULL;
}

const char *ofp_ifport_tun_ipv4_up(int port, uint16_t greid,
				   uint16_t vrf, uint32_t tun_loc,
				   uint32_t tun_rem, uint32_t p2p,
				   uint32_t addr, int mlen,
				   odp_bool_t sp_itf_mgmt)
{
#ifdef SP
	char cmd[200];
	int new_tun = 0;
#endif /* SP */
	struct ofp_ifnet *data, *dev_root;

#ifdef SP
	(void)new_tun;
#endif /*SP*/

	(void)sp_itf_mgmt;

	if (!OFP_IFPORT_IS_GRE(port))
		return "Wrong port number.";

	if (vrf >= global_param->num_vrf)
		return "VRF ID too big";

	dev_root = ofp_get_ifnet_by_ip(tun_loc, vrf);
	if (dev_root == NULL)
		return "Tunnel local ip not configured.";

	data = ofp_get_ifnet(port, greid, 0);

	if (data && data->vrf != vrf) {
		ofp_ifport_ifnet_down(data->port, data->vlan);
		data = NULL;
	}

	if (data == NULL) {
#ifdef SP
		new_tun = 1;
#endif /* SP */
		data = ofp_get_ifnet(port, greid, 1);
		data->if_type = OFP_IFT_GRE;
	} else {
		ofp_set_route_params(OFP_ROUTE_DEL, data->vrf, greid, port,
				     data->ip_p2p, data->ip_addr_info[0].masklen, 0, 0);
#ifdef SP
		if (data->sp_itf_mgmt) {	/*old interface*/
			snprintf(cmd, sizeof(cmd),
				 "ip addr del dev %s %s peer %s",
				 ofp_port_vlan_to_ifnet_name(port, greid),
				 ofp_print_ip_addr(data->ip_addr_info[0].ip_addr),
				 ofp_print_ip_addr(data->ip_p2p));
			exec_sys_call_depending_on_vrf(cmd, data->vrf);
		}
#endif /* SP */
	}

	data->vrf = vrf;
	data->ip_local = tun_loc;
	data->ip_remote = tun_rem;
	data->ip_p2p = p2p;
	data->ip_addr_info[0].ip_addr = addr;
	data->ip_addr_info[0].masklen = mlen;
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_greip);
#ifdef SP
	data->sp_itf_mgmt = sp_itf_mgmt;
#endif /*SP*/

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, greid, port,
			     data->ip_p2p, data->ip_addr_info[0].masklen, 0,
			     OFP_RTF_HOST);

#ifdef SP
	if (vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	if (data->sp_itf_mgmt) {
		snprintf(cmd, sizeof(cmd),
			 "ip tunnel %s %s mode gre local %s remote %s ttl 255",
			 (new_tun ? "add" : "change"),
			 ofp_port_vlan_to_ifnet_name(port, greid),
			 ofp_print_ip_addr(tun_loc),
			 ofp_print_ip_addr(tun_rem));
		exec_sys_call_depending_on_vrf(cmd, vrf);

		snprintf(cmd, sizeof(cmd),
			 "ip link set dev %s up",
			 ofp_port_vlan_to_ifnet_name(port, greid));
		exec_sys_call_depending_on_vrf(cmd, vrf);

		snprintf(cmd, sizeof(cmd),
			 "ip addr add dev %s %s peer %s",
			 ofp_port_vlan_to_ifnet_name(port, greid),
			 ofp_print_ip_addr(addr), ofp_print_ip_addr(p2p));
		exec_sys_call_depending_on_vrf(cmd, vrf);
	} else
#endif /* SP */
	{
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, greid, port,
				     addr, 32, 0, OFP_RTF_LOCAL);
	}
	return NULL;
}

void ofp_join_device_to_multicast_group(struct ofp_ifnet *dev_root,
				       struct ofp_ifnet *dev_vxlan,
				       uint32_t group)
{
	/* Join root device to multicast group. */
	struct ofp_in_addr gina;
	gina.s_addr = group;

	OFP_DBG("Device joining multicast group: "
		"interface=%d/%d vni=%d group=%x",
		dev_root->port, dev_root->vlan,
		dev_vxlan->vlan, group);
	/* Use data->ii_inet.ii_allhosts for Vxlan purposes. */
	ofp_in_joingroup(dev_root, &gina, NULL, &(dev_vxlan->ii_inet.ii_allhosts));
	fflush(NULL);
}

void ofp_leave_multicast_group(struct ofp_ifnet *dev_vxlan)
{
	if (dev_vxlan->ii_inet.ii_allhosts) {
		/* Use data->ii_inet.ii_allhosts for Vxlan. */
		ofp_in_leavegroup(dev_vxlan->ii_inet.ii_allhosts, NULL);
	}
	dev_vxlan->ii_inet.ii_allhosts = NULL;
}

const char *ofp_ifport_vxlan_ipv4_up(int vni, uint32_t group,
				     int physport, int physvlan,
				     uint32_t addr, int mlen)
{
#ifdef SP
	char cmd[200];
	int ret = 0, new = 0;
#endif /* SP */
	struct ofp_ifnet *data, *dev_root;
	uint32_t mask;

#ifdef SP
	(void)ret;
	(void)new;
#endif /*SP*/

	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - mlen));
	dev_root = ofp_get_ifnet(physport, physvlan, 0);
	if (dev_root == NULL)
		return "No physical device configured.";

	data = ofp_get_ifnet(OFP_IFPORT_VXLAN, vni, 0);

	/* To be on the safe side it is better to put down the interface and
	   reconfigure.*/
	if (data) {
		ofp_ifport_ifnet_down(data->port, data->vlan);
		data = NULL;
	}

	data = ofp_get_ifnet(OFP_IFPORT_VXLAN, vni, 1);
	data->if_type = OFP_IFT_VXLAN;

	/* different MAC address per VNI*/
	if (odp_random_data((uint8_t *)data->if_mac,
			    sizeof(data->if_mac), 0) < 0)
		return "Failed to initialize default MAC address.";
	data->if_mac[0] = 0x02;
	data->if_mac[1] = data->port;

	data->vrf = dev_root->vrf;
	data->ip_p2p = group;
	data->if_mtu = dev_root->if_mtu - sizeof(struct ofp_vxlan_udp_ip);
	data->physport = physport;
	data->physvlan = physvlan;
	data->pkt_pool = V_ifnet_port[OFP_IFPORT_VXLAN].pkt_pool;

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vni, OFP_IFPORT_VXLAN,
			     addr, 32, 0, OFP_RTF_LOCAL);
	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, vni, OFP_IFPORT_VXLAN,
			     addr & mask, mlen, 0, OFP_RTF_NET);
	ofp_ifnet_ip_find_update_fields(data, addr, mlen, addr | ~mask);

	/* Join root device to multicast group. */
	ofp_join_device_to_multicast_group(dev_root, data, group);

#ifdef SP
	if (data->vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	snprintf(cmd, sizeof(cmd),
		 "ip link add vxlan%d type vxlan id %d group %s dev %s dstport %d",
		 vni, vni, ofp_print_ip_addr(group),
		 ofp_port_vlan_to_ifnet_name(physport, physvlan), VXLAN_PORT);
	ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip link set dev vxlan%d address %s up",
		 vni, ofp_print_mac(data->if_mac));
	ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);

	snprintf(cmd, sizeof(cmd),
		 "ip addr add dev vxlan%d %s/%d", vni,
		 ofp_print_ip_addr(addr), mlen);
	ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */

	return NULL;
}

const char *ofp_ifport_local_ipv4_up(uint16_t id, uint16_t vrf,
				     uint32_t addr, int masklen,
				     odp_bool_t sp_itf_mgmt)
{
#ifdef SP
	char cmd[200];
	int linux_index = -1;
	struct ofp_linux_interface_param *ifparam = NULL;
#endif /* SP */
	struct ofp_ifnet *data;
	uint32_t mask;

	(void)sp_itf_mgmt;

	if (vrf >= global_param->num_vrf)
		return "VRF ID too big";

#ifdef SP	/* force only one loopback interface for 'lo' */
	if (sp_itf_mgmt) {
		linux_index = ofp_get_linuxindex("lo");
		if (linux_index == -1)
			return "Interface 'lo' not found.";

		ifparam = ofp_ifindex_lookup_tab_get(linux_index);
		if (ifparam == NULL)
			return "Invalid interface index.";

		if (!((ifparam->port == PORT_UNDEF) ||
		      ((ifparam->port == OFP_IFPORT_LOCAL) &&
		       (ifparam->vlan == id))))
			return "Interface 'lo' already configured.";

		if (ifparam->port == PORT_UNDEF)
			exec_sys_call_depending_on_vrf("ip addr flush  dev lo", vrf);
	}
#endif /* SP */

	mask = ~0;
	mask = odp_cpu_to_be_32(mask << (32 - masklen));

	data = ofp_get_ifnet(OFP_IFPORT_LOCAL, id, 0);
	if (data)
		ofp_ifport_ifnet_down(data->port, data->vlan);
	data = ofp_get_ifnet(OFP_IFPORT_LOCAL, id, 1);
	ofp_loopq_create(data);

#ifdef SP
	data->sp_itf_mgmt = sp_itf_mgmt;

	if (data->sp_itf_mgmt && vrf) {
		/* Create vrf if not exist using dummy call */
		exec_sys_call_depending_on_vrf("", vrf);
	}
#endif /* SP */
	data->vrf = vrf;
	data->if_type = OFP_IFT_LOOP;
	data->if_flags = OFP_IFF_LOOPBACK;

	ofp_set_route_params(OFP_ROUTE_ADD, data->vrf, id, OFP_IFPORT_LOCAL,
			     addr, masklen, 0, OFP_RTF_LOCAL | OFP_RTF_HOST);

#ifdef SP
	if (vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	if (data->sp_itf_mgmt) {
		data->linux_index = linux_index;
		ofp_ifindex_lookup_tab_update(data);

		exec_sys_call_depending_on_vrf("ip link set lo up", vrf);
		snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev lo",
			 ofp_print_ip_addr(addr), masklen);
		exec_sys_call_depending_on_vrf(cmd, vrf);
	} else
#endif /* SP */
	{
		ofp_set_route_params(OFP_ROUTE_ADD, data->vrf,
				     data->vlan, data->port,
				     addr, 32, 0, OFP_RTF_LOCAL);
		ofp_ifnet_ip_find_update_fields(data, addr, masklen,
						addr | ~mask);
	}

	return NULL;
}


#ifdef INET6
const char *ofp_ifport_net_ipv6_up(int port, uint16_t vlan,
				   uint8_t *addr, int masklen)
{
#ifdef SP
	char cmd[200];
	int ret = 0;
	char *iname = NULL;
#endif /* SP */
	uint8_t gw6[16];
	struct ofp_ifnet *data;

#ifdef SP
	(void)ret;
#endif /*SP*/
	memset(gw6, 0, 16);

	if (!OFP_IFPORT_IS_NET(port))
		return "Wrong port number";

	data = ofp_get_ifnet(port, vlan, 0);

	if (vlan != OFP_IFPORT_NET_SUBPORT_ITF) {
		if (data == NULL) {
			data = ofp_get_ifnet(port, vlan, 1);
			data->vrf = 0;
#ifdef SP
			iname = ofp_port_vlan_to_ifnet_name(port, OFP_IFPORT_NET_SUBPORT_ITF);
			snprintf(cmd, sizeof(cmd),
				 "ip link add name %s.%d link %s type vlan id %d",
				 iname, vlan, iname, vlan);
			ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
		} else {
			if (ofp_ip6_is_set(data->ip6_addr)) {
				ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan,
						      port, data->ip6_addr,
						      data->ip6_prefix, gw6, 0);
				ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, vlan,
						      port, data->ip6_addr,
						      128, gw6, 0);
			}
		}

		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port,
				      data->ip6_addr, data->ip6_prefix, gw6,
				      OFP_RTF_NET);
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port,
				      data->ip6_addr, 128, gw6,
				      OFP_RTF_LOCAL);
#ifdef SP
		if (data->vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd),
			 "ifconfig %s inet6 add %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, vlan),
			 ofp_print_ip6_addr(addr), masklen);
		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /*SP*/
	} else {
		if (ofp_ip6_is_set(data->ip6_addr)) {
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/,
					      OFP_IFPORT_NET_SUBPORT_ITF,
					      port, data->ip6_addr,
					      data->ip6_prefix, gw6, 0);
			ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/,
					      OFP_IFPORT_NET_SUBPORT_ITF,
					      port, data->ip6_addr, 128,
					      gw6, 0);
		}
		memcpy(data->ip6_addr, addr, 16);
		data->ip6_prefix = masklen;

		ofp_mac_to_link_local(data->if_mac, data->link_local);

		/* Add interface to the if_addr v6 queue */
		ofp_ifaddr6_elem_add(data);

		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/,
				      OFP_IFPORT_NET_SUBPORT_ITF, port,
				      data->ip6_addr, 128, gw6,
				      OFP_RTF_LOCAL);
		ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/,
				      OFP_IFPORT_NET_SUBPORT_ITF, port,
				      data->ip6_addr, data->ip6_prefix, gw6,
				      OFP_RTF_NET);
#ifdef SP
		if (data->vrf == 0)
			data->sp_status = OFP_SP_UP;
		else
			data->sp_status = OFP_SP_DOWN;

		snprintf(cmd, sizeof(cmd),
			 "ifconfig %s inet6 add %s/%d up",
			 ofp_port_vlan_to_ifnet_name(port, OFP_IFPORT_NET_SUBPORT_ITF),
			 ofp_print_ip6_addr(addr), masklen);

		ret = exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /* SP */
	}

	return NULL;
}
#endif /* INET6 */

#ifdef INET6
const char *ofp_ifport_local_ipv6_up(uint16_t id, uint8_t *addr, int masklen)
{
#ifdef SP
	char cmd[200];
#endif /* SP */
	uint8_t gw6[16];
	struct ofp_ifnet *data;

	memset(gw6, 0, 16);

	data = ofp_get_ifnet(OFP_IFPORT_LOCAL, id, 0);
	if (data == NULL)
		return "Create IPv4 loopback interface first";

	if (ofp_ip6_is_set(data->ip6_addr)) {
#ifdef SP
		if (data->sp_itf_mgmt) {
			snprintf(cmd, sizeof(cmd),
				 "ip -f inet6 addr del %s/%d dev lo",
				 ofp_print_ip6_addr(data->ip6_addr),
				 data->ip6_prefix);
			exec_sys_call_depending_on_vrf(cmd, data->vrf);
		}
#endif
		ofp_set_route6_params(OFP_ROUTE6_DEL, data->vrf, id,
				      OFP_IFPORT_LOCAL, data->ip6_addr,
				      data->ip6_prefix, gw6, 0);
		ofp_set_route6_params(OFP_ROUTE6_DEL, data->vrf, id,
				      OFP_IFPORT_LOCAL, data->ip6_addr,
				      128, gw6, 0);
	}

	memcpy(data->ip6_addr, addr, 16);
	data->ip6_prefix = masklen;
	ofp_set_route6_params(OFP_ROUTE6_ADD, data->vrf, id, OFP_IFPORT_LOCAL,
			      data->ip6_addr, data->ip6_prefix, gw6, 0);
	ofp_set_route6_params(OFP_ROUTE6_ADD, data->vrf, id, OFP_IFPORT_LOCAL,
			      data->ip6_addr, 128, gw6,
			      OFP_RTF_LOCAL);
#ifdef SP
	if (data->vrf == 0)
		data->sp_status = OFP_SP_UP;
	else
		data->sp_status = OFP_SP_DOWN;

	if (data->sp_itf_mgmt) {
		snprintf(cmd, sizeof(cmd),
			 "ip -f inet6 addr add %s/%d dev lo",
			 ofp_print_ip6_addr(addr), masklen);
		exec_sys_call_depending_on_vrf(cmd, data->vrf);
	}
#endif /*SP*/

	return NULL;
}
#endif /* INET6 */

int ofp_local_interfaces_destroy(void)
{
	if (!shm_ifnet_port) {
		ofp_portconf_lookup_shared_memory();

		if (!shm_ifnet_port) {
			OFP_ERR("ofp_shared_memory_lookup failed");
			return -1;
		}
	}

	return ofp_destroy_subports(&V_ifnet_port[OFP_IFPORT_LOCAL]);
}

int ofp_gre_interfaces_destroy(void)
{
	if (!shm_ifnet_port) {
		ofp_portconf_lookup_shared_memory();

		if (!shm_ifnet_port) {
			OFP_ERR("ofp_shared_memory_lookup failed");
			return -1;
		}
	}

	return ofp_destroy_subports(&V_ifnet_port[OFP_IFPORT_GRE]);
}

int ofp_vxlan_interfaces_destroy(void)
{
	if (!shm_ifnet_port) {
		ofp_portconf_lookup_shared_memory();

		if (!shm_ifnet_port) {
			OFP_ERR("ofp_shared_memory_lookup failed");
			return -1;
		}
	}

	return ofp_destroy_subports(&V_ifnet_port[OFP_IFPORT_VXLAN]);
}

int ofp_net_interfaces_destroy(void)
{
	uint16_t i;
	int rc = 0;

	if (!shm_ifnet_port) {
		ofp_portconf_lookup_shared_memory();

		if (!shm_ifnet_port) {
			OFP_ERR("ofp_shared_memory_lookup failed");
			return -1;
		}
	}

	for (i = 0; OFP_IFPORT_IS_NET_U(i); i++) {
		if (ofp_ifnet_net_cleanup(&V_ifnet_port[i]))
			rc = -1;
	}

	return rc;
}

static int iter_iface_destroy(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	(void)iter_arg;

	ofp_ifport_ifnet_down(iface->port, iface->vlan);

	return 0;
}

int ofp_destroy_subports(struct ofp_ifnet *ifnet)
{
	if (!ifnet)
		return -1;

	if (!ifnet->vlan_structs)
		return 0;

	vlan_cleanup_inorder(ifnet->vlan_structs,
			     iter_iface_destroy, NULL);

	return 0;
}

static int ofp_ifnet_addr_cleanup(struct ofp_ifnet *ifnet)
{
#ifdef SP
	char cmd[200];
	uint16_t vrf;
#endif /* SP */

	if (!ifnet)
		return -1;

	/* Remove interface from the if_addr v4 queue */
	ofp_ifaddr_elem_del(ifnet);
#ifdef INET6
	/* Remove interface from the if_addr v6 queue */
	ofp_ifaddr6_elem_del(ifnet);
#endif

#ifdef SP
	vrf = ifnet->vrf;
#endif /*SP*/

	if (ifnet->ip_addr_info[0].ip_addr) {
		struct ofp_ifnet_ipaddr *ipaddr = &ifnet->ip_addr_info[0];

		uint32_t a = (ofp_if_type(ifnet) == OFP_IFT_GRE) ?
			ifnet->ip_p2p : ipaddr->ip_addr;
		int m = ipaddr->masklen;
#ifdef SP
		uint32_t dest = a;
#endif /* SP */

		a = odp_cpu_to_be_32(odp_be_to_cpu_32(a) & (0xFFFFFFFFULL << (32 - ipaddr->masklen)));
		if (ofp_if_type(ifnet) == OFP_IFT_LOOP) {
			ofp_set_route_params(OFP_ROUTE_DEL, ifnet->vrf,
					     ifnet->vlan, ifnet->port,
					     ipaddr->ip_addr, ipaddr->masklen,
					     0, 0);
			/*ofp_set_route_params(OFP_ROUTE_DEL, ifnet->vrf,
					       ifnet->vlan, ifnet->port,
					       dest, 32, 0, 0);*/
		} else if (ofp_if_type(ifnet) != OFP_IFT_GRE)
			ofp_set_route_params(OFP_ROUTE_DEL, ifnet->vrf,
					     ifnet->vlan, ifnet->port,
					     ipaddr->ip_addr, 32, 0, 0);
		ofp_set_route_params(OFP_ROUTE_DEL, ifnet->vrf,
				     ifnet->vlan, ifnet->port,
				     a, m, 0, 0);

		ofp_free_ifnet_ip_list(ifnet);
#ifdef SP
		if (ifnet->sp_itf_mgmt) {
			if (ifnet->port == OFP_IFPORT_LOCAL) {
				snprintf(cmd, sizeof(cmd),
					 "ip addr del %s/%d dev lo",
					 ofp_print_ip_addr(dest), m);
				exec_sys_call_depending_on_vrf(cmd, vrf);
			} else if (!OFP_IFPORT_IS_NET_U(ifnet->port)) {
				snprintf(cmd, sizeof(cmd),
					 "ifconfig %s 0.0.0.0",
					 ofp_port_vlan_to_ifnet_name(ifnet->port, ifnet->vlan));
				exec_sys_call_depending_on_vrf(cmd, vrf);
			}
		}
#endif /*SP*/
	}
#ifdef INET6
	if (ofp_ip6_is_set(ifnet->ip6_addr)) {
		uint8_t gw6[16];

		memset(gw6, 0, 16);
		ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/,
				      ifnet->vlan, ifnet->port,
				      ifnet->ip6_addr, ifnet->ip6_prefix,
				      gw6, 0);
		ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/,
				      ifnet->vlan, ifnet->port,
				      ifnet->ip6_addr, 128,
				      gw6, 0);
#ifdef SP
		if (ifnet->sp_itf_mgmt) {
			snprintf(cmd, sizeof(cmd),
				 "ifconfig %s inet6 del %s/%d",
				 ifnet->port == OFP_IFPORT_LOCAL ? "lo" :
				 ofp_port_vlan_to_ifnet_name(ifnet->port, ifnet->vlan),
				 ofp_print_ip6_addr(ifnet->ip6_addr),
				 ifnet->ip6_prefix);
			exec_sys_call_depending_on_vrf(cmd, vrf);
		}
#endif /* SP */

		memset(ifnet->ip6_addr, 0, 16);
	}
#endif /* INET6 */

	return 0;
}

static const char *ofp_ifport_net_down(int port, uint16_t subport)
{
	struct ofp_ifnet *ifnet_port = NULL;
	struct ofp_ifnet *ifnet;
#ifdef SP
	char cmd[200];

	(void)cmd;
#endif /* SP */

	if (!OFP_IFPORT_IS_NET(port))
		return "Wrong port number";

	ifnet_port = &V_ifnet_port[port];

	if (subport != OFP_IFPORT_NET_SUBPORT_ITF) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (!ifnet)
			return "Unknown interface";

		ofp_ifnet_addr_cleanup(ifnet);

		free(ifnet->ii_inet.ii_igmp);

#ifdef SP
		/* Already deleted
		snprintf(cmd, sizeof(cmd), "ip link del %s",
			 ofp_port_vlan_to_ifnet_name(port, subport));
		exec_sys_call_depending_on_vrf(cmd, ifnet->vrf);*/
#endif /*SP*/

		ofp_del_subport(ifnet_port, subport);
		return NULL;
	}

	ofp_ifnet_addr_cleanup(ifnet_port);

	return NULL;
}

static const char *ofp_ifport_local_down(int port, uint16_t subport)
{
	struct ofp_ifnet *ifnet_port = NULL;
	struct ofp_ifnet *ifnet;

	if (!OFP_IFPORT_IS_LOCAL(port))
		return "Wrong port number";

	ifnet_port = &V_ifnet_port[port];

	ifnet = ofp_get_subport(ifnet_port, subport);
	if (!ifnet)
		return "Unknown interface";

	ofp_ifnet_addr_cleanup(ifnet);

	if (ifnet->loopq_def != ODP_QUEUE_INVALID) {
		if (odp_queue_destroy(ifnet->loopq_def) < 0) {
			OFP_ERR("Failed to destroy loop queue for %s",
				ifnet->if_name);
		}
		ifnet->loopq_def = ODP_QUEUE_INVALID;
	}

	free(ifnet->ii_inet.ii_igmp);

#ifdef SP
	if (ifnet->sp_itf_mgmt)
		ofp_ifindex_lookup_tab_cleanup(ifnet);
#endif /*SP*/

	ofp_del_subport(ifnet_port, subport);

	return NULL;
}

static const char *ofp_ifport_vxlan_down(int port, uint16_t subport)
{
	struct ofp_ifnet *data;
	struct ofp_ifnet *ifnet_port = NULL;
#ifdef SP
	char cmd[200];
#endif /* SP */

	if (!OFP_IFPORT_IS_VXLAN(port))
		return "Wrong port number";

	ifnet_port = &V_ifnet_port[port];

	data = ofp_get_subport(ifnet_port, subport);
	if (!data)
		return "Unknown interface";

	ofp_ifnet_addr_cleanup(data);

	if (data->ii_inet.ii_allhosts) {
		/* Use data->ii_inet.ii_allhosts for Vxlan. */
		ofp_in_leavegroup(data->ii_inet.ii_allhosts, NULL);
	}

	free(data->ii_inet.ii_igmp);

#ifdef SP
	snprintf(cmd, sizeof(cmd), "ip link del %s",
		 ofp_port_vlan_to_ifnet_name(port, subport));

	exec_sys_call_depending_on_vrf(cmd, data->vrf);
#endif /*SP*/

	ofp_del_subport(ifnet_port, subport);

	return NULL;
}

static const char *ofp_ifport_gre_down(int port, uint16_t subport)
{
	struct ofp_ifnet *data;
	struct ofp_ifnet *ifnet_port = NULL;
#ifdef SP
	char cmd[200];
#endif /* SP */

	if (!OFP_IFPORT_IS_GRE(port))
		return "Wrong port number";

	ifnet_port = &V_ifnet_port[port];

	data = ofp_get_subport(ifnet_port, subport);
	if (!data)
		return "Unknown interface";

	ofp_ifnet_addr_cleanup(data);

	free(data->ii_inet.ii_igmp);

#ifdef SP
	if (data->sp_itf_mgmt) {
		snprintf(cmd, sizeof(cmd), "ip tunnel del %s",
			 ofp_port_vlan_to_ifnet_name(port, subport));
		exec_sys_call_depending_on_vrf(cmd, data->vrf);
	}
#endif /*SP*/

	ofp_del_subport(ifnet_port, subport);

	return NULL;
}

const char *ofp_ifport_ifnet_down(int port, uint16_t subport)
{
	if (port < 0 || port >= V_ifnet_num_ports) {
		OFP_DBG("port:%d is outside the valid interval", port);
		return "Wrong port number";
	}

	if (OFP_IFPORT_IS_NET(port))
		return ofp_ifport_net_down(port, subport);

	if (OFP_IFPORT_IS_LOCAL(port))
		return ofp_ifport_local_down(port, subport);

	if (OFP_IFPORT_IS_VXLAN(port))
		return ofp_ifport_vxlan_down(port, subport);

	if (OFP_IFPORT_IS_GRE(port))
		return ofp_ifport_gre_down(port, subport);

	return NULL;
}

static struct ofp_ifnet *ofp_get_subport(struct ofp_ifnet *ifnet_port,
					 uint16_t subport)
{
	struct ofp_ifnet key, *data;

	if (!ifnet_port || !ifnet_port->vlan_structs)
		return NULL;

	key.vlan = subport;
	if (ofp_vlan_get_by_key(ifnet_port->vlan_structs, &key, (void *)&data))
		return NULL;

	return data;
}

static struct ofp_ifnet *ofp_create_subport(struct ofp_ifnet *ifnet_port,
					    uint16_t subport)
{
	struct ofp_ifnet *ifnet = NULL;
	struct ofp_in_ifinfo *ii = NULL;

	ifnet = ofp_vlan_alloc();
	if (!ifnet)
		return NULL;

	memset(ifnet, 0, sizeof(*ifnet));

	ifnet->port = ifnet_port->port;
	ifnet->vlan = subport;
	memcpy(ifnet->if_mac, ifnet_port->if_mac, 6);
	ifnet->if_mtu = ifnet_port->if_mtu;
	ifnet->if_csum_offload_flags = ifnet_port->if_csum_offload_flags;

#ifdef INET6
	memcpy(ifnet->link_local, ifnet_port->link_local, 16);
#endif /* INET6 */
	/* Add interface to the if_addr v4 queue */
	ofp_ifaddr_elem_add(ifnet);
#ifdef INET6
	/* Add interface to the if_addr v6 queue */
	ofp_ifaddr6_elem_add(ifnet);
#endif

#ifdef SP
	ifnet->sp_itf_mgmt = ifnet_port->sp_itf_mgmt;
#endif /*SP*/

	/* Multicast related */
	OFP_TAILQ_INIT(&ifnet->if_multiaddrs);
	ifnet->if_flags |= OFP_IFF_MULTICAST;
	ifnet->if_afdata[OFP_AF_INET] = &ifnet->ii_inet;

	ii = &ifnet->ii_inet;
	ii->ii_igmp = ofp_igmp_domifattach(ifnet);

	IP_ADDR_LIST_INIT(ifnet);
	memset(ifnet->ip_addr_info, 0, sizeof(ifnet->ip_addr_info));

	vlan_ifnet_insert(ifnet_port->vlan_structs, ifnet);

	return ifnet;
}

static int ofp_del_subport(struct ofp_ifnet *ifnet_port, uint16_t subport)
{
	struct ofp_ifnet key;

	key.vlan = subport;
	return vlan_ifnet_delete(ifnet_port->vlan_structs, &key, free_key);
}

struct ofp_ifnet *ofp_get_ifnet(int port, uint16_t subport,
				odp_bool_t create_if_not_exist)
{
	struct ofp_ifnet *ifnet_port;
	struct ofp_ifnet *ifnet = NULL;

	if (port < 0 || port >= V_ifnet_num_ports) {
		OFP_DBG("port:%d is outside the valid interval", port);
		return NULL;
	}

	if (port == PORT_UNDEF) {
		OFP_DBG("port in undefined");
		return NULL;
	}

	ifnet_port = &V_ifnet_port[port];

	if (OFP_IFPORT_IS_NET(port)) {
		if (subport != OFP_IFPORT_NET_SUBPORT_ITF) {
			ifnet = ofp_get_subport(ifnet_port, subport);
			if (ifnet || !create_if_not_exist)
				return ifnet;

			return ofp_create_subport(ifnet_port, subport);
		}

		return ifnet_port;
	}

	if (OFP_IFPORT_IS_LOCAL(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (ifnet || !create_if_not_exist)
			return ifnet;

		return ofp_create_subport(ifnet_port, subport);
	}

	if (OFP_IFPORT_IS_VXLAN(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (ifnet || !create_if_not_exist)
			return ifnet;

		return ofp_create_subport(ifnet_port, subport);
	}

	if (OFP_IFPORT_IS_GRE(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (ifnet || !create_if_not_exist)
			return ifnet;

		return ofp_create_subport(ifnet_port, subport);
	}

	OFP_DBG("port:%d is unknown.", port);
	return NULL;
}

int ofp_delete_ifnet(int port, uint16_t subport)
{
	struct ofp_ifnet *ifnet_port;
	struct ofp_ifnet *ifnet = NULL;

	if (port < 0 || port >= V_ifnet_num_ports) {
		OFP_DBG("port:%d is outside the valid interval", port);
		return -1;
	}

	if (port == PORT_UNDEF) {
		OFP_DBG("port in undefined");
		return -1;
	}

	ifnet_port = &V_ifnet_port[port];

	if (OFP_IFPORT_IS_NET(port)) {
		if (subport == OFP_IFPORT_NET_SUBPORT_ITF)
			return 0;

		ifnet = ofp_get_subport(ifnet_port, subport);
		if (!ifnet)
			return 0;/* subport not found (deleted already)*/

		ofp_del_subport(ifnet_port, subport);

		return 0;
	}

	if (OFP_IFPORT_IS_LOCAL(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (!ifnet)
			return 0;/* subport not found (deleted already)*/

		ofp_del_subport(ifnet_port, subport);
		return 0;
	}

	if (OFP_IFPORT_IS_VXLAN(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (!ifnet)
			return 0;/* subport not found (deleted already)*/

		ofp_del_subport(ifnet_port, subport);
		return 0;
	}

	if (OFP_IFPORT_IS_GRE(port)) {
		ifnet = ofp_get_subport(ifnet_port, subport);
		if (!ifnet)
			return 0;/* subport not found (deleted already)*/

		ofp_del_subport(ifnet_port, subport);
		return 0;
	}

	return -1;
}

#ifdef SP
struct iter_str {
	int ix;
	struct ofp_ifnet *dev;
};

static int iter_vlan_1(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_str *data = iter_arg;

	if (iface->linux_index == data->ix) {
		data->dev = key;
		return 1;
	}

	return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_linux_ifindex(int ix)
{
	struct ofp_linux_interface_param *ifparam = NULL;
	int i;
	struct iter_str data;

	ifparam = ofp_ifindex_lookup_tab_get(ix);
	if (ifparam)
		return ofp_get_ifnet(ifparam->port, ifparam->vlan, 0);

	/* Iterate through other index values */
	data.ix = ix;
	data.dev = NULL;

	for (i = 0; i < V_ifnet_num_ports && data.dev == NULL; i++) {
		if (V_ifnet_port[i].linux_index == ix)
			return &(V_ifnet_port[i]);

		vlan_iterate_inorder(V_ifnet_port[i].vlan_structs,
				     iter_vlan_1, &data);
	}

	return data.dev;
}

void ofp_ifindex_lookup_tab_update(struct ofp_ifnet *ifnet)
{
	/* quick access table based on linux_index*/
	if (ifnet->linux_index < NUM_LINUX_INTERFACES) {
		V_ifnet_linux_itf[ifnet->linux_index].port =
			ifnet->port;
		V_ifnet_linux_itf[ifnet->linux_index].vlan =
			ifnet->vlan;
	}
}

void ofp_ifindex_lookup_tab_cleanup(struct ofp_ifnet *ifnet)
{
	/* quick access table based on linux_index*/
	if (ifnet->linux_index < NUM_LINUX_INTERFACES)
		V_ifnet_linux_itf[ifnet->linux_index].port = PORT_UNDEF;
}

struct ofp_linux_interface_param *ofp_ifindex_lookup_tab_get(int ix)
{
	if (ix >= NUM_LINUX_INTERFACES)
		return NULL;

	return &V_ifnet_linux_itf[ix];
}
#else
struct ofp_ifnet *ofp_get_ifnet_by_linux_ifindex(int ix)
{
	(void)ix;

	return NULL;
}
#endif /* SP */

struct ofp_ifnet *ofp_get_ifnet_match(uint32_t ip,
		uint16_t vrf,
		uint16_t vlan)
{
	uint16_t port;

	if (vlan == 0) {
		for (port = 0; port < OFP_FP_INTERFACE_MAX; port++) {
			struct ofp_ifnet *ifnet =
				&V_ifnet_port[port];

			if (ifnet->vrf == vrf)
				if (-1 != ofp_ifnet_ip_find(ifnet, ip))
					return ifnet;
		}
	} else {
		for (port = 0; port < OFP_FP_INTERFACE_MAX; port++) {
			uint16_t vlan_id = vlan_iterate_inorder(
				V_ifnet_port[port].vlan_structs,
				vlan_match_ip, &ip);

			if (vlan_id)
				return ofp_get_ifnet(port, vlan, 0);
		}
	}
	return NULL;
}

static int iter_interface(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct ofp_ifconf *ifc = iter_arg;
	int len = ifc->ifc_current_len;
	struct ofp_ifreq *ifr = (struct ofp_ifreq *)(((uint8_t *)ifc->ifc_buf) + len);

	if (len + (int)sizeof(struct ofp_ifreq) > ifc->ifc_len)
		return 1;

	ifc->ifc_current_len += sizeof(struct ofp_ifreq);

	((struct ofp_sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr =
		iface->ip_addr_info[0].ip_addr;
	ifr->ifr_addr.sa_family = OFP_AF_INET;

	if (ofp_if_type(iface) == OFP_IFT_GRE)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "gre%d", iface->vlan);
	else if (ofp_if_type(iface) == OFP_IFT_VXLAN)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "vxlan%d", iface->vlan);
	else if (iface->vlan)
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "fp%d.%d", iface->port, iface->vlan);
	else
		snprintf(ifr->ifr_name, OFP_IFNAMSIZ,
			 "fp%d", iface->port);

	return 0;
}

void ofp_get_interfaces(struct ofp_ifconf *ifc)
{
	int i;

	ifc->ifc_current_len = 0;

	/* fp interfaces */
	for (i = 0; i < OFP_FP_INTERFACE_MAX; i++) {
		iter_interface(&V_ifnet_port[i], ifc);
		vlan_iterate_inorder(V_ifnet_port[i].vlan_structs,
				     iter_interface, ifc);
	}

	/* gre interfaces */
	if (avl_get_first(V_ifnet_port[OFP_IFPORT_GRE].vlan_structs))
		vlan_iterate_inorder(
			V_ifnet_port[OFP_IFPORT_GRE].vlan_structs,
			iter_interface, ifc);

	/* vxlan interfaces */
	if (avl_get_first(V_ifnet_port[OFP_IFPORT_VXLAN].vlan_structs))
		vlan_iterate_inorder(
			V_ifnet_port[OFP_IFPORT_VXLAN].vlan_structs,
			iter_interface, ifc);

	ifc->ifc_len = ifc->ifc_current_len;
}

struct iter_ip {
	uint32_t addr;
	uint16_t vrf;
};

static int vlan_match_ip_vrf(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_ip *iterdata = (struct iter_ip *)iter_arg;

	if (iface->vrf == iterdata->vrf &&
	    (ofp_ifnet_ip_find(iface, iterdata->addr) != -1))
		return iface->vlan + 1;	/* workaround for vlan 0*/
	else
		return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_ip(uint32_t ip, uint16_t vrf)
{
	uint16_t port;
	struct ofp_ifnet *ifnet;
	uint16_t vlan;
	int res;
	struct iter_ip iterdata;

	for (port = 0; port < OFP_FP_INTERFACE_MAX; ++port) {
		ifnet = &V_ifnet_port[port];
		if (ifnet->vrf == vrf && (ofp_ifnet_ip_find(ifnet, ip) != -1))
			return ifnet;
	}

	iterdata.addr = ip;
	iterdata.vrf = vrf;

	for (port = 0; port < OFP_FP_INTERFACE_MAX; ++port) {
		res = vlan_iterate_inorder(V_ifnet_port[port].vlan_structs,
					   vlan_match_ip_vrf, &iterdata);
		if (res) {
			vlan = res - 1; /* workaround for vlan 0*/
			return ofp_get_ifnet(port, vlan, 0);
		}
	}

	return NULL;
}

struct iter_tun {
	uint32_t tun_loc;
	uint32_t tun_rem;
	uint16_t vrf;
};

static int vlan_match_tun(void *key, void *iter_arg)
{
	struct ofp_ifnet *iface = key;
	struct iter_tun *tundata = iter_arg;

	if (iface->ip_local == tundata->tun_loc &&
	    iface->ip_remote == tundata->tun_rem &&
	    iface->vrf == tundata->vrf)
		return iface->vlan;
	else
		return 0;
}

struct ofp_ifnet *ofp_get_ifnet_by_tunnel(uint32_t tun_loc,
					  uint32_t tun_rem, uint16_t vrf)
{
	uint16_t port = OFP_IFPORT_GRE;
	uint16_t greid;
	struct iter_tun tundata;

	tundata.tun_loc = tun_loc;
	tundata.tun_rem = tun_rem;
	tundata.vrf = vrf;

	greid = vlan_iterate_inorder(
		V_ifnet_port[port].vlan_structs,
		vlan_match_tun, &tundata);

	if (greid)
		return ofp_get_ifnet(port, greid, 0);

	return NULL;
}

struct ofp_in_ifaddrhead *ofp_get_ifaddrhead(void)
{
	return &V_ifnet_ifaddrhead;
}

void ofp_ifaddr_elem_add(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ia, ofp_get_ifaddrhead(), ia_link) {
		if (ia == ifnet)
			break;
	}

	if (!ia)
		OFP_TAILQ_INSERT_TAIL(ofp_get_ifaddrhead(), ifnet, ia_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
}

void ofp_ifaddr_elem_del(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ia, ofp_get_ifaddrhead(), ia_link) {
		if (ia == ifnet)
			break;
	}

	if (ia)
		OFP_TAILQ_REMOVE(ofp_get_ifaddrhead(), ifnet, ia_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
}

struct ofp_ifnet *ofp_ifaddr_elem_get(int vrf, uint8_t *addr)
{
	struct ofp_ifnet *ifa;

	OFP_IFNET_LOCK_WRITE(ifaddr_list);

	OFP_TAILQ_FOREACH(ifa, ofp_get_ifaddrhead(), ia_link) {
		if (ifa->ip_addr_info[0].ip_addr == *(uint32_t *)addr &&
		    ifa->vrf == vrf)
			break;
	}

	OFP_IFNET_UNLOCK_WRITE(ifaddr_list);
	return ifa;
}

/* The dev->ip_addr_info array holds IP entries.
	When an element is inserted it is inserted in the first entry != 0
	When an element is deleted the last element != 0 replaces the removed element.
 */
static inline int get_first_free_ifnet_pos(struct ofp_ifnet *dev)
{
	int free_idx = 0;
	while(free_idx < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[free_idx].ip_addr)
	{
		free_idx++;
	}
	return free_idx;
}

inline int ofp_ifnet_ip_add(struct ofp_ifnet *dev, uint32_t addr)
{
	int i;
	int free_idx;

	IP_ADDR_LIST_WLOCK(dev);
	i = ofp_ifnet_ip_find(dev, addr);
	if (i != -1) {	/* already set */
		IP_ADDR_LIST_WUNLOCK(dev);
		return 0;
	}

	free_idx = get_first_free_ifnet_pos(dev);
	if (odp_likely(free_idx < OFP_NUM_IFNET_IP_ADDRS))
		dev->ip_addr_info[free_idx].ip_addr = addr;
	else {
		IP_ADDR_LIST_WUNLOCK(dev);
		return -1;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return 0;
}

inline void ofp_ifnet_ip_remove(struct ofp_ifnet *dev, uint32_t addr)
{
	int i;
	int free_idx;

	IP_ADDR_LIST_WLOCK(dev);
	i = ofp_ifnet_ip_find(dev, addr);
	if (-1 != i) {
		free_idx = get_first_free_ifnet_pos(dev);
		if (OFP_NUM_IFNET_IP_ADDRS != free_idx) {
			free_idx--;
			if (free_idx != i) {
				dev->ip_addr_info[i].ip_addr = dev->ip_addr_info[free_idx].ip_addr;
				dev->ip_addr_info[i].masklen = dev->ip_addr_info[free_idx].masklen;
				dev->ip_addr_info[i].bcast_addr = dev->ip_addr_info[free_idx].bcast_addr;
			}
			dev->ip_addr_info[free_idx].ip_addr = 0;
			dev->ip_addr_info[free_idx].masklen = 0;
			dev->ip_addr_info[free_idx].bcast_addr = 0;
		}
	}
	IP_ADDR_LIST_WUNLOCK(dev);
}

inline int ofp_ifnet_ip_find(struct ofp_ifnet *dev, uint32_t addr)
{
	for (int i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		if (addr == dev->ip_addr_info[i].ip_addr)
			return i;
	}
	return -1;
}
/*
 * The address is already added in the list. Move it in the first element of the list
 * and update its fields.
 */
inline int ofp_set_first_ifnet_addr(struct ofp_ifnet *dev, uint32_t addr, uint32_t bcast_addr, int masklen)
{
	int idx;

	IP_ADDR_LIST_WLOCK(dev);
	idx = ofp_ifnet_ip_find(dev, addr);
	if (-1 == idx) {
		IP_ADDR_LIST_WUNLOCK(dev);
		return idx;
	}
	else if (0 == idx) {
		dev->ip_addr_info[0].bcast_addr = bcast_addr;
		dev->ip_addr_info[0].masklen = masklen;
	}
	else {
		dev->ip_addr_info[idx].ip_addr = dev->ip_addr_info[0].ip_addr;
		dev->ip_addr_info[idx].bcast_addr = dev->ip_addr_info[0].bcast_addr;
		dev->ip_addr_info[idx].masklen = dev->ip_addr_info[0].masklen;

		dev->ip_addr_info[0].ip_addr = addr;
		dev->ip_addr_info[0].bcast_addr = bcast_addr;
		dev->ip_addr_info[0].masklen = masklen;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return 0;
}

inline void ofp_ifnet_print_ip_addrs(struct ofp_ifnet *dev)
{
	int i;

	IP_ADDR_LIST_RLOCK(dev);
	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		OFP_INFO("       inet addr:%s    Bcast:%s        Mask:%s\r\n",
				ofp_print_ip_addr(dev->ip_addr_info[i].ip_addr),
				ofp_print_ip_addr(dev->ip_addr_info[i].bcast_addr),
				ofp_print_ip_addr(mask));
	}
	IP_ADDR_LIST_RUNLOCK(dev);
}

inline int ofp_ifnet_ip_find_update_fields(struct ofp_ifnet *dev, uint32_t addr, int masklen, uint32_t bcast_addr)
{
	int i;
	IP_ADDR_LIST_WLOCK(dev);
	i = ofp_ifnet_ip_find(dev, addr);
	if (-1 != i) {
		dev->ip_addr_info[i].masklen = masklen;
		dev->ip_addr_info[i].bcast_addr = bcast_addr;
		IP_ADDR_LIST_WUNLOCK(dev);
		return 0;
	}
	IP_ADDR_LIST_WUNLOCK(dev);
	return -1;
}

inline void ofp_free_ifnet_ip_list(struct ofp_ifnet *dev)
{
	int i;
	uint32_t mask;
	struct ofp_ifnet_ipaddr *ip_addr_info;
	int size;

	IP_ADDR_LIST_RLOCK(dev);
	size = get_first_free_ifnet_pos(dev);

	ip_addr_info = malloc(size*sizeof(struct ofp_ifnet_ipaddr));
	if (NULL == ip_addr_info) {
		OFP_INFO("ofp_free_ifnet_ip_list failed");
		return;
	}
	memset(ip_addr_info, 0, size*sizeof(struct ofp_ifnet_ipaddr));

	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		ip_addr_info[i].ip_addr = dev->ip_addr_info[i].ip_addr;
		ip_addr_info[i].masklen = dev->ip_addr_info[i].masklen;
	}
	IP_ADDR_LIST_RUNLOCK(dev);

	for(i=0; i < size && ip_addr_info[i].ip_addr; i++)
	{
		mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf, dev->vlan, dev->port,
				ip_addr_info[i].ip_addr & mask, ip_addr_info[i].masklen, 0, 0);
		ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf, dev->vlan, dev->port,
				ip_addr_info[i].ip_addr, 32, 0, 0);

	}
	free(ip_addr_info);

	IP_ADDR_LIST_RLOCK(dev);
	size = get_first_free_ifnet_pos(dev);
	IP_ADDR_LIST_RUNLOCK(dev);

	if (0 != size)
		OFP_INFO("IP address %s not removed", ofp_print_ip_addr(dev->ip_addr_info[0].ip_addr));

}

inline void ofp_ifnet_print_ip_info(ofp_print_t *pr, struct ofp_ifnet *dev)
{
	char buf[16];
	int i;

	if (dev->vlan)
		snprintf(buf, sizeof(buf), ".%d", dev->vlan);

	ofp_print(pr, "%s%d%s (%s):\r\n",
		  OFP_IFNAME_PREFIX,
		  dev->port,
		  (dev->vlan) ? buf : "",
		  dev->if_name);
	IP_ADDR_LIST_RLOCK(dev);
	for(i=0; i < OFP_NUM_IFNET_IP_ADDRS && dev->ip_addr_info[i].ip_addr; i++)
	{
		uint32_t mask = ~0;
		mask = odp_cpu_to_be_32(mask << (32 - dev->ip_addr_info[i].masklen));
		ofp_print(pr,
			  "       inet addr:%s    Bcast:%s        Mask:%s\r\n",
			  ofp_print_ip_addr(dev->ip_addr_info[i].ip_addr),
			  ofp_print_ip_addr(dev->ip_addr_info[i].bcast_addr),
			  ofp_print_ip_addr(mask));
	}
	IP_ADDR_LIST_RUNLOCK(dev);
	ofp_print(pr, "\r\n");
}

#ifdef INET6
struct ofp_in_ifaddrhead *ofp_get_ifaddr6head(void)
{
	return &V_ifnet_ifaddr6head;
}

void ofp_ifaddr6_elem_add(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia6;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ia6, ofp_get_ifaddr6head(), ia6_link) {
		if (ia6 == ifnet)
			break;
	}

	if (!ia6)
		OFP_TAILQ_INSERT_TAIL(ofp_get_ifaddr6head(), ifnet, ia6_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
}

void ofp_ifaddr6_elem_del(struct ofp_ifnet *ifnet)
{
	struct ofp_ifnet *ia6;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ia6, ofp_get_ifaddr6head(), ia6_link) {
		if (ia6 == ifnet)
			break;
	}

	if (ia6)
		OFP_TAILQ_REMOVE(ofp_get_ifaddr6head(), ifnet, ia6_link);

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
}

struct ofp_ifnet *ofp_ifaddr6_elem_get(uint8_t *addr6)
{
	struct ofp_ifnet *ifa6 = NULL;

	OFP_IFNET_LOCK_WRITE(ifaddr6_list);

	OFP_TAILQ_FOREACH(ifa6, ofp_get_ifaddr6head(), ia6_link) {
		if (!memcmp(ifa6->ip6_addr, addr6, 16))
			break;
	}

	OFP_IFNET_UNLOCK_WRITE(ifaddr6_list);
	return ifa6;
}
#endif /* INET6 */
