/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_PORTCONF_H__
#define __OFP_PORTCONF_H__

#include <odp_api.h>
#include "ofp_print.h"
#include "ofp_config.h"
#include "ofp_ifnet.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * OFP interface ports
 *
 * The organization of OFP interfaces is based on the concept of interface port.
 * A port represents either a network interface (physical or otherwise) or a
 * pseudo-port used to organize pseudo-interfaces e.g. gre, local, vxlan, etc.
 *
 * Current array of ports:
 * [0 - OFP_FP_INTERFACE_MAX - 1]: network interfaces
 * OFP_IFPORT_LOCAL              : local pseudo-interfaces
 * OFP_IFPORT_VXLAN              : vxlan pseudo-interfaces
 * OFP_IFPORT_GRE                : gre pseudo-interfaces
 *
 * Each port may have a number of sub-ports. The tuple (port, sub-port) is
 * uniquely identifying an OFP interface.
 *
 * The meaning of 'sub-port' depends on the type of port:
 * OFP_IFPORT_NET_XXX:
 *  - sub-port OFP_IFPORT_NET_SUBPORT_ITF represents the network interface
 *  - sub-port != OFP_IFPORT_NET_SUBPORT_ITF represents vlan
 * OFP_IFPORT_LOCAL:
 *  -sub-ports represents local interface ID
 * OFP_IFPORT_VXLAN:
 *  -sub-ports represents VXLAN network identifier (VNI)
 * OFP_IFPORT_GRE:
 *  -sub-ports represents GRE ID
 **/

enum {
	OFP_IFPORT_NET_FIRST = 0,
	OFP_IFPORT_NET_LAST = OFP_FP_INTERFACE_MAX - 1,
	OFP_IFPORT_LOCAL,
	OFP_IFPORT_VXLAN,
	OFP_IFPORT_GRE,
	OFP_IFPORT_NUM
};

#define OFP_IFPORT_IS_NET_U(_port) \
	(_port <= OFP_IFPORT_NET_LAST)

#define OFP_IFPORT_IS_NET(_port) \
	(_port >= OFP_IFPORT_NET_FIRST && OFP_IFPORT_IS_NET_U(_port))

#define OFP_IFPORT_IS_LOCAL(_port) \
	(_port == OFP_IFPORT_LOCAL)

#define OFP_IFPORT_IS_VXLAN(_port) \
	(_port == OFP_IFPORT_VXLAN)

#define OFP_IFPORT_IS_GRE(_port) \
	(_port == OFP_IFPORT_GRE)

/* Sub-port of the network (physical or otherwise) interface */
#define OFP_IFPORT_NET_SUBPORT_ITF 4096

/**
 * Create an OFP network interface port (ifport)
 *
 * Open an ODP interface using its name and configuration parameters.
 * The coresponding OFP interface is created and is uniquely identified
 * by the tuple (port, sub-port). Sub-port has always the value
 * OFP_IFPORT_NET_SUBPORT_ITF.
 *
 * This function can be used anytime to open ODP interfaces that were not opened
 * during ofp_initialize(). One can specify no interface in ofp_initialize()
 * and open one by one using this functionality.
 *
 * @param if_name Interface name to open
 * @param pktio_param Specify packet access mode for this
 *        interface
 * @param pktin_param Specify packet input queue parameters for
 *        this interface
 * @param pktout_param Specify packet output queue parameters for
 *        this interface
 * @param port Get the port value of the created interface.
 * @param subport Get the sub-port value of the created interface.
 *        The value is always OFP_IFPORT_NET_SUBPORT_ITF.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_initialize() can init interfaces.
 */
int ofp_ifport_net_create(char *if_name, odp_pktio_param_t *pktio_param,
			  odp_pktin_queue_param_t *pktin_param,
			  odp_pktout_queue_param_t *pktout_param,
			  int *port, uint16_t *subport);

/**
 * Get OFP interface associated with the network port
 *
 * Network port is searched by port ID. The function is equivalent with
 * calling ofp_ifport_ifnet_get(port, OFP_IFPORT_NET_SUBPORT_ITF).
 *
 * @param port Specify the network port
 *
 * @retval OFP interface on success
 * @retval OFP_IFNET_INVALID on failure
 */
ofp_ifnet_t ofp_ifport_net_ifnet_get_by_port(int port);

/**
 * Get OFP interface associated with the network port
 *
 * Network port is searched by ODP name.
 *
 * @param if_name Specify the interface ODP name
 *
 * @retval OFP interface on success
 * @retval OFP_IFNET_INVALID on failure
 */
ofp_ifnet_t ofp_ifport_net_ifnet_get_by_name(char *if_name);

/**
 * Get ODP pktio associated with the network port
 *
 * The function is equivalent with getting network port interface and
 * and retrieving ODP pktio.
 *
 * @param port Specify the network port
 *
 * @retval ODP pktio on success
 * @retval ODP_PKTIO_INVALID on failure
 */
odp_pktio_t ofp_ifport_net_pktio_get(int port);

/**
 * Get slow path ODP queue associated with the network port
 *
 * The function is equivalent with getting network port interface and
 * and retrieving the slow path queue.
 *
 * @retval slow path ODP queue on success
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t ofp_ifport_net_spq_get(int port);

/**
 * Get loopback ODP queue associated with the network port
 *
 * The function is equivalent with getting network port interface and
 * and retrieving the loopback queue.
 *
 * @retval loopback ODP queue on success
 * @retval ODP_QUEUE_INVALID on failure
 */
odp_queue_t ofp_ifport_net_loopq_get(int port);

/**
 * Get OFP interface associate with a tuple (port, sub-port)
 *
 * @param port Specify the network port
 * @param subport Specify the network sub-port
 *
 * @retval OFP interface on success
 * @retval OFP_IFNET_INVALID on failure
 */
ofp_ifnet_t ofp_ifport_ifnet_get(int port, uint16_t subport);

/**
 * Get total number of ports defined
 *
 * The value includes used and not used network ports and all
 * pseudo-ports
 *
 * @retval number of ports defined
 */
int ofp_ifport_count(void);

/* Interfaces: UP/DOWN */

/**
 * Configure IPv4 address on a network port interface
 *
 * The function applies to the interface associated to the port (when
 * subport_vlan is OFP_IFPORT_NET_SUBPORT_ITF) or to a VLAN.
 * VLAN interface is created if it does not exists.
 *
 * @param port Specify the network port
 * @param subport_vlan Specify the network sub-port.
 * @param vrf Virtual routing table
 * @param addr IPv4 address to set
 * @param masklen Mask length
 * @param sp_itf_mgmt Slow path interface management for the newly
 * created VLAN interface
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_net_ipv4_up(int port, uint16_t subport_vlan,
				   uint16_t vrf, uint32_t addr, int masklen,
				   odp_bool_t sp_itf_mgmt);

/**
 * Configure IPv6 address on network port interface
 *
 * The function applies to the interface associated to the port (when
 * subport_vlan is OFP_IFPORT_NET_SUBPORT_ITF) or to a VLAN.
 * VLAN interface is created if it does not exists.
 *
 * @param port Specify the network port
 * @param subport_vlan Specify the network sub-port.
 * @param vrf Virtual routing table
 * @param addr IPv6 address to set
 * @param masklen Mask length
 * @param sp_itf_mgmt Slow path interface management for the newly
 * created VLAN interface
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_net_ipv6_up(int port, uint16_t subport_vlan,
				   uint8_t *addr, int masklen,
				   odp_bool_t sp_itf_mgmt);

/**
 * Add an IPv4 address on network port interface
 *
 * The function applies to the interface associated to the port (when
 * subport_vlan is OFP_IFPORT_NET_SUBPORT_ITF) or to a VLAN.
 * VLAN interface must exist.
 *
 * @param port Specify the network port
 * @param subport_vlan Specify the network sub-port.
 * @param vrf Virtual routing table
 * @param addr IPv4 address to set
 * @param masklen Mask length
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_net_ipv4_addr_add(int port, uint16_t subport_vlan,
					 uint16_t vrf,
					 uint32_t addr, int masklen);

/**
 * Delete an IPv4 address from network port interface
 *
 * The function applies to the interface associated to the port (when
 * subport_vlan is OFP_IFPORT_NET_SUBPORT_ITF) or to a VLAN.
 *
 * @param port Specify the network port
 * @param subport_vlan Specify the network sub-port.
 * @param vrf Virtual routing table
 * @param addr IPv4 address to delete
 * @param masklen Mask length
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_net_ipv4_addr_del(int port, uint16_t subport_vlan,
					 int vrf, uint32_t addr, int masklen);

/**
 * Configure a IPv4 tunnel interface
 *
 * Interface is created if it does not exists.
 *
 * @param port Port associated with the tunnel type (e.g. OFP_IFPORT_GRE)
 * @param subport Sub-port associated with the interface.
 * @param vrf Virtual routing table
 * @param tun_loc Tunnel local address
 * @param tun_loc Tunnel remote address
 * @param p2p Peer address
 * @param addr IPv4 address to set
 * @param masklen Mask length
 * @param sp_itf_mgmt Slow path interface management
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_tun_ipv4_up(int port, uint16_t subport,
				   uint16_t vrf, uint32_t tun_loc,
				   uint32_t tun_rem, uint32_t p2p,
				   uint32_t addr, int masklen,
				   odp_bool_t sp_itf_mgmt);

/**
 * Configure an IPv4 VXLAN interface
 *
 * Interface is created if it does not exists.
 * Port is always OFP_IFPORT_VXLAN.
 *
 * @param subport_vni VXLAN Network Identifier
 * @param group Multicast IP Address group
 * @param endpoint_port Endpoint interface port
 * @param endpoint_subport Endpoint interface sub-port
 * @param addr IPv4 address to set
 * @param masklen Mask length
 * @param sp_itf_mgmt Slow path interface management
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_vxlan_ipv4_up(int subport_vni, uint32_t group,
				     int endpoint_port, int endpoint_subport,
				     uint32_t addr, int masklen,
				     odp_bool_t sp_itf_mgmt);

/**
 * Configure IPv4 address on a local port interface
 *
 * Local interface is created if it does not exists.
 * Port is always OFP_IFPORT_LOCAL.
 *
 * @param subport_id Local interface ID
 * @param vrf Virtual routing table
 * @param addr IPv4 address to set
 * @param masklen Mask length
 * @param sp_itf_mgmt Slow path interface management
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_local_ipv4_up(uint16_t subport_id, uint16_t vrf,
				     uint32_t addr, int masklen,
				     odp_bool_t sp_itf_mgmt);

/**
 * Configure IPv6 address on a local port interface
 *
 * Local interface must exist. It can be created with
 * ofp_ifport_local_ipv4_up() function.
 * Port is always OFP_IFPORT_LOCAL.
 *
 * @param subport_id Local interface ID
 * @param addr IPv6 address to set
 * @param masklen Mask length
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_local_ipv6_up(uint16_t subport_id,
				     uint8_t *addr, int masklen);

/**
 * Unconfigure an OFP interface
 *
 * Cleans up the interface resources (e.g routes and addresses).
 * If the interface coresponds to a subport (e.g. vlan), the interfaces
 * is deleted.
 *
 * @param port Specify the network port
 * @param subport Specify the network sub-port
 *
 * @retval NULL on success
 * @retval error message on error
 */
const char *ofp_ifport_ifnet_down(int port, uint16_t subport);

/**
 * Show interfaces configuration
 *
 * @param pr OFP printer to use
 */
void ofp_ifport_ifnet_show(ofp_print_t *pr);

/**
 *  Show IPv4 address configured on network ports
 *
 * @param pr OFP printer to use
 */
void ofp_ifport_net_ipv4_addr_show(ofp_print_t *pr);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_PORTCONF_H__ */

