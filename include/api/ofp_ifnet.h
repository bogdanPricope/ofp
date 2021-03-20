/* Copyright (c) 2015, ENEA Software AB
 * Copyright (c) 2015, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IFNET_H__
#define __OFP_IFNET_H__

#include <odp_api.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef void *ofp_ifnet_t;
#define OFP_IFNET_INVALID NULL

enum ofp_ifnet_ip_type {
	OFP_IFNET_IP_TYPE_IP_ADDR = 0,
	OFP_IFNET_IP_TYPE_P2P,
	OFP_IFNET_IP_TYPE_TUN_LOCAL,
	OFP_IFNET_IP_TYPE_TUN_REM
};

/**
 * Get interface port and subport
 *
 * @param ifnet Interface
 * @param port Interface port
 * @param subport Interface sub-port
 * @retval -1 on error
 * @retval 0 on success
 */
int ofp_ifnet_port_get(ofp_ifnet_t ifnet, int *port, uint16_t *subport);

/**
 * Get interface IPv4 address
 *
 * @param ifnet Interface
 * @param type Address type to get
 * @param addr IPv4 address
 * @retval -1 on error
 * @retval 0 on success
 */
int ofp_ifnet_ipv4_addr_get(ofp_ifnet_t ifnet, enum ofp_ifnet_ip_type type,
			    uint32_t *addr);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_IFNET_H__ */
