/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_SELECTORS_H__
#define __OFP_IPSEC_SELECTORS_H__

#include "odp.h"
#include "ofp_ipsec_common.h"

#define OFP_IPSEC_ADDR_RANGE_LIST_SIZE 3
#define OFP_IPSEC_PORT_RANGE_LIST_SIZE 3
#define OFP_IPSEC_ICMP_RANGE_LIST_SIZE 3

enum ofp_ipsec_selector_value_type {
	OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE = 0,
	OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE,
	OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY
};

struct ofp_ipsec_addr_range {
	struct ofp_ipsec_addr addr_start;
	struct ofp_ipsec_addr addr_end;
};

struct ofp_ipsec_selector_addr {
	uint8_t list_size;
	struct ofp_ipsec_addr_range list[OFP_IPSEC_ADDR_RANGE_LIST_SIZE];
};
#define ofp_trivial_range_addr list[0].addr_start

struct ofp_ipsec_selector_next_layer_protocol {
	enum ofp_ipsec_selector_value_type value_type;
	uint8_t	protocol;
};

struct ofp_ipsec_port_range {
	uint16_t port_start;
	uint16_t port_end;
};

struct ofp_ipsec_selector_port {
	enum ofp_ipsec_selector_value_type value_type;

	uint8_t list_size;
	struct ofp_ipsec_port_range list[OFP_IPSEC_PORT_RANGE_LIST_SIZE];
};
#define ofp_trivial_range_port list[0].port_start

struct ofp_ipsec_selector_mh {
	enum ofp_ipsec_selector_value_type value_type;
	uint8_t mh_type;
};

struct ofp_ipsec_selector_icmp_type {
	enum ofp_ipsec_selector_value_type value_type;
	uint8_t icmp_type;
};

struct ofp_ipsec_icmp_code_range {
	uint8_t code_start;
	uint8_t code_end;
};

struct ofp_ipsec_selector_icmp_code {
	enum ofp_ipsec_selector_value_type value_type;
	uint8_t list_size;
	struct ofp_ipsec_icmp_code_range list[OFP_IPSEC_ICMP_RANGE_LIST_SIZE];
};
#define ofp_trivial_range_icmp_code list[0].code_start

enum ofp_ipsec_selector_protocol_dependent_type {
	OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE = 0,
	OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS,
	OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH,
	OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP
};

struct ofp_ipsec_selectors {
	struct ofp_ipsec_selector_addr src_addr_ranges;
	struct ofp_ipsec_selector_addr dest_addr_ranges;

	struct ofp_ipsec_selector_next_layer_protocol protocol;
	enum ofp_ipsec_selector_protocol_dependent_type proto_dep_type;
	union {
		struct {
			struct ofp_ipsec_selector_port src_port_ranges;
			struct ofp_ipsec_selector_port dest_port_ranges;
		} ports;

		struct ofp_ipsec_selector_mh mh;

		struct {
			struct ofp_ipsec_selector_icmp_type icmp_type;
			struct ofp_ipsec_selector_icmp_code icmp_code_ranges;
		} icmp;
	} _protocol_dependent;
};
#define ofp_src_port_ranges  _protocol_dependent.ports.src_port_ranges
#define ofp_dest_port_ranges  _protocol_dependent.ports.dest_port_ranges

#define ofp_mh _protocol_dependent.mh

#define ofp_icmp_type _protocol_dependent.icmp.icmp_type
#define ofp_icmp_code_ranges _protocol_dependent.icmp.icmp_code_ranges

void ofp_ipsec_selectors_init(struct ofp_ipsec_selectors *);

odp_bool_t ofp_ipsec_selectors_equal(struct ofp_ipsec_selectors *,
	struct ofp_ipsec_selectors *);
odp_bool_t ofp_ipsec_selectors_match_sp_pkt(struct ofp_ipsec_selectors *,
	struct ofp_ipsec_selectors *);
odp_bool_t ofp_ipsec_selectors_match_sa_pkt(struct ofp_ipsec_selectors *,
	struct ofp_ipsec_selectors *);

int ofp_ipsec_selectors_from_pkt(odp_packet_t,
	struct ofp_ipsec_selectors *);

#endif /* __OFP_IPSEC_SELECTORS_H__ */
