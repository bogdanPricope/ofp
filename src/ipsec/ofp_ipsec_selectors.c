/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_ipsec_selectors.h"
#include "api/ofp_socket.h"
#include "api/ofp_in.h"
#include "api/ofp_ethernet.h"
#include "api/ofp_if_vlan.h"
#include "api/ofp_ip.h"
#include "api/ofp_udp.h"
#include "api/ofp_tcp.h"
#include "api/ofp_icmp.h"
#include "ofpi_log.h"


void ofp_ipsec_selectors_init(struct ofp_ipsec_selectors *arg)
{
	if (!arg)
		return;

	memset(arg, 0, sizeof (struct ofp_ipsec_selectors));

	arg->protocol.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY;
	arg->proto_dep_type = OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE;
}

static odp_bool_t comp_address(struct ofp_ipsec_addr *addr1,
	struct ofp_ipsec_addr *addr2)
{
	if (!addr1 || !addr2)
		return 0;

	if (addr1->addr_type_ipv4 != addr2->addr_type_ipv4)
		return 0;

	if (addr1->addr_type_ipv4) {
		if (addr1->addr.addr4 != addr2->addr.addr4)
			return 0;
	} else
		if (memcmp(&addr1->addr.addr6, &addr2->addr.addr6, 16))
			return 0;

	return 1;
}

static odp_bool_t comp_address_range(struct ofp_ipsec_addr_range *rg1,
	struct ofp_ipsec_addr_range *rg2)
{
	if (!rg1 || !rg2)
		return 0;

	if (!comp_address(&rg1->addr_start, &rg2->addr_start))
		return 0;

	if (!comp_address(&rg1->addr_end, &rg2->addr_end))
		return 0;

	return 1;
}

static odp_bool_t comp_selector_address_ranges(struct ofp_ipsec_selector_addr *addr1,
	struct ofp_ipsec_selector_addr *addr2)
{
	int i;

	if (!addr1 || !addr2)
		return 0;

	if (addr1->list_size != addr2->list_size)
		return 0;

	for (i = 0; i < addr1->list_size; i++)
		if (!comp_address_range(&addr1->list[i], &addr2->list[i]))
			return 0;
	return 1;
}

static odp_bool_t comp_selector_mh(struct ofp_ipsec_selector_mh *mh1,
	struct ofp_ipsec_selector_mh *mh2)
{
	if (!mh1 || !mh2)
		return 0;

	if (mh1->value_type != mh2->value_type)
		return 0;
	if (mh1->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE &&
		mh1->mh_type != mh2->mh_type)
		return 0;
	return 1;
}


static odp_bool_t comp_selector_icmp_type(struct ofp_ipsec_selector_icmp_type *type1,
	struct ofp_ipsec_selector_icmp_type *type2)
{
	if (!type1 || !type2)
		return 0;

	if (type1->value_type != type2->value_type)
		return 0;

	if (type1->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE &&
		type1->icmp_type != type2->icmp_type)
		return 0;

	return 1;
}

static odp_bool_t comp_icmp_code_range(struct ofp_ipsec_icmp_code_range *rg1,
	struct ofp_ipsec_icmp_code_range *rg2)
{
	if (!rg1 || !rg2)
		return 0;

	if (rg1->code_start != rg2->code_start)
		return 0;

	if (rg1->code_end != rg2->code_end)
		return 0;

	return 1;
}

static odp_bool_t comp_selector_icmp_code(struct ofp_ipsec_selector_icmp_code *cd1,
	struct ofp_ipsec_selector_icmp_code *cd2)
{
	int i;

	if (!cd1 || !cd2)
		return 0;

	if (cd1->value_type != cd2->value_type)
		return 0;

	if (cd1->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE) {
		if (cd1->list_size != cd2->list_size)
			return 0;
		for (i = 0; i < cd1->list_size; i++)
			if (!comp_icmp_code_range(&cd1->list[i], &cd2->list[i]))
				return 0;
	}

	return 1;
}

static odp_bool_t comp_port_range(struct ofp_ipsec_port_range *rg1,
	struct ofp_ipsec_port_range *rg2)
{
	if (!rg1 || !rg2)
		return 0;

	if (rg1->port_start != rg2->port_start)
		return 0;

	if (rg1->port_end != rg2->port_end)
		return 0;

	return 1;
}

static odp_bool_t comp_selector_port_ranges(
	struct ofp_ipsec_selector_port *port1,
	struct ofp_ipsec_selector_port *port2)
{
	int i;

	if (!port1 || !port2)
		return 0;

	if (port1->value_type != port2->value_type)
		return 0;
	if (port1->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE) {
		if (port1->list_size != port2->list_size)
			return 0;
		for (i = 0; i < port1->list_size; i++)
			if (!comp_port_range(&port1->list[i], &port2->list[i]))
				return 0;
	}
	return 1;
}

odp_bool_t ofp_ipsec_selectors_equal(struct ofp_ipsec_selectors *sl1,
	struct ofp_ipsec_selectors * sl2)
{
	if (!sl1 || !sl2)
		return 0;

/* compare source adddress*/
	if (!comp_selector_address_ranges(&sl1->src_addr_ranges,
		&sl2->src_addr_ranges))
		return 0;

/* compare destination adddress*/
	if (!comp_selector_address_ranges(&sl1->dest_addr_ranges,
		&sl2->dest_addr_ranges))
		return 0;

/* compare protocol*/
	if (sl1->protocol.value_type != sl2->protocol.value_type)
		return 0;
	if (sl1->protocol.value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE) {
		if (sl1->protocol.protocol != sl2->protocol.protocol)
			return 0;
	}

	if (sl1->proto_dep_type != sl1->proto_dep_type)
		return 0;

	switch (sl1->proto_dep_type) {
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE:
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS:
		if (!comp_selector_port_ranges(&sl1->ofp_dest_port_ranges,
			&sl2->ofp_dest_port_ranges))
			return 0;
		if (!comp_selector_port_ranges(&sl1->ofp_src_port_ranges,
			&sl2->ofp_src_port_ranges))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP:
		if (!comp_selector_icmp_type(&sl1->ofp_icmp_type,
			&sl2->ofp_icmp_type))
			return 0;
		if (!comp_selector_icmp_code(&sl1->ofp_icmp_code_ranges,
			&sl2->ofp_icmp_code_ranges))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH:
		if (!comp_selector_mh(&sl1->ofp_mh, &sl2->ofp_mh))
			return 0;
		break;
	}
	return 1;
}

static odp_bool_t match_address_range(struct ofp_ipsec_addr_range *rg,
	struct ofp_ipsec_addr *addr)
{
	if (!rg || !addr)
		return 0;

	if (addr->addr_type_ipv4 != rg->addr_start.addr_type_ipv4)
		return 0;

	if (addr->addr_type_ipv4) {
		if (addr->addr.addr4 < rg->addr_start.addr.addr4)
			return 0;
		if (addr->addr.addr4 > rg->addr_end.addr.addr4)
			return 0;
	} else
		return 0; /* IPv6 not supported*/

	return 1;
}

static odp_bool_t match_selector_address_ranges(
	struct ofp_ipsec_selector_addr *addr_policy,
	struct ofp_ipsec_selector_addr *addr_pkt)
{
	int i;
	int match = 0;

	if (!addr_policy || !addr_pkt)
		return 0;

	for (i = 0; i < addr_policy->list_size && !match; i++) {
		match = match_address_range(&addr_policy->list[i],
			&addr_pkt->ofp_trivial_range_addr);
	}
	return match;
}


static odp_bool_t match_selector_mh(struct ofp_ipsec_selector_mh *mh1,
	struct ofp_ipsec_selector_mh *mh2)
{
	switch (mh1->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (mh2->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (mh1->mh_type != mh2->mh_type)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (mh2->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	}
	return 1;
}

static odp_bool_t match_port_range(struct ofp_ipsec_port_range *rg_policy,
	uint16_t port_pkt)
{
	if (port_pkt < rg_policy->port_start)
		return 0;

	if (port_pkt > rg_policy->port_end)
		return 0;

	return 1;
}

static odp_bool_t match_selector_port_ranges_value(
	struct ofp_ipsec_selector_port *port_policy,
	struct ofp_ipsec_selector_port *port_pkt)
{
	int i;
	int match = 0;

	for (i = 0; i < port_policy->list_size && !match; i++)
		match = match_port_range(&port_policy->list[i],
			port_pkt->ofp_trivial_range_port);
	return match;
}

static odp_bool_t match_selector_port_ranges(
	struct ofp_ipsec_selector_port *port_policy,
	struct ofp_ipsec_selector_port *port_pkt)
{
	switch (port_policy->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (port_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (port_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (!match_selector_port_ranges_value(port_policy, port_pkt))
			return 0;
		break;
	};
	return 1;
}

static odp_bool_t match_selector_protocol(
	struct ofp_ipsec_selector_next_layer_protocol *proto_policy,
	struct ofp_ipsec_selector_next_layer_protocol *proto_pkt)
{
	switch (proto_policy->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (proto_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (proto_pkt->protocol != proto_pkt->protocol)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE: /*IPv6*/
		if (proto_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	}

	return 1;
}

static odp_bool_t match_selector_icmp_type(
	struct ofp_ipsec_selector_icmp_type *type_policy,
	struct ofp_ipsec_selector_icmp_type *type_pkt)
{
	switch (type_policy->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (type_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (type_policy->icmp_type != type_pkt->icmp_type)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (type_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	}
	return 1;
}

static odp_bool_t match_icmp_code_range(
	struct ofp_ipsec_icmp_code_range *code_rg_policy,
	uint8_t code_pkt)
{
	if (code_pkt < code_rg_policy->code_start)
		return 0;
	if (code_pkt > code_rg_policy->code_end)
		return 0;
	return 1;
}

static odp_bool_t match_selector_icmp_code_value(
	struct ofp_ipsec_selector_icmp_code *cd_policy,
	struct ofp_ipsec_selector_icmp_code *cd_pkt)
{
	int i;
	int match = 0;

	for (i = 0; i < cd_policy->list_size && !match; i++)
		match = match_icmp_code_range(&cd_policy->list[i],
			cd_pkt->ofp_trivial_range_icmp_code);

	return match;
}

static odp_bool_t match_selector_icmp_code(
	struct ofp_ipsec_selector_icmp_code *cd_policy,
	struct ofp_ipsec_selector_icmp_code *cd_pkt)
{
	switch (cd_policy->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (cd_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (!match_selector_icmp_code_value(cd_policy, cd_pkt))
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (cd_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	}
	return 1;
}

static odp_bool_t match_protocol_dependent_ports(
	struct ofp_ipsec_selectors *sl_policy,
	struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_selector_port *sp = &sl_pkt->ofp_src_port_ranges;
	struct ofp_ipsec_selector_port *dp = &sl_pkt->ofp_dest_port_ranges;
	struct ofp_ipsec_selector_port opaque_port;

	if (sl_pkt->proto_dep_type != OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS) {
		sp = dp = &opaque_port;
		opaque_port.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
	}
	if (!match_selector_port_ranges(&sl_policy->ofp_src_port_ranges, sp))
		return 0;
	if (!match_selector_port_ranges(&sl_policy->ofp_dest_port_ranges, dp))
		return 0;

	return 1;
}

static odp_bool_t match_protocol_dependent_mh(
	struct ofp_ipsec_selectors *sl_policy,
	struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_selector_mh *mh = &sl_pkt->ofp_mh;
	struct ofp_ipsec_selector_mh opaque_mh;

	if (sl_pkt->proto_dep_type != OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH) {
		mh = &opaque_mh;
		opaque_mh.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
	}
	if (!match_selector_mh(&sl_policy->ofp_mh, mh))
		return 0;

	return 1;
}

static odp_bool_t match_protocol_dependent_icmp(
	struct ofp_ipsec_selectors *sl_policy,
	struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_selector_icmp_type *type = &sl_pkt->ofp_icmp_type;
	struct ofp_ipsec_selector_icmp_type opaque_type;
	struct ofp_ipsec_selector_icmp_code *code = &sl_pkt->ofp_icmp_code_ranges;
	struct ofp_ipsec_selector_icmp_code opaque_code;

	if (sl_pkt->proto_dep_type != OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP) {
		type = &opaque_type;
		opaque_type.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		code = &opaque_code;
		opaque_code.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
	}
	if (!match_selector_icmp_type(&sl_policy->ofp_icmp_type, type))
		return 0;
	if (!match_selector_icmp_code(&sl_policy->ofp_icmp_code_ranges, code))
		return 0;

	return 1;
}

odp_bool_t ofp_ipsec_selectors_match_sp_pkt(struct ofp_ipsec_selectors *sl_policy,
	struct ofp_ipsec_selectors *sl_pkt)
{
	if (!sl_policy || !sl_pkt)
		return 0;

	if (!match_selector_address_ranges(&sl_policy->src_addr_ranges,
		&sl_pkt->src_addr_ranges))
		return 0;
	if (!match_selector_address_ranges(&sl_policy->dest_addr_ranges,
		&sl_pkt->dest_addr_ranges))
		return 0;

	if (!match_selector_protocol(&sl_policy->protocol, &sl_pkt->protocol))
		return 0;

	switch (sl_policy->proto_dep_type) {
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE:
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS:
		if (!match_protocol_dependent_ports(sl_policy, sl_pkt))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP:
		if (!match_protocol_dependent_icmp(sl_policy, sl_pkt))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH:
		if (!match_protocol_dependent_mh(sl_policy, sl_pkt))
			return 0;
		break;
	}

	return 1;
}

static odp_bool_t comp_selector_address_ranges_triv(struct ofp_ipsec_selector_addr *addr1,
	struct ofp_ipsec_selector_addr *addr2)
{
	return comp_address(&addr1->ofp_trivial_range_addr, &addr2->ofp_trivial_range_addr);
}

static odp_bool_t match_selector_port_ranges_triv(
	struct ofp_ipsec_selector_port *port_sa,
	struct ofp_ipsec_selector_port *port_pkt)
{
	switch (port_sa->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (port_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (port_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (port_sa->ofp_trivial_range_port != port_pkt->ofp_trivial_range_port)
			return 0;
		break;
	};
	return 1;
}

static odp_bool_t match_protocol_dependent_ports_triv(
	struct ofp_ipsec_selectors *sl_sa,
	struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_selector_port *sp = &sl_pkt->ofp_src_port_ranges;
	struct ofp_ipsec_selector_port *dp = &sl_pkt->ofp_dest_port_ranges;
	struct ofp_ipsec_selector_port opaque_port;

	if (sl_pkt->proto_dep_type != OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS) {
		sp = dp = &opaque_port;
		opaque_port.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
	}
	if (!match_selector_port_ranges_triv(&sl_sa->ofp_src_port_ranges, sp))
		return 0;
	if (!match_selector_port_ranges_triv(&sl_sa->ofp_dest_port_ranges, dp))
		return 0;

	return 1;
}

static odp_bool_t match_selector_icmp_code_triv(
	struct ofp_ipsec_selector_icmp_code *cd_sa,
	struct ofp_ipsec_selector_icmp_code *cd_pkt)
{
	switch (cd_sa->value_type) {
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY:
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE:
		if (cd_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
			return 0;
		if (cd_sa->ofp_trivial_range_icmp_code != cd_pkt->ofp_trivial_range_icmp_code)
			return 0;
		break;
	case OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE:
		if (cd_pkt->value_type != OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE)
			return 0;
		break;
	}
	return 1;
}

static odp_bool_t match_protocol_dependent_icmp_triv(
	struct ofp_ipsec_selectors *sl_sa,
	struct ofp_ipsec_selectors *sl_pkt)
{
	struct ofp_ipsec_selector_icmp_type *type = &sl_pkt->ofp_icmp_type;
	struct ofp_ipsec_selector_icmp_type opaque_type;
	struct ofp_ipsec_selector_icmp_code *code = &sl_pkt->ofp_icmp_code_ranges;
	struct ofp_ipsec_selector_icmp_code opaque_code;

	if (sl_pkt->proto_dep_type != OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP) {
		type = &opaque_type;
		opaque_type.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		code = &opaque_code;
		opaque_code.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
	}
	if (!match_selector_icmp_type(&sl_sa->ofp_icmp_type, type))
		return 0;
	if (!match_selector_icmp_code_triv(&sl_sa->ofp_icmp_code_ranges, code))
		return 0;

	return 1;
}

odp_bool_t ofp_ipsec_selectors_match_sa_pkt(struct ofp_ipsec_selectors *sl_sa,
	struct ofp_ipsec_selectors *sl_pkt)
{
	if (!comp_selector_address_ranges_triv(&sl_sa->src_addr_ranges,
		&sl_pkt->src_addr_ranges))
		return 0;
	if (!comp_selector_address_ranges_triv(&sl_sa->dest_addr_ranges,
		&sl_pkt->dest_addr_ranges))
		return 0;

	if (!match_selector_protocol(&sl_sa->protocol, &sl_pkt->protocol))
		return 0;

	switch (sl_sa->proto_dep_type) {
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE:
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS:
		if (!match_protocol_dependent_ports_triv(sl_sa, sl_pkt))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP:
		if (!match_protocol_dependent_icmp_triv(sl_sa, sl_pkt))
			return 0;
		break;
	case OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH:
		if (!match_protocol_dependent_mh(sl_sa, sl_pkt))
			return 0;
		break;
	}

	return 1;
}

static int ofp_ipsec_selector_ports_from_outgoing_ipv4_pkt(struct ofp_ip *ip,
	struct ofp_ipsec_selectors *sl)
{
	uint32_t iphlen;
	uint16_t sport, dport;

	if (odp_be_to_cpu_16(ip->ip_off) & OFP_IP_OFFMASK) {
		sl->ofp_src_port_ranges.value_type =
			OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		sl->ofp_src_port_ranges.value_type =
			OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		return 0;
	}

	iphlen = ip->ip_hl << 2;
	if (ip->ip_p == OFP_IPPROTO_UDP) {
		struct ofp_udphdr *uh;

		uh = (struct ofp_udphdr *)((uint8_t *)ip + iphlen);
		sport = uh->uh_sport;
		dport = uh->uh_dport;
	} else if (ip->ip_p == OFP_IPPROTO_TCP){
		struct ofp_tcphdr *th;

		th = (struct ofp_tcphdr *)((uint8_t *)ip + iphlen);
		sport = th->th_sport;
		dport = th->th_dport;
	} else
		return -1;

	sl->ofp_src_port_ranges.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	sl->ofp_src_port_ranges.list_size = 1;
	sl->ofp_src_port_ranges.ofp_trivial_range_port = sport;

	sl->ofp_dest_port_ranges.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	sl->ofp_dest_port_ranges.list_size = 1;
	sl->ofp_dest_port_ranges.ofp_trivial_range_port = dport;

	return 0;
}

static int ofp_ipsec_selector_icmp_from_outgoing_ipv4_pkt(struct ofp_ip *ip,
	struct ofp_ipsec_selectors *sl)
{
	struct ofp_icmp *icmp;
	uint32_t iphlen;

	if (odp_be_to_cpu_16(ip->ip_off) & OFP_IP_OFFMASK) {
		sl->ofp_icmp_type.value_type =
			OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		sl->ofp_icmp_code_ranges.value_type =
			OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE;
		return 0;
	}

	iphlen = ip->ip_hl << 2;
	icmp = (struct ofp_icmp *)((uint8_t *)ip + iphlen);

	sl->ofp_icmp_type.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	sl->ofp_icmp_type.icmp_type = icmp->icmp_type;
	sl->ofp_icmp_code_ranges.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	sl->ofp_icmp_code_ranges.list_size = 1;
	sl->ofp_icmp_code_ranges.ofp_trivial_range_icmp_code = icmp->icmp_code;

	return 0;
}

int ofp_ipsec_selectors_from_pkt(odp_packet_t pkt,
	struct ofp_ipsec_selectors *sl)
{
	struct ofp_ip *ip;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	ofp_ipsec_selectors_init(sl);

	/* Source address*/
	sl->src_addr_ranges.list_size = 1;
	sl->src_addr_ranges.ofp_trivial_range_addr.addr_type_ipv4 = 1;
	sl->src_addr_ranges.ofp_trivial_range_addr.addr.addr4 =
		odp_cpu_to_le_32(odp_be_to_cpu_32(ip->ip_src.s_addr));

	/* Destination address*/
	sl->dest_addr_ranges.list_size = 1;
	sl->dest_addr_ranges.ofp_trivial_range_addr.addr_type_ipv4 = 1;
	sl->dest_addr_ranges.ofp_trivial_range_addr.addr.addr4 = odp_cpu_to_le_32(odp_be_to_cpu_32(ip->ip_dst.s_addr));

	sl->protocol.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	sl->protocol.protocol = ip->ip_p;

	if (ip->ip_p == OFP_IPPROTO_UDP || ip->ip_p == OFP_IPPROTO_TCP) {
		sl->proto_dep_type = OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS;
		if (ofp_ipsec_selector_ports_from_outgoing_ipv4_pkt(ip, sl))
			return -1;
	} else if (ip->ip_p == OFP_IPPROTO_ICMP) {
		sl->proto_dep_type = OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP;

		if (ofp_ipsec_selector_icmp_from_outgoing_ipv4_pkt(ip, sl))
			return -1;
	}
#if 0
	else if (ip->ip_p == OFP_IPPROTO_MH) {  /* IPv6 only*/
		sl->proto_dep_type = OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_MH;
		sl->ofp_mh.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
		sl->ofp_mh.mh_type = 0;
	}
#endif /* 0*/
	else
		sl->proto_dep_type = OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE;

	return 0;
}
