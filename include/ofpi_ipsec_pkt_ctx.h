/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_IPSEC_PKT_CTX_H__
#define __OFP_IPSEC_PKT_CTX_H__

#include "odp.h"
#include "api/ofp_types.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_in.h"

struct ofp_ipsec_context
{
	odp_bool_t	in;
	odp_bool_t	ipsec_boundary_crossing;
	union {
		struct ofp_ipsec_cache_in_entry *cache_in;
		struct ofp_ipsec_cache_out_entry *cache_out;
	} cache;
	uint32_t ipsec_off;
	uint32_t ipsec_len;
	uint8_t inner_ip_tos;
	uint8_t inner_ttl;
};

static inline void ofp_ipsec_boundary_crossing_set(odp_packet_t pkt, odp_bool_t val)
{
	struct ofp_ipsec_context *ctx =
		(struct ofp_ipsec_context *)odp_packet_user_area(pkt);

	ctx->ipsec_boundary_crossing = val;
}
static inline odp_bool_t ofp_ipsec_boundary_crossing_get(odp_packet_t pkt)
{
	struct ofp_ipsec_context *ctx =
		(struct ofp_ipsec_context *)odp_packet_user_area(pkt);

	return ctx->ipsec_boundary_crossing;
}
#endif /* __OFP_IPSEC_PKT_CTX_H__ */


