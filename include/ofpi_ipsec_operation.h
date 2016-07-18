/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_IPSEC_OPERATION_H__
#define __OFP_IPSEC_OPERATION_H__

#include "odp.h"
#include "api/ofp_types.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_ipsec_pkt_ctx.h"

typedef enum ofp_return_code (*ofp_ipsec_pkt_in_proc)(odp_packet_t,
	struct ofp_ipsec_cache_in_entry *,
	 int *, int *);

typedef enum ofp_return_code (*ofp_ipsec_pkt_out_proc)(odp_packet_t,
	struct ofp_ipsec_cache_out_entry *);

enum ofp_return_code ofp_ipsec_esp_tunnel_in(odp_packet_t,
	struct ofp_ipsec_cache_in_entry *,
	 int *, int *);
enum ofp_return_code ofp_ipsec_esp_tunnel_in_compl(odp_packet_t,
	struct ofp_ipsec_cache_in_entry *,
	 int *, int *);
enum ofp_return_code ofp_ipsec_esp_tunnel_out(odp_packet_t,
	struct ofp_ipsec_cache_out_entry *);
enum ofp_return_code ofp_ipsec_esp_tunnel_out_compl(odp_packet_t,
	struct ofp_ipsec_cache_out_entry *);

#endif /* __OFP_IPSEC_OPERATION_H__*/


