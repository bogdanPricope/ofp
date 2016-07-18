/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_IPSEC_PKT_PROCESSING_H__
#define __OFPI_IPSEC_PKT_PROCESSING_H__

#include "odp.h"
#include "api/ofp_types.h"
#include "api/ofp_ipsec_common.h"
#include "api/ofp_ipsec_pkt_processing.h"
#include "ofpi_ipsec_pkt_ctx.h"

enum ofp_return_code ofp_ipsec_process_outbound_pkt(odp_packet_t, odp_bool_t *);
enum ofp_return_code ofp_ipsec_process_inbound_pkt_sec_local(odp_packet_t,
	uint32_t, enum ofp_ipsec_protocol,
	int *, int *);
enum ofp_return_code ofp_ipsec_process_inbound_pkt_other(odp_packet_t);

#endif /* __OFPI_IPSEC_PKT_PROCESSING_H__ */


