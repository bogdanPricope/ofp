/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_config.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_pkt_processing.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

enum ofp_return_code ofp_ah4_input(odp_packet_t pkt, int off)
{
	enum ofp_return_code ret;
	uint32_t spi;
	struct ofp_ip *ip;
	int nloff, nlp;

	if (!ofp_ipsec_boundary_crossing_get(pkt))
		return OFP_PKT_DROP;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	spi = *(uint32_t*)((uint8_t *)ip + off + 4 /*SPI offset*/);
	nloff = off;

	ret = ofp_ipsec_process_inbound_pkt_sec_local(pkt,
		spi, OFP_IPSEC_PROTOCOL_AH,
		&nloff, &nlp);
	if (ret != OFP_PKT_CONTINUE)
		return ret;

	return ofp_nlp_processing(pkt, nloff, nlp, OFP_IPPROTO_IPV4);
}

void ofp_ah4_ctlinput(int cmd, struct ofp_sockaddr *sa, void *vip)
{
	(void)cmd;
	(void)sa;
	(void)vip;
}

enum ofp_return_code ofp_esp4_input(odp_packet_t pkt, int off)
{
	enum ofp_return_code ret;
	uint32_t spi;
	struct ofp_ip *ip;
	int nloff, nlp;

	if (!ofp_ipsec_boundary_crossing_get(pkt))
		return OFP_PKT_DROP;

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	spi = *(uint32_t*)((uint8_t *)ip + off);
	nloff = off;

	ret = ofp_ipsec_process_inbound_pkt_sec_local(pkt,
		odp_be_to_cpu_32(spi), OFP_IPSEC_PROTOCOL_ESP,
		&nloff, &nlp);
	if (ret != OFP_PKT_CONTINUE)
		return ret;

	return ofp_nlp_processing(pkt, nloff, nlp, OFP_IPPROTO_IPV4);
}

void ofp_esp4_ctlinput(int cmd, struct ofp_sockaddr *sa, void *vip)
{
	(void)cmd;
	(void)sa;
	(void)vip;
}


