/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "api/ofp_config.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_ipsec_pkt_processing.h"
#include "ofpi_ipsec_operation.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_hook.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

static ofp_ipsec_pkt_in_proc
	ofp_process_in[OFP_IPSEC_PROTOCOL_CNT][OFP_IPSEC_MODE_CNT] = {
	{ofp_ipsec_esp_tunnel_in, NULL},	/*ESP: tunnel, transport*/
	{NULL, NULL}	/*AH:  tunnel, transport*/
};

static ofp_ipsec_pkt_in_proc
	ofp_process_in_compl[OFP_IPSEC_PROTOCOL_CNT][OFP_IPSEC_MODE_CNT] = {
	{ofp_ipsec_esp_tunnel_in_compl, NULL},	/*ESP: tunnel, transport*/
	{NULL, NULL}	/*AH:  tunnel, transport*/
};

static ofp_ipsec_pkt_out_proc
	ofp_process_out[OFP_IPSEC_PROTOCOL_CNT][OFP_IPSEC_MODE_CNT] = {
	{ofp_ipsec_esp_tunnel_out, NULL},	/*ESP: tunnel, transport*/
	{NULL, NULL}	/*AH:  tunnel, transport*/
};

static ofp_ipsec_pkt_out_proc
	ofp_process_out_compl[OFP_IPSEC_PROTOCOL_CNT][OFP_IPSEC_MODE_CNT] = {
	{ofp_ipsec_esp_tunnel_out_compl, NULL},	/*ESP: tunnel, transport*/
	{NULL, NULL}	/*AH:  tunnel, transport*/
};

enum ofp_return_code ofp_ipsec_process_outbound_pkt(odp_packet_t pkt,
	odp_bool_t *ip_header_changed)
{
	struct ofp_ipsec_selectors sl_pkt;
	struct ofp_ipsec_cache_out_entry *cache_entry;
	struct ofp_spd_entry *sp;

	*ip_header_changed = 0;

	if (ofp_ipsec_selectors_from_pkt(pkt, &sl_pkt)) {
		OFP_ERR("Failed to parse outbound packet\n");
		return OFP_PKT_DROP;
	}

	cache_entry = ofp_ipsec_cache_out_search(&sl_pkt);

#if !defined(OFP_STATIC_IPSEC_SAD_CONFIG) && defined(OFP_IPSEC_CUSTOM_KEY_MANAGEMENT)
	if (!cache_entry) {
		sp = ofp_ipsec_spd_search_local(OFP_SPD_S, &sl_pkt);
		if (sp) {
			enum ofp_return_code res;

			OFP_HOOK(OFP_HOOK_IPSEC_CUSTOM_KEY_MGNT, pkt, sp, &res);
			if (res != OFP_PKT_CONTINUE)
				return res;
			cache_entry = ofp_ipsec_cache_out_search(&sl_pkt);
		}
	}
#endif /* OFP_IPSEC_CUSTOM_KEY_MANAGEMENT */

	if (cache_entry) {
		enum ofp_return_code ret;
		ofp_ipsec_pkt_out_proc proc;

#ifdef OFP_IPSEC_SESSION_LAZY_CREATE
		if (cache_entry->_protect.session == ODP_CRYPTO_SESSION_INVALID)
			if (ofp_ipsec_create_session(&cache_entry->_protect.algs,
				&cache_entry->_protect.proc,
				OFP_IPSEC_DIRECTION_OUT,
				&cache_entry->_protect.session)) {
				OFP_ERR("Failed to create IPsec session.");
				return OFP_PKT_DROP;
			}
#endif /*OFP_IPSEC_SESSION_LAZY_CREATE*/

		/* Perform IPsec transformation (encrypt) */
		proc = ofp_process_out[cache_entry->_protect.protocol][cache_entry->_protect.protect_mode];
		if (!proc) {
			OFP_ERR("Operation not permitted.");
			return OFP_PKT_DROP;
		}
		ret = proc(pkt, cache_entry);
		if (ret != OFP_PKT_CONTINUE)
			return ret;

		if (cache_entry->_protect.protect_mode == OFP_IPSEC_MODE_TUNNEL)
			*ip_header_changed = 1;
		return OFP_PKT_CONTINUE; /* eventually */
	}

	sp = ofp_ipsec_spd_search_local(OFP_SPD_O, &sl_pkt);
	if (sp && sp->action == OFP_SPD_ACTION_BYPASS)
		return OFP_PKT_CONTINUE;

	return OFP_PKT_DROP;
}

enum ofp_return_code ofp_ipsec_process_inbound_pkt_sec_local(odp_packet_t pkt,
	uint32_t spi,
	enum ofp_ipsec_protocol protocol,
	int *offp, int *nlp)
{
	struct ofp_ipsec_cache_in_entry *cache_entry;
	enum ofp_return_code ret;
	ofp_ipsec_pkt_in_proc proc;

	cache_entry = ofp_ipsec_cache_in_search(spi, protocol);
	if (!cache_entry)
		return OFP_PKT_DROP;

#ifdef OFP_IPSEC_SESSION_LAZY_CREATE
	if (cache_entry->session == ODP_CRYPTO_SESSION_INVALID)
		if (ofp_ipsec_create_session(&cache_entry->algs,
			&cache_entry->proc,
			OFP_IPSEC_DIRECTION_IN,
			&cache_entry->session)) {
			OFP_ERR("Failed to create IPsec session.");
			return OFP_PKT_DROP;
		}
#endif /*OFP_IPSEC_SESSION_LAZY_CREATE*/

	/* Perform IPsec transformation (decrypt) */
	proc = ofp_process_in[cache_entry->protocol][cache_entry->protect_mode];
	if (!proc) {
		OFP_ERR("Operation not permitted.");
		return OFP_PKT_DROP;
	}
	ret = proc(pkt, cache_entry, offp, nlp);
	if (ret != OFP_PKT_CONTINUE)
		return ret;

#ifdef OFP_IPSEC_CHECK_INBOUND_SECURED_TRAFFIC
	{
		struct ofp_ipsec_selectors sl_pkt;

		if (ofp_ipsec_selectors_from_pkt(pkt, &sl_pkt)) {
			OFP_ERR("Failed to parse inbound packet\n");
			return OFP_PKT_DROP;
		}
		if (!ofp_ipsec_selectors_match_sa_pkt(&cache_entry->check_selectors,
			&sl_pkt)) {
			OFP_ERR("Inbound traffic does not match SA selectors.\n");
			return OFP_PKT_DROP;
		}
	}
#endif /* OFP_IPSEC_CHECK_INBOUND_SECURED_TRAFFIC */

	ofp_ipsec_boundary_crossing_set(pkt, 0);

	return OFP_PKT_CONTINUE;
}
enum ofp_return_code ofp_ipsec_process_inbound_pkt_other(odp_packet_t pkt)
{
	struct ofp_ipsec_selectors sl_pkt;
	struct ofp_spd_entry *sp;

	if (ofp_ipsec_selectors_from_pkt(pkt, &sl_pkt)) {
		OFP_ERR("Failed to parse inbound packet\n");
		return OFP_PKT_DROP;
	}

	sp = ofp_ipsec_spd_search_local(OFP_SPD_I, &sl_pkt);
	if (sp && sp->action == OFP_SPD_ACTION_BYPASS) {
		ofp_ipsec_boundary_crossing_set(pkt, 0);
		return OFP_PKT_CONTINUE;
	}

	return OFP_PKT_DROP;
}

enum ofp_return_code ofp_ipsec_crypto_compl(odp_packet_t pkt)
{
	struct ofp_ipsec_context *ctx;
	enum ofp_return_code res = OFP_PKT_PROCESSED;

	ctx = (struct ofp_ipsec_context *)odp_packet_user_area(pkt);
	if (ctx->in) {
		struct ofp_ipsec_cache_in_entry *cache_entry =
			ctx->cache.cache_in;
		ofp_ipsec_pkt_in_proc proc =
			ofp_process_in_compl[cache_entry->protocol][cache_entry->protect_mode];
		int off, nlp;

		res = proc(pkt, cache_entry, &off, &nlp);

		if (res == OFP_PKT_DROP)
			odp_packet_free(pkt);

		if (res != OFP_PKT_CONTINUE)
			return res;

#ifdef OFP_IPSEC_CHECK_INBOUND_SECURED_TRAFFIC
	{
		struct ofp_ipsec_selectors sl_pkt;

		if (ofp_ipsec_selectors_from_pkt(pkt, &sl_pkt)) {
			OFP_ERR("Failed to parse inbound packet\n");
			return OFP_PKT_DROP;
		}
		if (!ofp_ipsec_selectors_match_sa_pkt(&cache_entry->check_selectors,
			&sl_pkt)) {
			OFP_ERR("Inbound traffic does not match SA selectors.\n");
			return OFP_PKT_DROP;
		}
	}
#endif /* OFP_IPSEC_CHECK_INBOUND_SECURED_TRAFFIC */

		ofp_ipsec_boundary_crossing_set(pkt, 0);

		return ofp_packet_input_compl(pkt, off, nlp,
			OFP_IPPROTO_IPV4); /* only IPv4 is supported*/
	} else {
		struct ofp_ipsec_cache_out_entry *cache_entry =
			ctx->cache.cache_out;
		ofp_ipsec_pkt_out_proc proc =
			ofp_process_out_compl[cache_entry->_protect.protocol][cache_entry->_protect.protect_mode];

		res = proc(pkt, cache_entry);
		if (res == OFP_PKT_DROP)
			odp_packet_free(pkt);

		if (res != OFP_PKT_CONTINUE)
			return res;

		return ofp_packet_output_compl(pkt);
	}
	return OFP_PKT_PROCESSED;
}
