/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "odp/helper/ipsec.h"
#include "odp/helper/ip.h"
#include "api/ofp_config.h"
#include "ofpi_in.h"
#include "ofpi_ip.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_operation.h"
#include "ofpi_ipsec_util.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

enum ofp_return_code ofp_ipsec_esp_tunnel_in(odp_packet_t pkt,
	struct ofp_ipsec_cache_in_entry *cache_in,
	int *offp, int *nlp)
{
	odp_crypto_op_params_t params;
	odp_bool_t posted = 1;
	odp_crypto_op_result_t result;
	struct ofp_ipsec_context *ctx;
	uint32_t esp_off = odp_packet_l3_offset(pkt) + *offp;
	uint32_t esp_len = odp_packet_len(pkt) - esp_off;
	uint32_t esp_len_wo_icv = esp_len - cache_in->algs.auth_alg_desc.icv_len;
	uint32_t esph_iv_len = ODPH_ESPHDR_LEN + cache_in->algs.cipher_alg_desc.iv_len;
	uint8_t *esp_hdr;

	params.session = cache_in->session;
	params.ctx = NULL;
	params.pkt = pkt;
	params.out_pkt = pkt;

	esp_hdr = (uint8_t *)odp_packet_data(pkt) + esp_off;

	/*cipher*/
	params.override_iv_ptr = esp_hdr + ODPH_ESPHDR_LEN;
	params.cipher_range.offset = esp_off + esph_iv_len;
	params.cipher_range.length = esp_len_wo_icv - esph_iv_len;

	/*auth*/
	params.auth_range.offset = esp_off;
	params.auth_range.length = esp_len_wo_icv;
	params.hash_result_offset = esp_off + esp_len_wo_icv;

	ctx = (struct ofp_ipsec_context *)odp_packet_user_area(pkt);
	ctx->in = 1;
	ctx->cache.cache_in = cache_in;
	ctx->ipsec_off = esp_off;
	ctx->ipsec_len = esp_len;
	if (odp_crypto_operation(&params,
				 &posted,
				 &result)) {
		OFP_ERR("Error: Crypto operation error.");
		return OFP_PKT_DROP;
	}
	if (posted)
		return OFP_PKT_ON_HOLD;

	if (!result.ok) {
		OFP_ERR("Crypto operation error: auth = %d, cipher = %d",
			result.auth_status.alg_err,
			result.cipher_status.alg_err);
		return OFP_PKT_DROP;
	}

	return ofp_ipsec_esp_tunnel_in_compl(pkt, cache_in, offp, nlp);
}
enum ofp_return_code ofp_ipsec_esp_tunnel_in_compl(odp_packet_t pkt,
	struct ofp_ipsec_cache_in_entry *cache_in,
	int *offp, int *nlp)
{
	struct ofp_ipsec_context *ctx =
		(struct ofp_ipsec_context *)odp_packet_user_area(pkt);
	uint32_t esp_off = ctx->ipsec_off;
	uint32_t esp_len = ctx->ipsec_len;
	uint32_t auth_icv_len = cache_in->algs.auth_alg_desc.icv_len;
	uint32_t esp_len_wo_icv = esp_len - auth_icv_len;
	uint32_t esph_iv_len = ODPH_ESPHDR_LEN + cache_in->algs.cipher_alg_desc.iv_len;
	uint32_t seq;
	uint8_t pad_len;
	uint8_t *esp_hdr;

	esp_hdr = (uint8_t *)odp_packet_data(pkt) + esp_off;
	seq = odp_be_to_cpu_32(*((uint32_t*)esp_hdr + 1));

	*nlp = *(esp_hdr + esp_len_wo_icv - 1);

	pad_len = *(esp_hdr + esp_len_wo_icv - 2);

	odp_packet_pull_head(pkt, esp_off + esph_iv_len);
	odp_packet_l3_offset_set(pkt, 0);
	*offp = 0;

	odp_packet_pull_tail(pkt, auth_icv_len + ODPH_ESPTRL_LEN +
				pad_len /* padding */);

	OFP_IPSEC_CACHE_IN_LOCK(cache_in);
	cache_in->seq_number = seq;
	OFP_IPSEC_CACHE_IN_UNLOCK(cache_in);

	return OFP_PKT_CONTINUE;
}
enum ofp_return_code ofp_ipsec_esp_tunnel_out(odp_packet_t pkt,
	struct ofp_ipsec_cache_out_entry *cache_out)
{
	odp_crypto_op_params_t params;
	odp_bool_t posted = 1;
	odp_crypto_op_result_t result;
	struct ofp_ipsec_context *ctx;
	struct ofp_ip *ip_in;
	uint32_t ip_in_off;
	uint32_t esp_off;
	uint32_t esp_len_wo_icv;
	uint8_t *esp_hdr, *esp_trailer;
	uint32_t esph_iv_len = ODPH_ESPHDR_LEN +
		cache_out->_protect.algs.cipher_alg_desc.iv_len;
	uint32_t payload_size, padding_len, esp_trailer_size;
	uint32_t tail_space_req;
	uint32_t seq, i;

/* 1. Fill ESP header + trailer*/
/*ESP header*/
	ip_in_off = odp_packet_l3_offset(pkt);
	ip_in = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	ctx = (struct ofp_ipsec_context *)odp_packet_user_area(pkt);
	ctx->inner_ip_tos = ip_in->ip_tos;
	ctx->inner_ttl = ip_in->ip_ttl;

	if (ip_in_off >= esph_iv_len)
		esp_off = ip_in_off - esph_iv_len;
	else if (odp_packet_push_head(pkt, esph_iv_len - ip_in_off)) {
		esp_off = 0;
		ip_in_off = esph_iv_len;
	} else /* no room for ESP header in this segment: drop for now: TODO - copy*/
		return OFP_PKT_DROP;

	OFP_IPSEC_CACHE_OUT_LOCK(cache_out);
	seq = ++cache_out->_protect.seq_number;
	OFP_IPSEC_CACHE_OUT_UNLOCK(cache_out);

	esp_hdr = (uint8_t *)odp_packet_data(pkt) + esp_off;

	/* SPI*/
	*(uint32_t*)esp_hdr = odp_cpu_to_be_32(cache_out->_protect.spi);

	/* Sequence Number */
	*((uint32_t*)esp_hdr + 1) = odp_cpu_to_be_32(seq);

	/* IV */
	ofp_ipsec_generate_iv(esp_hdr + ODPH_ESPHDR_LEN,
		cache_out->_protect.algs.cipher_alg_desc.iv_len,
		cache_out->_protect.algs.cipher_iv.data, seq);

/*ESP trailer*/
	payload_size = odp_be_to_cpu_16(ip_in->ip_len);
	padding_len = ofp_ipsec_compute_padding_len(payload_size + ODPH_ESPTRL_LEN,
		cache_out->_protect.algs.cipher_alg_desc.blk_size);

	esp_trailer_size = padding_len + ODPH_ESPTRL_LEN;
	tail_space_req = esp_trailer_size +
		cache_out->_protect.algs.auth_alg_desc.icv_len;
	esp_len_wo_icv = esph_iv_len + payload_size + esp_trailer_size;

	/* if no room for ESP trailer in this segment: drop for now: TODO - copy*/
	if (!odp_packet_push_tail(pkt, tail_space_req))
		return OFP_PKT_DROP;

	esp_trailer = (uint8_t *)ip_in + payload_size;

	/*Padding*/
	for (i = 0; i < padding_len; i++)
		*(esp_trailer + i) = (uint8_t)i + 1;

	/*Padding len*/
	*(esp_trailer + padding_len) = (uint8_t)padding_len;

	/* Next header*/
	*(esp_trailer + padding_len + 1) = OFP_IPPROTO_IPV4;

/* 2. Configure params*/
	params.session = cache_out->_protect.session;
	params.ctx = NULL;
	params.pkt = pkt;
	params.out_pkt = pkt;

	/*cipher*/
	params.override_iv_ptr = esp_hdr + ODPH_ESPHDR_LEN;
	params.cipher_range.offset = esp_off + esph_iv_len;
	params.cipher_range.length = esp_len_wo_icv - esph_iv_len;

	/*auth*/
	params.auth_range.offset = esp_off;
	params.auth_range.length = esp_len_wo_icv;
	params.hash_result_offset = esp_off + esp_len_wo_icv;

/* 3. Save context*/
	ctx->in = 0;
	ctx->cache.cache_out = cache_out;
	ctx->ipsec_off = esp_off;
	ctx->ipsec_len = esph_iv_len +
		payload_size +
		tail_space_req;

/* 4. Do operation*/
	if (odp_crypto_operation(&params,
				 &posted,
				 &result)) {
		OFP_ERR("Error: Crypto operation error.");
		return OFP_PKT_DROP;
	}
	if (posted)
		return OFP_PKT_ON_HOLD;

	if (!result.ok) {
		OFP_ERR("Crypto operation error: auth = %d, cipher = %d",
			result.auth_status.alg_err,
			result.cipher_status.alg_err);
		return OFP_PKT_DROP;
	}

	return ofp_ipsec_esp_tunnel_out_compl(pkt, cache_out);
}

enum ofp_return_code ofp_ipsec_esp_tunnel_out_compl(odp_packet_t pkt,
	struct ofp_ipsec_cache_out_entry *cache_out)
{
	struct ofp_ipsec_context *ctx =
		(struct ofp_ipsec_context *)odp_packet_user_area(pkt);
	struct ofp_ip *ip_out = NULL;
	uint32_t esp_off = ctx->ipsec_off;
	uint32_t esp_len = ctx->ipsec_len;
	static uint16_t id = 0;

	if (esp_off >= ODPH_IPV4HDR_LEN) {
		ip_out = (struct ofp_ip *)((uint8_t *)odp_packet_data(pkt) + esp_off - ODPH_IPV4HDR_LEN);
		odp_packet_l3_offset_set(pkt, esp_off - ODPH_IPV4HDR_LEN);
	} else if (odp_packet_push_head(pkt, ODPH_IPV4HDR_LEN - esp_off)) {
			ip_out = (struct ofp_ip *)odp_packet_data(pkt);
			esp_off = ODPH_IPV4HDR_LEN;
			odp_packet_l3_offset_set(pkt, 0);
	} else {
		/* No room for outer IP header in this segment: drop for now*/
		/* TODO - copy / add segment*/
		return OFP_PKT_DROP;
	}

	ip_out->ip_hl = 5;
	ip_out->ip_v = OFP_IPVERSION;
	ip_out->ip_tos = ctx->inner_ip_tos;
	ip_out->ip_len = odp_cpu_to_be_16(ODPH_IPV4HDR_LEN + esp_len);
	ip_out->ip_id = odp_cpu_to_be_16(id++);
	ip_out->ip_off = odp_cpu_to_be_16(OFP_IP_DF);
	ip_out->ip_ttl = ctx->inner_ttl;
	ip_out->ip_p = OFP_IPPROTO_ESP;
	ip_out->ip_src.s_addr = odp_cpu_to_be_32(odp_le_to_cpu_32(
		cache_out->_protect.protect_tunnel_src_addr.addr.addr4));
	ip_out->ip_dst.s_addr = odp_cpu_to_be_32(odp_le_to_cpu_32(
		cache_out->_protect.protect_tunnel_dest_addr.addr.addr4));

	ip_out->ip_sum = 0;
	ip_out->ip_sum = ofp_cksum_buffer((uint16_t *)ip_out, ODPH_IPV4HDR_LEN);

	return OFP_PKT_CONTINUE;
}
