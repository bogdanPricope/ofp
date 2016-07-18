/*-
 * Copyright (c) 2016 ENEA Software AB
 * Copyright (c) 2016 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "odp.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_spd.h"
#include "ofpi_ipsec_sad.h"
#include "ofpi_ipsec_cache_in.h"
#include "ofpi_ipsec_cache_out.h"
#include "ofpi_ipsec_alg.h"
#include "ofpi_portconf.h"
#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_util.h"

/*#define IPSEC_CLI_PARSE_LOG*/

#ifdef IPSEC_CLI_PARSE_LOG
# define PARSE_LOG(_fd, fmt, ...) \
	ofp_sendf(_fd, fmt, ##__VA_ARGS__)
#else
# define PARSE_LOG(_fd, fmt, ...)
#endif /* IPSEC_CLI_PARSE_LOG */

#define IPSEC_CLI_ERR(_fd,  fmt, ...) do {\
	ofp_sendf(_fd, fmt, ##__VA_ARGS__); \
	OFP_ERR(fmt, ##__VA_ARGS__); \
} while(0)


const char* alg_auth_array_str[] = {"null", "hmac-md5",
		"hmac-sha256-128", "aes128-gmac", NULL};
const uint32_t alg_auth_array_val[] = {OFP_AUTH_ALG_NULL,
		OFP_AUTH_ALG_MD5_96, OFP_AUTH_ALG_SHA256_128,
		OFP_AUTH_ALG_AES128_GMAC};

const char* alg_enc_array_str[] = {"null",
		"des-cbc", "3des-cbc",
		"aes128-cbc", "aes128-gcm", NULL};
const uint32_t alg_enc_array_val[] = { OFP_CIPHER_ALG_NULL,
		OFP_CIPHER_ALG_DES,OFP_CIPHER_ALG_3DES_CBC,
		OFP_CIPHER_ALG_AES128_CBC, OFP_CIPHER_ALG_AES128_GCM};

const char* selector_type_array_str[] = {"any", "opaque", NULL};
const uint32_t selector_type_array_val[] = {
		OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY,
		OFP_IPSEC_SELECTOR_VALUE_TYPE_OPAQUE};

const char* selector_type_no_opaque_array_str[] = {"any", NULL};
const uint32_t selector_type_no_opaque_array_val[] =
	{OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY};

const char* selector_proto_dep_array_str[] = {"none", "ports:", "icmp:", NULL};
const uint32_t selector_proto_dep_array_val[] = {OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_NONE,
		OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS, OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP};

const char* ipsec_proto_array_str[] = {"esp", "ah", NULL};
const uint32_t ipsec_proto_array_val[] = {OFP_IPSEC_PROTOCOL_ESP,
		OFP_IPSEC_PROTOCOL_AH};

const char* ipsec_mode_array_str[] = {"tunnel", "transport", NULL};
const uint32_t ipsec_mode_array_val[] = {OFP_IPSEC_MODE_TUNNEL,
		OFP_IPSEC_MODE_TRANSPORT};

const char* ipsec_flags_array_str[] = {"flags:", NULL};

static int parse_icmp_type(struct cli_conn *conn, char *str,
	struct ofp_ipsec_selector_icmp_type *type)
{
	int val;

	(void)conn;

	if (!token_string_to_val(str, &type->value_type,
		selector_type_no_opaque_array_str,
		selector_type_no_opaque_array_val))
		return 0;

	val = atoi(str);
	if (val < 0 || val > 255) {
		PARSE_LOG(conn->fd, "Invalid icmp type = |%s|\r\n", str);
		return -1;
	}

	type->value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	type->icmp_type = (uint8_t)val;

	return 0;
}

static int parse_icmp_code_range(struct cli_conn *conn, char *str,
	struct ofp_ipsec_icmp_code_range *rg)
{
	char *tkn;

	(void)conn;
	tkn = strsep(&str, "-");

	PARSE_LOG(conn->fd, "%s: rg_start = |%s|\r\n", __FUNCTION__, tkn);
	rg->code_start = (uint8_t)atoi(tkn);

	if (str) {
		tkn = str;
		PARSE_LOG(conn->fd, "%s: rg_end = |%s|\r\n", __FUNCTION__, tkn);
		rg->code_end = (uint8_t)atoi(tkn);
	} else
		rg->code_end = rg->code_start;

	return 0;
}

static int parse_icmp_codes(struct cli_conn *conn, char *str,
	struct ofp_ipsec_selector_icmp_code *codes)
{
	char *tkn;

	if (!token_string_to_val(str, &codes->value_type,
		selector_type_no_opaque_array_str,
		selector_type_no_opaque_array_val))
		return 0;

	codes->value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	codes->list_size = 0;

	while((tkn = strsep(&str, ",")) != NULL) {
		PARSE_LOG(conn->fd, "%s: rg = |%s|\r\n", __FUNCTION__, tkn);

		if (codes->list_size >=  OFP_IPSEC_ICMP_RANGE_LIST_SIZE) {
			ofp_sendf(conn->fd,
				"Maximum number of icmp codes ranges (%d) exceeded\r\n",
				OFP_IPSEC_ICMP_RANGE_LIST_SIZE);
			return -1;
		}
		if (parse_icmp_code_range(conn, tkn,
			&codes->list[codes->list_size])) {
			ofp_sendf(conn->fd,
				"Invalid icmp code range: %s\r\n", tkn);
			return -1;
		}
		codes->list_size++;
	}
	return 0;
}

static int parse_selector_icmp(struct cli_conn *conn, char *str,
	struct ofp_ipsec_selectors *sl)
{
	char *tkn;

	tkn = strsep(&str, ":");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: icmp type = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_icmp_type(conn, tkn, &sl->ofp_icmp_type)) {
		ofp_sendf(conn->fd, "Invalid icmp type = |%s|\r\n", tkn);
		return -1;
	}

	tkn = strsep(&str, ":");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: icmp code = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_icmp_codes(conn, tkn, &sl->ofp_icmp_code_ranges)) {
		ofp_sendf(conn->fd, "Invalid icmp type = %s\r\n", tkn);
		return -1;
	}
	if (sl->ofp_icmp_type.value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY &&
		sl->ofp_icmp_code_ranges.value_type !=
		OFP_IPSEC_SELECTOR_VALUE_TYPE_ANY) {
		ofp_sendf(conn->fd, "Invalid icmp type/code combination\r\n");
		return -1;
	}
	return 0;
}

static int parse_selector_port_range(struct cli_conn *conn, char *str,
	struct ofp_ipsec_port_range *rg)
{
	char *tkn;

	(void)conn;
	tkn = strsep(&str, "-");
	PARSE_LOG(conn->fd, "%s: rg_start = |%s|\r\n", __FUNCTION__, tkn);
	rg->port_start = (uint16_t)atoi(tkn);

	if (str) {
		tkn = str;
		PARSE_LOG(conn->fd, "%s: rg_end = |%s|\r\n", __FUNCTION__, tkn);
		rg->port_end = (uint16_t)atoi(tkn);
	} else
		rg->port_end = rg->port_start;

	return 0;
}

static int parse_selector_port_ranges(struct cli_conn *conn, char *str,
	struct ofp_ipsec_selector_port *port_ranges)
{
	char *tkn;

	if (!token_string_to_val(str, &port_ranges->value_type,
		selector_type_array_str, selector_type_array_val))
		return 0;

	port_ranges->value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
	port_ranges->list_size = 0;
	while((tkn = strsep(&str, ",")) != NULL) {
		PARSE_LOG(conn->fd, "%s: rg = |%s|\r\n", __FUNCTION__, tkn);

		if (port_ranges->list_size >=  OFP_IPSEC_PORT_RANGE_LIST_SIZE) {
			ofp_sendf(conn->fd,
				"Maximum number of port ranges (%d) exceeded\r\n",
				OFP_IPSEC_PORT_RANGE_LIST_SIZE);
			return -1;
		}
		if (parse_selector_port_range(conn, tkn,
			&port_ranges->list[port_ranges->list_size])) {
			ofp_sendf(conn->fd, "Invalid port range: %s\r\n", tkn);
			return -1;
		}
		port_ranges->list_size ++;
	}

	return 0;
}

static int parse_selector_ports(struct cli_conn *conn, char *str,
	struct ofp_ipsec_selectors *sl)
{
	char *tkn;

	tkn = strsep(&str, ":");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: port_src = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_selector_port_ranges(conn, tkn, &sl->ofp_src_port_ranges)) {
		ofp_sendf(conn->fd, "Invalid port range list: %s\r\n", tkn);
		return -1;
	}
	tkn = strsep(&str, ":");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: port_dest = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_selector_port_ranges(conn, tkn, &sl->ofp_dest_port_ranges)) {
		ofp_sendf(conn->fd, "Invalid port range list: %s\r\n", tkn);
		return -1;
	}

	return 0;
}

static int parse_selector_addr_range(struct cli_conn *conn, char *str,
	struct ofp_ipsec_addr_range *rg)
{
	char *tkn;
	int a, b, c, d;

	(void)conn;
	tkn = strsep(&str, "-");
	PARSE_LOG(conn->fd, "%s: addr_start = |%s|\r\n", __FUNCTION__, tkn);
	rg->addr_start.addr_type_ipv4 = 1;
	if (sscanf(tkn, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return -1;
	rg->addr_start.addr.addr4 = (a << 24) | (b << 16) | (c << 8) | d; /* LE*/

	if (str) {
		tkn = str;
		PARSE_LOG(conn->fd, "%s: addr_end = |%s|\r\n", __FUNCTION__, tkn);
		rg->addr_end.addr_type_ipv4 = 1;
		if (sscanf(tkn, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
			return -1;
		rg->addr_end.addr.addr4 = (a << 24) | (b << 16) | (c << 8) | d; /* LE*/
	} else {
		rg->addr_end.addr_type_ipv4 = rg->addr_start.addr_type_ipv4;
		rg->addr_end.addr.addr4 = rg->addr_start.addr.addr4;
	}
	PARSE_LOG(conn->fd, "%s: [0x%x-0x%x]\r\n", __FUNCTION__,
		rg->addr_start.addr.addr4,
		rg->addr_end.addr.addr4);
   return 0;
}
static int parse_selector_addr_ranges(struct cli_conn *conn, char *str,
   struct ofp_ipsec_selector_addr *addr_ranges)
{
	char *tkn;

	addr_ranges->list_size = 0;

	while ((tkn = strsep(&str, ",")) != NULL) {
		PARSE_LOG(conn->fd, "%s: rg = |%s|\r\n", __FUNCTION__, tkn);

		if (addr_ranges->list_size >=  OFP_IPSEC_ADDR_RANGE_LIST_SIZE) {
			ofp_sendf(conn->fd,
				"Maximum number of address ranges (%d) exceeded\r\n",
				OFP_IPSEC_ADDR_RANGE_LIST_SIZE);
			return -1;
		}
		if (parse_selector_addr_range(conn, tkn,
			&addr_ranges->list[addr_ranges->list_size])) {
			ofp_sendf(conn->fd,
				"Invalid address range: %s\r\n", tkn);
			return -1;
		}
		addr_ranges->list_size ++;
	}
	return 0;
}

static int parse_selectors(struct cli_conn *conn, char **str_sl,
	struct ofp_ipsec_selectors *sl)
{
	char *str_iter = *str_sl;
	char *tkn;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, str_iter);

/* Source address ranges */
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: src = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_selector_addr_ranges(conn, tkn, &sl->src_addr_ranges)) {
		ofp_sendf(conn->fd, "Invalid Source address ranges");
		return -1;
	}

/* Destination address ranges */
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: dest = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_selector_addr_ranges(conn, tkn, &sl->dest_addr_ranges)) {
		ofp_sendf(conn->fd, "Invalid Destination address ranges");
		return -1;
	}

/* Next Layer Protocol selector */
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: nlp = |%s|\r\n", __FUNCTION__, tkn);
	if (token_string_to_val(tkn, &sl->protocol.value_type,
		selector_type_array_str, selector_type_array_val)) {
		int val = atoi(tkn);

		if (val <= 0 || val > 255) {
			ofp_sendf(conn->fd, "Invalid Next Layer Protocol value: %d", val);
			return -1;
		}
		sl->protocol.value_type = OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE;
		sl->protocol.protocol = (uint8_t)val;
	}

/* Next Layer Protocol Dependent selectors */
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: nlp_dep = |%s|\r\n", __FUNCTION__, tkn);
	if (token_string_to_val_with_size(tkn, &sl->proto_dep_type,
		selector_proto_dep_array_str, selector_proto_dep_array_val)) {
		ofp_sendf(conn->fd,
			"Invalid Next Layer Protocol Dependent value: %s", tkn);
		return -1;
	}

	if (sl->proto_dep_type == OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS) {
		if (parse_selector_ports(conn, tkn + 6, sl)) {
			ofp_sendf(conn->fd,
				"Invalid port selector: %s", tkn);
			return -1;
		}
	} else if (sl->proto_dep_type == OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP) {
		if (parse_selector_icmp(conn, tkn + 5, sl)) {
			ofp_sendf(conn->fd,
				"Invalid icmp selector: %s", tkn);
			return -1;
		}
	}

	*str_sl = str_iter;
	return 0;
}

static int parse_protocol(char *str, enum ofp_ipsec_protocol *proto)
{
	if (!str)
		return -1;

	if (token_string_to_val(str, proto,
		ipsec_proto_array_str, ipsec_proto_array_val))
		return -1;
	return 0;
}

static int parse_policy_mode(char *str, enum ofp_ipsec_mode *mode)
{
	if (!str)
		return -1;

	if (token_string_to_val(str, mode,
		ipsec_mode_array_str, ipsec_mode_array_val))
		return -1;
	return 0;
}

static int parse_policy_tunnel_IPs(struct cli_conn *conn, char *str,
	struct ofp_spd_entry *sp)
{
	char *tkn;
	int a, b, c, d;

	(void)conn;
	tkn = strsep(&str, "-");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: ip_src = |%s|\r\n", __FUNCTION__, tkn);
	if (sscanf(tkn, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return -1;
	sp->protect_tunnel_src_addr.addr.addr4 =
		(a << 24) | (b << 16) | (c << 8) | d; /* LE*/
	sp->protect_tunnel_src_addr.addr_type_ipv4 = 1;

	tkn = strsep(&str, " ");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: ip_dest = |%s|\r\n", __FUNCTION__, tkn);
	if (sscanf(tkn, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return -1;
	sp->protect_tunnel_dest_addr.addr.addr4 =
		(a << 24) | (b << 16) | (c << 8) | d; /* LE*/
	sp->protect_tunnel_dest_addr.addr_type_ipv4 = 1;

	return 0;
}

static int parse_policy(struct cli_conn *conn, char **str_sl, struct ofp_spd_entry *sp)
{
	char *tkn;
	char *str_iter = *str_sl;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, str_iter);

/* Protect protocol */
	tkn = strsep(&str_iter, "/ ");
	PARSE_LOG(conn->fd, "%s: protocol = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_protocol(tkn, &sp->protect_protocol)) {
		ofp_sendf(conn->fd, "Invalid policy protect protocol!");
		return -1;
	}

/* Protect mode */
	tkn = strsep(&str_iter, "/ ");
	PARSE_LOG(conn->fd, "%s: mode = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_policy_mode(tkn, &sp->protect_mode)) {
		ofp_sendf(conn->fd, "Invalid policy protect mode!");
		return -1;
	}

/* Protect tunnel IP addresses*/
	tkn = str_iter;
	if (sp->protect_mode == OFP_IPSEC_MODE_TRANSPORT) {
		if (tkn && strlen(tkn)) {
			ofp_sendf(conn->fd,
				"Transport mode does not require additional params!");
			return -1;
		}
	} else {
		if (!(tkn && strlen(tkn))) {
			ofp_sendf(conn->fd,
				"Tunnel mode requires additional params!");
			return -1;
		}
		PARSE_LOG(conn->fd, "%s: mode = |%s|\r\n", __FUNCTION__, tkn);
		if (parse_policy_tunnel_IPs(conn, tkn, sp)) {
			ofp_sendf(conn->fd, "Invalid policy tunnel IPs!");
			return -1;
		}
	}

	*str_sl = str_iter;
	return 0;
}

void f_ipsec_spdadd_in_bypass(struct cli_conn *conn, const char *s)
{
	struct ofp_spd_entry sp;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);

	ofp_ipsec_spd_entry_init(&sp);

	sp.direction = OFP_IPSEC_DIRECTION_IN;
	sp.action = OFP_SPD_ACTION_BYPASS;

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sp.selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_add(&sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security policy to SPD");
	} else
		OFP_INFO("Security policy added successfuly to SPD");

	sendcrlf(conn);
}

void f_ipsec_spdadd_in_discard(struct cli_conn *conn, const char *s)
{
	struct ofp_spd_entry sp;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_spd_entry_init(&sp);

	sp.direction = OFP_IPSEC_DIRECTION_IN;
	sp.action = OFP_SPD_ACTION_DISCARD;

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sp.selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_add(&sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security policy to SPD");
	} else
		OFP_INFO("Security policy added successfuly to SPD");

	sendcrlf(conn);
}

void f_ipsec_spdadd_out_bypass(struct cli_conn *conn, const char *s)
{
	struct ofp_spd_entry sp;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_spd_entry_init(&sp);

	sp.direction = OFP_IPSEC_DIRECTION_OUT;
	sp.action = OFP_SPD_ACTION_BYPASS;

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sp.selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_add(&sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security policy to SPD");
	} else
		OFP_INFO("Security policy added successfuly to SPD");

	sendcrlf(conn);
}

void f_ipsec_spdadd_out_discard(struct cli_conn *conn, const char *s)
{
	struct ofp_spd_entry sp;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_spd_entry_init(&sp);

	sp.direction = OFP_IPSEC_DIRECTION_OUT;
	sp.action = OFP_SPD_ACTION_DISCARD;

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sp.selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_add(&sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security policy to SPD");
	} else
		OFP_INFO("Security policy added successfuly to SPD");

	sendcrlf(conn);
}

void f_ipsec_spdadd_out_protect(struct cli_conn *conn, const char *s)
{
	struct ofp_spd_entry sp;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_spd_entry_init(&sp);

	sp.direction = OFP_IPSEC_DIRECTION_OUT;
	sp.action = OFP_SPD_ACTION_PROTECT;

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sp.selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	if (parse_policy(conn, &itr, &sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse protect policy!");
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_add(&sp)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security policy to SPD");
	} else
		OFP_INFO("Security policy added successfuly to SPD");

	sendcrlf(conn);
}


void f_ipsec_spddel_in(struct cli_conn *conn, const char *s)
{
	struct ofp_ipsec_selectors sl;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_IN;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_selectors_init(&sl);
	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sl)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_del(&sl, dir)) {
		IPSEC_CLI_ERR(conn->fd,
			"Failed to delete security policy to SPD\r\n");
	} else
		OFP_INFO("Security policy deleted successfuly to SPD");

	sendcrlf(conn);
}
void f_ipsec_spddel_out(struct cli_conn *conn, const char *s)
{
	struct ofp_ipsec_selectors sl;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_OUT;
	char *sbuf, *itr;

	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, s);
	ofp_ipsec_selectors_init(&sl);
	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sl)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_spd_del(&sl, dir)) {
		IPSEC_CLI_ERR(conn->fd,
			"Failed to delete security policy from SPD\r\n");
	} else
		OFP_INFO("Security policy deleted successfuly to SPD");

	sendcrlf(conn);
}

void f_ipsec_spdflush(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_spd_flush())
		IPSEC_CLI_ERR(conn->fd, "Failed to flush SPDs\r\n");
	else
		OFP_INFO("Security policy database successfuly flushed");
	sendcrlf(conn);
}

static void addr4_le_dump(int fd, uint32_t addr4)
{
	ofp_sendf(fd, "%d.%d.%d.%d",
		addr4>>24, (addr4>>16)&0xff,
		(addr4>>8)&0xff, addr4&0xff);
}

static void addr6_dump(int fd, uint8_t *addr)
{
	int i;

	for (i = 0; i < 16; i += 2)
		ofp_sendf(fd, "%s%02x%02x",
			i == 0 ? "" : ":", *(addr + i), *(addr + i+1));
}

static void addr_dump(int fd, struct ofp_ipsec_addr *addr)
{
	if (addr->addr_type_ipv4)
		addr4_le_dump(fd, addr->addr.addr4);
	else
		addr6_dump(fd, (uint8_t *)addr->addr.addr6);
}

static void addr_range_dump(int fd, struct ofp_ipsec_addr_range *rg)
{
	addr_dump(fd, &rg->addr_start);
	ofp_sendf(fd, "-");
	addr_dump(fd, &rg->addr_end);
}

static void addr_ranges_dump(int fd, struct ofp_ipsec_selector_addr *rg_lst,
	odp_bool_t triv)
{
	int i;

	ofp_sendf(fd, " ");

	if (triv) {
		addr_dump(fd, &rg_lst->ofp_trivial_range_addr);
		return;
	}

	for (i = 0; i < rg_lst->list_size; i++) {
		if (i)
			ofp_sendf(fd, ",");
		addr_range_dump(fd, &rg_lst->list[i]);
	}
}

static void nlp_dump(int fd,
	struct ofp_ipsec_selector_next_layer_protocol *nlp)
{
	const char *val_type_str;

	ofp_sendf(fd, " ");

	val_type_str = token_val_to_string(nlp->value_type,
		selector_type_array_str, selector_type_array_val);
	if (val_type_str)
		ofp_sendf(fd, "%s", val_type_str);
	else if (nlp->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
		ofp_sendf(fd, "%d", nlp->protocol);
	else
		ofp_sendf(fd, "error");
}

static void nlp_dep_port_range_dump(int fd, struct ofp_ipsec_port_range *rg)
{
	ofp_sendf(fd, "%d-%d", rg->port_start, rg->port_end);
}

static void nlp_dep_port_ranges_dump(int fd, struct ofp_ipsec_selector_port *ports,
	odp_bool_t triv)
{
	const char *val_type_str;

	val_type_str = token_val_to_string(ports->value_type,
		selector_type_array_str, selector_type_array_val);
	if (val_type_str)
		ofp_sendf(fd, "%s", val_type_str);
	else if (ports->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE) {
		int i;

		if (triv) {
			ofp_sendf(fd, "%d", ports->ofp_trivial_range_port);
			return;
		}
		for (i = 0; i < ports->list_size; i++) {
			if (i)
				ofp_sendf(fd, ",");
			nlp_dep_port_range_dump(fd, &ports->list[i]);
		}
	} else
		ofp_sendf(fd, "error");
}

static void nlp_dep_icmp_type_dump(int fd, struct ofp_ipsec_selector_icmp_type *type)
{
	const char *val_type_str;

	val_type_str = token_val_to_string(type->value_type,
		selector_type_array_str, selector_type_array_val);
	if (val_type_str)
		ofp_sendf(fd, "%s", val_type_str);
	else if (type->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE)
		ofp_sendf(fd, "%d", type->icmp_type);
	else
		ofp_sendf(fd, "error");
}

static void nlp_dep_icmp_codes_range_dump(int fd,
	struct ofp_ipsec_icmp_code_range *rg)
{
	ofp_sendf(fd, "%d-%d", rg->code_start, rg->code_end);
}

static void nlp_dep_icmp_codes_dump(int fd, struct ofp_ipsec_selector_icmp_code *codes,
	odp_bool_t triv)
{
	const char *val_type_str;

	val_type_str = token_val_to_string(codes->value_type,
		selector_type_array_str, selector_type_array_val);
	if (val_type_str)
		ofp_sendf(fd, "%s", val_type_str);
	else if (codes->value_type == OFP_IPSEC_SELECTOR_VALUE_TYPE_VALUE) {
       	int i;

		if (triv) {
			ofp_sendf(fd, "%d", codes->ofp_trivial_range_icmp_code);
			return;
		}
		for (i = 0; i < codes->list_size; i++) {
			if (i)
				ofp_sendf(fd, ",");
			nlp_dep_icmp_codes_range_dump(fd, &codes->list[i]);
		}
	} else
		ofp_sendf(fd, "error");
}

static void nlp_dep_dump(int fd, struct ofp_ipsec_selectors *sl,
	odp_bool_t triv)
{
	const char *val_type_str;

	ofp_sendf(fd, " ");

	val_type_str = token_val_to_string(sl->proto_dep_type,
		selector_proto_dep_array_str, selector_proto_dep_array_val);
	if (!val_type_str) {
		ofp_sendf(fd, "error");
		return;
	}

	ofp_sendf(fd, "%s", val_type_str);

       if (sl->proto_dep_type == OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_PORTS) {
		nlp_dep_port_ranges_dump(fd, &sl->ofp_src_port_ranges, triv);
		ofp_sendf(fd, ":");
		nlp_dep_port_ranges_dump(fd, &sl->ofp_dest_port_ranges, triv);
	} else if (sl->proto_dep_type == OFP_IPSEC_PROTOCOL_DEPENDENT_TYPE_ICMP) {
		nlp_dep_icmp_type_dump(fd, &sl->ofp_icmp_type);
		ofp_sendf(fd, ":");
		nlp_dep_icmp_codes_dump(fd, &sl->ofp_icmp_code_ranges, triv);
	}
}

static void selector_dump(int fd, struct ofp_ipsec_selectors *sl,
	odp_bool_t triv)
{
/* src address ranges list*/
	addr_ranges_dump(fd, &sl->src_addr_ranges, triv);

/* dest address ranges list*/
	addr_ranges_dump(fd, &sl->dest_addr_ranges, triv);

/* Next layer protocol*/
	nlp_dump(fd, &sl->protocol);

/* Next layer protocol dependent*/
	nlp_dep_dump(fd, sl, triv);
}

static void protocol_dump(int fd, enum ofp_ipsec_protocol *protocol)
{
	const char *str = token_val_to_string(*protocol,
		ipsec_proto_array_str, ipsec_proto_array_val);
	if (str)
		ofp_sendf(fd, " %s", str);
	else
		ofp_sendf(fd, " error");
}

static void mode_dump(int fd, enum ofp_ipsec_mode *mode)
{
	const char *str = token_val_to_string(*mode,
		ipsec_mode_array_str, ipsec_mode_array_val);
	if (str)
		ofp_sendf(fd, "%s", str);
	else
		ofp_sendf(fd, "error");
}

static void sp_protect_policy_dump(int fd, struct ofp_spd_entry *sp)
{
	protocol_dump(fd, &sp->protect_protocol);

	ofp_sendf(fd, "/");

	mode_dump(fd, &sp->protect_mode);

	if (sp->protect_mode == OFP_IPSEC_MODE_TUNNEL) {
		ofp_sendf(fd, "/");

		addr_dump(fd, &sp->protect_tunnel_src_addr);
		ofp_sendf(fd, "-");
		addr_dump(fd, &sp->protect_tunnel_dest_addr);
	}
}

static void action_dump(int fd, enum ofp_spd_action *action)
{
	ofp_sendf(fd, " ");

	if (*action == OFP_SPD_ACTION_DISCARD)
		ofp_sendf(fd, "discard");
	else if (*action == OFP_SPD_ACTION_BYPASS)
		ofp_sendf(fd, "bypass");
	else if (*action == OFP_SPD_ACTION_PROTECT)
		ofp_sendf(fd, "protect");
	else
		ofp_sendf(fd, "error ");
}

void sp_dump(int fd, void* _sp)
{
	struct ofp_spd_entry *sp = (struct ofp_spd_entry *)_sp;

/* selector*/
	selector_dump(fd, &sp->selectors, 0);

/* policy */
	ofp_sendf(fd, " -P");
	if (sp->direction == OFP_IPSEC_DIRECTION_IN)
		ofp_sendf(fd, " in");
	else
		ofp_sendf(fd, " out");

	action_dump(fd, &sp->action);
	if (sp->action == OFP_SPD_ACTION_PROTECT)
		sp_protect_policy_dump(fd, sp);
}

void f_ipsec_spddump(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_spd_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd, "Failed to dump SPDs\r\n");
	else
		OFP_INFO("Security policy database successfuly dump.");
	sendcrlf(conn);
}

static int parse_spi(char *str, uint32_t *spi)
{
	*spi = atoi(str);
	return 0;
}

static int parse_bool_flag(struct cli_conn *conn, char *str, odp_bool_t *flag)
{
	const char* array_str[] = {"true", "false", NULL};
	const uint32_t array_val[] = {1, 0};
	uint32_t _flag;

	(void)conn;

	if (!str)
		return -1;

	PARSE_LOG(conn->fd, "%s: tkn = |%s|\r\n", __FUNCTION__, str);

	if (token_string_to_val(str, &_flag,
		array_str, array_val))
		return -1;
	*flag = _flag;
	return 0;
}

static int parse_sa_flags(struct cli_conn *conn, char *str,
	struct ofp_sad_entry *sa)
{
	char *tkn, *fname;

	if (!token_match_array(str, ipsec_flags_array_str))
		return -1;

	tkn = strsep(&str, ":");

	while ((tkn = strsep(&str, ":")) != NULL) {
		PARSE_LOG(conn->fd, "%s: tkn = |%s|\r\n", __FUNCTION__, tkn);

		fname = strsep(&tkn, "=");
		PARSE_LOG(conn->fd, "%s: flag_name = |%s|\r\n", __FUNCTION__, fname);

		if (!strcmp(fname, "seq_ovf")) {
			if (parse_bool_flag(conn, tkn, &sa->seq_number_overflow)) {
				ofp_sendf(conn->fd,
					"Invalid sequence overflow value: %s\r\n",
					tkn);
				return -1;
			}
		} else if (!strcmp(fname, "auth_cipher")) {
			if (parse_bool_flag(conn, tkn, &sa->auth_cipher)) {
				ofp_sendf(conn->fd,
					"Invalid auth_cipher value: %s\r\n",
					tkn);
				return -1;
			}
		} else if (*fname == '\0')
			break;
		else
			return -1;
	}

	return 0;
}

static int parse_binary_str(struct cli_conn *conn, char *str,
	uint8_t *buff, uint32_t *len)
{
	uint32_t i;

	if (str[0] == '"') {			/* "form"*/
		str += 1;

		for (i = 0; (str[i] != '\0') && (str[i] != '"'); i++)
			*(buff + i) = (uint8_t)str[i];
		*len = i;
	} else if (!strncmp(str, "0x", 2)) {	/* 0xffd.. form*/
		char tmp_str[3];

		str += 2;
		if (strlen(str) % 2) {
			ofp_sendf(conn->fd,
				"Hex string has odd number of digits: %s\r\n",
				str);
			return -1;
		}
		tmp_str[2] = 0;
		for (i = 0; str[i] != '\0'; i += 2) {
			tmp_str[0] = str[i];
			tmp_str[1] = str[i + 1];
			*(buff + i / 2) = ofp_hex_to_num(tmp_str);
		}
		*len = i / 2;
	} else
		return -1;

	return 0;
}

static int parse_algo_auth(struct cli_conn *conn, char *str,
	struct ofp_sad_entry *sa)
{
	char *tkn;

	tkn = strsep(&str, ":");
	PARSE_LOG(conn->fd, "%s: alg = |%s|\r\n", __FUNCTION__, tkn);

	if (token_string_to_val(tkn, &sa->auth_alg,
		alg_auth_array_str, alg_auth_array_val))
		return -1;

	if (sa->auth_alg == OFP_AUTH_ALG_NULL)
		return 0;

	tkn = strsep(&str, ":");
	PARSE_LOG(conn->fd, "%s: key = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_binary_str(conn, tkn, sa->auth_key.data,
		&sa->auth_key.length))
		return -1;

	return 0;
}

static int parse_algo_enc(struct cli_conn *conn, char *str,
	struct ofp_sad_entry *sa)
{
	char *tkn;

	tkn = strsep(&str, ":");
	PARSE_LOG(conn->fd, "%s: alg = |%s|\r\n", __FUNCTION__, tkn);

	if (token_string_to_val(tkn, &sa->cipher_alg,
		alg_enc_array_str, alg_enc_array_val))
		return -1;

	if (sa->cipher_alg == OFP_CIPHER_ALG_NULL)
		return 0;

	tkn = strsep(&str, ":");
	if (!tkn)
		return -1;
	PARSE_LOG(conn->fd, "%s: key = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_binary_str(conn, tkn, sa->cipher_key.data,
		&sa->cipher_key.length))
		return -1;

	tkn = strsep(&str, ":");
	if (tkn) {
		PARSE_LOG(conn->fd, "%s: iv = |%s|\r\n", __FUNCTION__, tkn);
		if (parse_binary_str(conn, tkn, sa->cipher_iv.data,
			&sa->cipher_iv.length))
			return -1;
	} else
		sa->cipher_iv.length = 0;

	return 0;
}

static int parse_algorithms(struct cli_conn *conn, char **str,
	struct ofp_sad_entry *sa)
{
	char *str_iter = *str;
	char *tkn;

	(void)sa;
	PARSE_LOG(conn->fd, "%s: s = |%s|\r\n", __FUNCTION__, str_iter);

/*Authentication algorithm*/
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: auth alg = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_algo_auth(conn, tkn, sa)) {
		ofp_sendf(conn->fd, "Invalid authentication algorithm: %s\r\n",
			tkn);
		return -1;
	}

/*Encryption algorithm*/
	tkn = strsep(&str_iter, " ");
	PARSE_LOG(conn->fd, "%s: encrypt alg = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_algo_enc(conn, tkn, sa)) {
		ofp_sendf(conn->fd, "Invalid encryption algorithm: %s\r\n",
			tkn);
		return -1;
	}

	*str = str_iter;
	return 0;
}

void f_ipsec_sadadd_in(struct cli_conn *conn, const char *s)
{
	char *sbuf, *itr, *tkn;
	struct ofp_sad_entry sa;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_IN;

	PARSE_LOG(conn->fd, "sadadd in = |%s|\r\n", s);

	ofp_ipsec_sad_entry_init(&sa);

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sa.trivial_selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* Protect protocol */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: protocol = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_protocol(tkn, &sa.protocol)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid protect protocol!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* Protect mode */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: mode = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_policy_mode(tkn, &sa.incoming_protect_mode)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid protect mode!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* SPI */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: SPI = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_spi(tkn, &sa.spi)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid SPI!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* flags */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: flags = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_sa_flags(conn, tkn, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid SA flags!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
/* algorithms */
	if (parse_algorithms(conn, &itr, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid algorithms!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_sad_add(dir, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security association!");
	} else
		OFP_INFO("Security association added successfuly.");

	sendcrlf(conn);
}

void f_ipsec_sadadd_out(struct cli_conn *conn, const char *s)
{
	char *sbuf, *itr, *tkn;
	struct ofp_sad_entry sa;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_OUT;

	PARSE_LOG(conn->fd, "sadadd out = |%s|\r\n", s);

	ofp_ipsec_sad_entry_init(&sa);

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}

	if (parse_selectors(conn, &itr, &sa.trivial_selectors)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to parse selectors!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* Protect protocol */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: protocol = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_protocol(tkn, &sa.protocol)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid protect protocol!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* SPI */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: SPI = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_spi(tkn, &sa.spi)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid SPI!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}

/* flags */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: flags = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_sa_flags(conn, tkn, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid SA flags!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
/* algorithms */
	if (parse_algorithms(conn, &itr, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid algorithms!");
		free(sbuf);
		sendcrlf(conn);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_sad_add(dir, &sa)) {
		IPSEC_CLI_ERR(conn->fd, "Failed to add security association!");
	} else
		OFP_INFO("Security association added successfuly.");

	sendcrlf(conn);
}

static int parse_saddel_common(struct cli_conn *conn, char **str_sa,
	struct ofp_ipsec_selectors *sl,
	enum ofp_ipsec_protocol *protocol,
	uint32_t *spi)
{
	char *itr = *str_sa;
	char *tkn;

	ofp_ipsec_selectors_init(sl);

/* Trivial selectors */
	if (parse_selectors(conn, &itr, sl)) {
		ofp_sendf(conn->fd, "Failed to parse selectors!");
		return -1;
	}

/* Protect protocol */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: protocol = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_protocol(tkn, protocol)) {
		ofp_sendf(conn->fd, "Invalid protect protocol!");
		return -1;
	}

/* SPI */
	tkn = strsep(&itr, " ");
	PARSE_LOG(conn->fd, "%s: SPI = |%s|\r\n", __FUNCTION__, tkn);
	if (parse_spi(tkn, spi)) {
		ofp_sendf(conn->fd, "Invalid SPI!");
		return -1;
	}

	*str_sa = itr;
	return 0;
}

void f_ipsec_saddel_in(struct cli_conn *conn, const char *s)
{
	char *sbuf, *itr;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_IN;
	struct ofp_ipsec_selectors sl;
	enum ofp_ipsec_protocol protocol;
	uint32_t spi;

	PARSE_LOG(conn->fd, "saddel in = |%s|\r\n", s);

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}
	if (parse_saddel_common(conn, &itr, &sl, &protocol, &spi)) {
		IPSEC_CLI_ERR(conn->fd, "Parameter parsing has failed!");
		sendcrlf(conn);
		free(sbuf);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_sad_del(dir, &sl, spi, protocol))
		IPSEC_CLI_ERR(conn->fd, "Failed to delete security association!");
	else
		OFP_INFO("Security association deleted successfuly.");

	sendcrlf(conn);
}
void f_ipsec_saddel_out(struct cli_conn *conn, const char *s)
{
	char *sbuf, *itr;
	enum ofp_ipsec_direction dir = OFP_IPSEC_DIRECTION_OUT;
	struct ofp_ipsec_selectors sl;
	enum ofp_ipsec_protocol protocol;
	uint32_t spi;

	PARSE_LOG(conn->fd, "saddel out = |%s|\r\n", s);

	itr = sbuf = strdup(s);
	if (!sbuf) {
		IPSEC_CLI_ERR(conn->fd, "Memory allocation failed!");
		sendcrlf(conn);
		return;
	}
	if (parse_saddel_common(conn, &itr, &sl, &protocol, &spi)) {
		IPSEC_CLI_ERR(conn->fd, "Parameter parsing has failed!");
		sendcrlf(conn);
		free(sbuf);
		return;
	}
	free(sbuf);

	if (ofp_ipsec_sad_del(dir, &sl, spi, protocol))
		IPSEC_CLI_ERR(conn->fd, "Failed to delete security association!");
	else
		OFP_INFO("Security association deleted successfuly.");

	sendcrlf(conn);
}

void f_ipsec_sadflush(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_sad_flush())
		IPSEC_CLI_ERR(conn->fd, "Failed to flush SADs\r\n");
	else
		OFP_INFO("Security association database successfuly flushed");

	sendcrlf(conn);
}


static void flags_seq_ovf_dump(int fd, odp_bool_t *val)
{
	ofp_sendf(fd, "seq_ovf=%s", (*val)? "true":"false");
}
static void flags_auth_cipher_dump(int fd, odp_bool_t *val)
{
	ofp_sendf(fd, "auth_cipher=%s", (*val)? "true":"false");
}

static void sa_flags_dump(int fd, struct ofp_sad_entry *sa)
{
	ofp_sendf(fd, " %s", ipsec_flags_array_str[0]);
	flags_seq_ovf_dump(fd, &sa->seq_number_overflow);
	ofp_sendf(fd, ":");
	flags_auth_cipher_dump(fd, &sa->auth_cipher);
}

static void binary_str_dump(int fd, uint8_t *buff, uint32_t len)
{
	uint32_t i;

	ofp_sendf(fd, "0x");
	for (i = 0; i < len; i++)
		ofp_sendf(fd, "%.2x", *(buff + i));
}

static void sa_algo_auth_dump(int fd,
	ofp_auth_alg_t		*auth_alg,
	struct ofp_ipsec_key	*auth_key)
{
	const char *str = token_val_to_string(*auth_alg,
		alg_auth_array_str, alg_auth_array_val);
	if (str)
		ofp_sendf(fd, " %s", str);
	else
		ofp_sendf(fd, " error");

	if (*auth_alg == OFP_AUTH_ALG_NULL)
		return;

	ofp_sendf(fd, ":");
	binary_str_dump(fd, auth_key->data, auth_key->length);
}

static void sa_algo_enc_dump(int 	fd,
	ofp_cipher_alg_t		*cipher_alg,
	struct ofp_ipsec_key		*cipher_key,
	struct ofp_ipsec_cipher_iv	*cipher_iv)
{
	const char *str = token_val_to_string(*cipher_alg,
		alg_enc_array_str, alg_enc_array_val);
	if (str)
		ofp_sendf(fd, " %s", str);
	else
		ofp_sendf(fd, " error");

	if (*cipher_alg == OFP_CIPHER_ALG_NULL)
		return;

	ofp_sendf(fd, ":");
	binary_str_dump(fd, cipher_key->data, cipher_key->length);

	if (cipher_iv->length) {
		ofp_sendf(fd, ":");
		binary_str_dump(fd, cipher_iv->data, cipher_iv->length);
	}
}

static void sa_algorithms_dump(int fd, struct ofp_sad_entry *sa)
{
	ofp_sendf(fd, " -A");
	sa_algo_auth_dump(fd, &sa->auth_alg, &sa->auth_key);

	ofp_sendf(fd, " -E");
	sa_algo_enc_dump(fd, &sa->cipher_alg, &sa->cipher_key, &sa->cipher_iv);
}

void sa_dump(int fd, void *_sa, int inbound)
{
	struct ofp_sad_entry *sa = (struct ofp_sad_entry *)_sa;

/* selector*/
	selector_dump(fd, &sa->trivial_selectors, 1);

/* protocol */
	protocol_dump(fd, &sa->protocol);

/* mode */
	if (inbound) {
		ofp_sendf(fd, " ");
		mode_dump(fd, &sa->incoming_protect_mode);
	}

/* SPI */
	ofp_sendf(fd, " %d", sa->spi);

/* flags */
	sa_flags_dump(fd, sa);

/* algorithms */
	sa_algorithms_dump(fd, sa);

/* direction*/
	if (inbound)
		ofp_sendf(fd, " in");
	else
		ofp_sendf(fd, " out");
}

void f_ipsec_saddump(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_sad_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd, "Failed to dump SADs\r\n");
	else
		OFP_INFO("Security association database successfuly dumped.");
	sendcrlf(conn);
}

void f_ipsec_cacheflush_in(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_cache_in_flush())
		IPSEC_CLI_ERR(conn->fd,
			"Failed to flush inbound cache entries\r\n");
	else
		OFP_INFO("Inbound cache entries successfuly flushed.");
	sendcrlf(conn);
}

void f_ipsec_cacheflush_out(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_cache_out_flush())
		IPSEC_CLI_ERR(conn->fd,
			"Failed to flush outbound cache entries\r\n");
	else
		OFP_INFO("Outbound cache entries successfuly flushed.");
	sendcrlf(conn);
}

void cachein_dump(int fd, void *_entry)
{
	struct ofp_ipsec_cache_in_entry *entry =
		(struct ofp_ipsec_cache_in_entry *)_entry;

/* SPI */
	ofp_sendf(fd, " %d", entry->spi);

/* protocol */
	protocol_dump(fd, &entry->protocol);

/* SAD check selectors */
	selector_dump(fd, &entry->check_selectors, 1);

/* protect mode */
	ofp_sendf(fd, " ");
	mode_dump(fd, &entry->protect_mode);

/* Seq number */
	ofp_sendf(fd, " Seq: %d", entry->seq_number);

/* Flags */
	ofp_sendf(fd, " ");
	flags_seq_ovf_dump(fd, &entry->seq_number_overflow);
	ofp_sendf(fd, ":");
	flags_auth_cipher_dump(fd, &entry->algs.auth_cipher);

/* Authentication algorithms*/
	ofp_sendf(fd, " -A");
	sa_algo_auth_dump(fd, &entry->algs.auth_alg, &entry->algs.auth_key);

/* Encryption algorithms*/
	ofp_sendf(fd, " -E");
	sa_algo_enc_dump(fd, &entry->algs.cipher_alg, &entry->algs.cipher_key,
		&entry->algs.cipher_iv);
}

void f_ipsec_cachedump_in(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_cache_in_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd,
			"Failed to dump inbound cache entries\r\n");
	else
		OFP_INFO("Inbound cache entries successfuly dumped.");
	sendcrlf(conn);
}

void cacheout_dump(int fd, void *_entry)
{
	struct ofp_ipsec_cache_out_entry *entry =
		(struct ofp_ipsec_cache_out_entry *)_entry;

/* Selectors */
	selector_dump(fd, &entry->trivial_selectors, 1);

/* Action*/
	action_dump(fd, &entry->action);

	if (entry->action != OFP_SPD_ACTION_PROTECT)
		return;

/* SPI */
	ofp_sendf(fd, " %d", entry->_protect.spi);

/* protocol */
	protocol_dump(fd, &entry->_protect.protocol);

/* protect mode */
	ofp_sendf(fd, "/");
	mode_dump(fd, &entry->_protect.protect_mode);

/* tunnel addresses*/
	if (entry->_protect.protect_mode == OFP_IPSEC_MODE_TUNNEL) {
		ofp_sendf(fd, "/");
		addr_dump(fd, &entry->_protect.protect_tunnel_src_addr);
		ofp_sendf(fd, "-");
		addr_dump(fd, &entry->_protect.protect_tunnel_dest_addr);
	}

/* Seq number */
	ofp_sendf(fd, " Seq: %d", entry->_protect.seq_number);

/* Flags */
	ofp_sendf(fd, " ");
	flags_seq_ovf_dump(fd, &entry->_protect.seq_number_overflow);
	ofp_sendf(fd, ":");
	flags_auth_cipher_dump(fd, &entry->_protect.algs.auth_cipher);

/* Authentication algorithms*/
	ofp_sendf(fd, " -A");
	sa_algo_auth_dump(fd, &entry->_protect.algs.auth_alg,
		&entry->_protect.algs.auth_key);

/* Encryption algorithms*/
	ofp_sendf(fd, " -E");
	sa_algo_enc_dump(fd, &entry->_protect.algs.cipher_alg,
		&entry->_protect.algs.cipher_key, &entry->_protect.algs.cipher_iv);
}

void f_ipsec_cachedump_out(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_cache_out_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd,
			"Failed to dump outbound cache entries\r\n");
	else
		OFP_INFO("Outbound cache entries successfuly dumped.");
	sendcrlf(conn);
}

void f_ipsec_cacheupdate_in(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_sad_update_cache_in())
		IPSEC_CLI_ERR(conn->fd, "Failed to update inbound cache\r\n");
	else
		OFP_INFO("Inbound cache successfuly updated.");
	sendcrlf(conn);
}
void f_ipsec_cacheupdate_out(struct cli_conn *conn, const char *s)
{
	(void)s;
	if (ofp_ipsec_sad_update_cache_out())
		IPSEC_CLI_ERR(conn->fd, "Failed to update outbound cache\r\n");
	else
		OFP_INFO("Outbound cache successfuly updated.");
	sendcrlf(conn);
}



static int f_ipsec_global_config_dump(struct cli_conn *conn, const char *s)
{
	struct ofp_ipsec_conf *conf = NULL;

	(void)s;

	conf = ofp_ipsec_config_get();
	if (!conf)
		return -1;

	ofp_sendf(conn->fd, "Global settings:\r\n");
	ofp_sendf(conn->fd, "  Sync/async mode: %s\r\n",
		conf->param.async_mode? "async":"sync");
	if (conf->param.async_mode) {
		ofp_sendf(conn->fd, "  Asynchronous completion queue count: %d\r\n",
			conf->param.async_queue_cnt);
		ofp_sendf(conn->fd, "  Asynchronous completion queue allocation: ");
		switch (conf->param.async_queue_alloc) {
		case OFP_ASYNC_QUEUE_ALLOC_ROUNDROBIN:
			ofp_sendf(conn->fd, "Roundrobin");
			break;
		case OFP_ASYNC_QUEUE_ALLOC_CORE:
			ofp_sendf(conn->fd, "Core");
			break;
		default:
			ofp_sendf(conn->fd, "error");
		}
		ofp_sendf(conn->fd, "\r\n");
	}
	ofp_sendf(conn->fd, "  Output buffer pool: %s\r\n",
		conf->param.output_pool == ODP_POOL_INVALID? "none" : "set");
	ofp_sendf(conn->fd, "\r\n");

	return 0;
}

void f_ipsec_show(struct cli_conn *conn, const char *s)
{
	if (f_ipsec_global_config_dump(conn, s))
		IPSEC_CLI_ERR(conn->fd,
			"Failed to dump IPsec global settings\r\n");
	else
		OFP_INFO("IPsec global settings successfuly dumped.");

	ofp_show_interfaces_ipsec(conn->fd);

	if (ofp_ipsec_spd_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd, "Failed to dump SPDs\r\n");
	else
		OFP_INFO("Security policy database successfuly dumped.");

	ofp_sendf(conn->fd, "\r\n");

	if (ofp_ipsec_sad_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd, "Failed to dump SADs\r\n");
	else
		OFP_INFO("Security association database successfuly dumped.");

	ofp_sendf(conn->fd, "\r\n");

	if (ofp_ipsec_cache_in_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd,
			"Failed to dump inbound cache entries\r\n");
	else
		OFP_INFO("Inbound cache entries successfuly dumped.");

	ofp_sendf(conn->fd, "\r\n");

	if (ofp_ipsec_cache_out_dump(conn->fd))
		IPSEC_CLI_ERR(conn->fd,
			"Failed to dump outbound cache entries\r\n");
	else
		OFP_INFO("Outbound cache entries successfuly dumped.");

	sendcrlf(conn);
}


void f_ipsec_flush(struct cli_conn *conn, const char *s)
{
	(void)s;

	if (ofp_ipsec_spd_flush())
		IPSEC_CLI_ERR(conn->fd, "Failed to flush SPDs\r\n");
	else
		OFP_INFO("Security policy database successfuly flushed");

	if (ofp_ipsec_sad_flush())
		IPSEC_CLI_ERR(conn->fd, "Failed to flush SADs\r\n");
	else
		OFP_INFO("Security association database successfuly flushed");

	if (ofp_ipsec_cache_in_flush())
		IPSEC_CLI_ERR(conn->fd,
			"Failed to flush inbound cache entries\r\n");
	else
		OFP_INFO("Inbound cache entries successfuly flushed.");

	if (ofp_ipsec_cache_out_flush())
		IPSEC_CLI_ERR(conn->fd,
			"Failed to flush outbound cache entries\r\n");
	else
		OFP_INFO("Outbound cache entries successfuly flushed.");

	sendcrlf(conn);
}

void f_ipsec_help(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd, "Show IPsec configuration:\r\n"
		"  ipsec dump\r\n\r\n");

	ofp_sendf(conn->fd, "Flush IPsec configuration:\r\n"
		"  ipsec flush\r\n\r\n");

	ofp_sendf(conn->fd, "Add IPsec Security policy:\r\n"
		"  ipsec spdadd SRC_ADDR_RGS DEST_ADDR_RGS NLP NLPD -P DIRECTION ACTION OUT_PROTECT_POLICY\r\n"
		"    SRC_ADDR_RGS: Source addresses in list of ranges format\r\n"
		"      SRC_ADDR_RGS: ADDR_RG,ADDR_RG\r\n"
		"      ADDR_RG: START_ADDR-END_ADDR | ADDR\r\n"
		"    DEST_ADDR_RGS: Destination addresses in list of ranges format\r\n"
		"      DEST_ADDR_RGS: ADDR_RG,ADDR_RG\r\n"
		"    NLP: Next layer protocol\r\n"
		"      NLP: NUMBER | any | opaque\r\n"
		"    NLPD: Next layer protocol dependent\r\n"
		"      NLPD: none | PORTS | ICMP\r\n"
		"      PORTS: ports:SRC_PORTS_RGS:DEST_PORTS_RGS\r\n"
		"      SRC_PORTS_RGS: any | opaque | PORT_RG,PORT_RG...\r\n"
		"      DEST_PORTS_RGS: any | opaque | PORT_RG,PORT_RG...\r\n"
		"      PORT_RG: START_PORT-END_PORT | PORT\r\n"
		"      ICMP: icmp:ICMP_TYPE:ICMP_CODES\r\n"
		"      ICMP_TYPE: any | NUMBER\r\n"
		"      ICMP_CODES: any | CODE_RGS\r\n"
		"      CODE_RGS: CODE_RG,CODE_RG,...\r\n"
		"      CODE_RG: START_CODE-END_CODE | CODE\r\n"
		"    DIRECTION: Direction\r\n"
		"      DIRECTION: in | out\r\n");
	ofp_sendf(conn->fd,
		"    ACTION: Policy action\r\n"
		"      ACTION: protect | discard | bypass\r\n"
		"    OUT_PROTECT_POLICY: Protect policy parameters\r\n"
		"      OUT_PROTECT_POLICY: PROTOCOL/MODE[/TUNNEL_ADDRS]\r\n"
		"      PROTOCOL: esp | ah\r\n"
		"      MODE: tunnel | transport\r\n"
		"      TUNNEL_ADDRS: SRC_ADDR-DEST_ADDR\r\n"
		"  Example:\r\n"
		"    ipsec spdadd 192.168.100.1-192.168.100.2,192.168.100.10-"
		"192.168.100.20 192.168.200.1-192.168.200.2 any "
		"ports:1000-2000:3000 -P out protect esp/tunnel/192.168.250.1-"
		"192.168.250.10"
		"\r\n\r\n");
	ofp_sendf(conn->fd, "Delete IPsec Security policy:\r\n"
		"  ipsec spddel SRC_ADDR_RGS DEST_ADDR_RGS NLP NLPD -P DIRECTION\r\n"
		"    SRC_ADDR_RGS: Source addresses in list of ranges format\r\n"
		"      SRC_ADDR_RGS: ADDR_RG,ADDR_RG\r\n"
		"      ADDR_RG: START_ADDR-END_ADDR | ADDR\r\n"
		"    DEST_ADDR_RGS: Destination addresses in list of ranges format\r\n"
		"      DEST_ADDR_RGS: ADDR_RG,ADDR_RG\r\n"
		"    NLP: Next layer protocol\r\n"
		"      NLP: NUMBER | any | opaque\r\n"
		"    NLPD: Next layer protocol dependent\r\n"
		"      NLPD: none | PORTS | ICMP\r\n"
		"      PORTS: ports:SRC_PORTS_RGS:DEST_PORTS_RGS\r\n"
		"      SRC_PORTS_RGS: any | opaque | PORT_RG,PORT_RG...\r\n"
		"      DEST_PORTS_RGS: any | opaque | PORT_RG,PORT_RG...\r\n"
		"      PORT_RG: START_PORT-END_PORT | PORT\r\n"
		"      ICMP: icmp:ICMP_TYPE:ICMP_CODES\r\n"
		"      ICMP_TYPE: any | NUMBER\r\n"
		"      ICMP_CODES: any | CODE_RGS\r\n"
		"      CODE_RGS: CODE_RG,CODE_RG,...\r\n"
		"      CODE_RG: START_CODE-END_CODE | CODE\r\n"
		"    DIRECTION: Direction\r\n"
		"      DIRECTION: in | out\r\n");
	ofp_sendf(conn->fd, "  Example:\r\n"
		"    ipsec spddel 192.168.100.1-192.168.100.2,192.168.100.10-"
		"192.168.100.20 192.168.200.1-192.168.200.2 any ports:"
		"1000-2000:3000 -P out"
		"\r\n\r\n");

	ofp_sendf(conn->fd, "Show IPsec SPD configuration:\r\n"
		"  ipsec spddump\r\n\r\n");

	ofp_sendf(conn->fd, "Flush IPsec SPD configuration:\r\n"
		"  ipsec spdflush\r\n\r\n");

	ofp_sendf(conn->fd, "Add IPsec Security association:\r\n"
		"  ipsec sadadd SRC_ADDR DEST_ADDR NLP NLPD PROTOCOL SPI SA_FLAGS -A IPSEC_AUTH -E IPSEC_ENC out\r\n"
		"  ipsec sadadd SRC_ADDR DEST_ADDR NLP NLPD PROTOCOL MODE SPI SA_FLAGS -A IPSEC_AUTH -E IPSEC_ENC in\r\n"
		"    SRC_ADDR: IP address in a.b.c.d format\r\n"
		"    DEST_ADDR: IP address in a.b.c.d format\r\n"
		"    NLP: Next layer protocol\r\n"
		"      NLP: NUMBER | any | opaque\r\n"
		"    NLPD: Next layer protocol dependent\r\n"
		"      NLPD: none | PORTS_T | ICMP_T\r\n"
		"      PORTS_T: ports:SRC_PORT:DEST_PORT\r\n"
		"      SRC_PORTS: NUMBER\r\n"
		"      DEST_PORT:  NUMBER\r\n"
		"      ICMP_T: icmp:ICMP_TYPE:ICMP_CODE\r\n"
		"      ICMP_TYPE: NUMBER\r\n"
		"      ICMP_CODE: NUMBER\r\n"
		"    PROTOCOL: esp | ah\r\n"
		"    MODE: tunnel | transport\r\n"
		"    SPI: NUMBER\r\n"
		"    SA_FLAGS: flags:[seq_ovf=BOOL_VAL][:auth_cipher=BOOL_VAL][:sync_mode=SYNC_VAL]\r\n"
		"      BOOL_VAL: true | false\r\n"
		"      SYNC_VAL: sync | async\r\n");
		ofp_sendf(conn->fd,
		"    IPSEC_AUTH: AUTH_ALG:KEY\r\n"
		"      AUTH_ALG: hmac-md5 | hmac-sha256-128 | aes128-gmac\r\n"
		"      KEY: BINARY_STR\r\n"
		"      BINARY_STR: \"text\" | 0xHEX\r\n"
		"    IPSEC_ENC: ENC_ALG:KEY[:IV]\r\n"
		"      ENC_ALG: des-cbc | 3des-cbc | aes128-cbc | aes128-gcm\r\n"
		"      KEY: BINARY_STR\r\n"
		"      IV: BINARY_STR\r\n"
		"      BINARY_STR: \"text\" | 0xHEX\r\n"
		"  Example:\r\n"
		"    ipsec sadadd 192.168.100.1 192.168.100.2 any "
		"ports:1000:3000 esp 100 flags:sync_mode=sync -A hmac-md5:0x12 "
		"-E 3des-cbc:0x13:0x11 out\r\n\r\n");

	ofp_sendf(conn->fd, "Delete IPsec Security association:\r\n"
		"  ipsec saddel SRC_ADDR DEST_ADDR NLP NLPD PROTOCOL SPI DIRECTION\r\n"
		"    SRC_ADDR: IP address in a.b.c.d format\r\n"
		"    DEST_ADDR: IP address in a.b.c.d format\r\n"
		"    NLP: Next layer protocol\r\n"
		"      NLP: NUMBER | any | opaque\r\n"
		"    NLPD: Next layer protocol dependent\r\n"
		"      NLPD: none | PORTS_T | ICMP_T\r\n"
		"      PORTS_T: ports:SRC_PORT:DEST_PORT\r\n"
		"      SRC_PORTS: NUMBER\r\n"
		"      DEST_PORT:  NUMBER\r\n"
		"      ICMP_T: icmp:ICMP_TYPE:ICMP_CODE\r\n"
		"      ICMP_TYPE: NUMBER\r\n"
		"      ICMP_CODE: NUMBER\r\n"
		"    PROTOCOL: esp | ah\r\n"
		"    SPI: NUMBER\r\n"
		"    DIRECTION: Direction\r\n"
		"      DIRECTION: in | out\r\n"
		"  Example:\r\n"
		"    ipsec saddel 192.168.100.1 192.168.100.2 any "
		"ports:1000:3000 esp 100 out\r\n\r\n");

	ofp_sendf(conn->fd, "Show IPsec SAD configuration:\r\n"
		"  ipsec saddump\r\n\r\n");

	ofp_sendf(conn->fd, "Flush IPsec SAD configuration:\r\n"
		"  ipsec sadflush\r\n\r\n");

	ofp_sendf(conn->fd, "Show IPsec CACHE entries:\r\n"
		"  ipsec cachedump DIRECTION\r\n"
		"    DIRECTION: in | out\r\n"
		"  Example:\r\n"
		"    ipsec cachedump in\r\n\r\n");

	ofp_sendf(conn->fd, "Flush IPsec CACHE entries:\r\n"
		"  ipsec cacheflush DIRECTION\r\n"
		"    DIRECTION: in | out\r\n"
		"  Example:\r\n"
		"    ipsec cacheflush in\r\n\r\n");

	ofp_sendf(conn->fd, "Update IPsec CACHE entries:\r\n"
		"  ipsec cacheupd DIRECTION\r\n"
		"    DIRECTION: in | out\r\n"
		"  Example:\r\n"
		"    ipsec cacheupd in\r\n\r\n");

	ofp_sendf(conn->fd, "Set IPsec protected/unprotected boundary:\r\n"
		"  ipsec boundary DEV true | false\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"  Example:\r\n"
		"    ipsec boundary %s0 true\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_sendf(conn->fd, "Print this help message:\r\n"
		"  ipsec help\r\n\r\n");
	sendcrlf(conn);
}

static struct ofp_ifnet *get_PHYS_port(struct cli_conn *conn, const char *dev)
{
	int port, vlan;

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (!PHYS_PORT(port)) {
		IPSEC_CLI_ERR(conn->fd, "Invalid interface: %s\r\n", dev);
		return NULL;
	}

	return ofp_get_ifnet(port, 0);
}

void f_ipsec_boundary_set(struct cli_conn *conn, const char *dev)
{
	struct ofp_ifnet *ifnet = get_PHYS_port(conn, dev);
	if (!ifnet) {
		IPSEC_CLI_ERR(conn->fd,
			"Failed to get interface: %s\r\n", dev);
		sendcrlf(conn);
		return;
	}
	ofp_ipsec_boundary_interface_set(ifnet, 1);
	sendcrlf(conn);
}

void f_ipsec_boundary_clr(struct cli_conn *conn, const char *dev)
{
	struct ofp_ifnet *ifnet = get_PHYS_port(conn, dev);
	if (!ifnet) {
		IPSEC_CLI_ERR(conn->fd,
			"Failed to get interface: %s\r\n", dev);
		sendcrlf(conn);
		return;
	}
	ofp_ipsec_boundary_interface_set(ifnet, 0);
	sendcrlf(conn);
}

int ofp_ipsec_nlp_token_ok(char *val)
{
	if (token_match_array(val, selector_type_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_nlp_dep_token_ok(char *val)
{
	if (token_match_array(val, selector_proto_dep_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_proto_token_ok(char *val)
{
	if (token_match_array(val, ipsec_proto_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_mode_token_ok(char *val)
{
	if (token_match_array(val, ipsec_mode_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_auth_token_ok(char *val)
{
	if (token_match_array(val, alg_auth_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_enc_token_ok(char *val)
{
	if (token_match_array(val, alg_enc_array_str))
		return 1;
	return 0;
}

int ofp_ipsec_flags_token_ok(char *val)
{
	if (token_match_array(val, ipsec_flags_array_str))
		return 1;
	return 0;
}
