/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _CLI_H_
#define _CLI_H_

#include <stdint.h>
#include "api/ofp_cli.h"

#define PASSWORD_LEN 32

#define NUM_OLD_BUFS 8

/** cli_conn: CLI connection context
 */
struct cli_conn {
	int           status;
	int           fd;
	char          inbuf[400];
	char          oldbuf[NUM_OLD_BUFS][400];
	int           old_put_cnt;
	int           old_get_cnt;
	unsigned int  pos;
	unsigned char ch1;
	char          passwd[PASSWORD_LEN + 1];
};

/** utils
 */
void sendcrlf(struct cli_conn *conn);
int ip4addr_get(const char *tk, uint32_t *addr);
int ip4net_get(const char *tk, uint32_t *addr, int *mask);
int ip6addr_get(const char *tk, int tk_len, uint8_t *addr);

int token_string_to_val(char *token, uint32_t *val,
	const char *array_str[], const uint32_t array_val[]);
int token_string_to_val_with_size(char *token, uint32_t *val,
	const char *array_str[], const uint32_t array_val[]);
const char* token_val_to_string(uint32_t token,
	const char *array_str[], const uint32_t array_val[]);
int token_match_array(char* token, const char *array_str[]);

/** commands
 */
void f_route_show(struct cli_conn *conn, const char *s);
void f_route_add(struct cli_conn *conn, const char *s);
void f_route_add_v6(struct cli_conn *conn, const char *s);
void f_route_add_vrf(struct cli_conn *conn, const char *s);
void f_route_del(struct cli_conn *conn, const char *s);
void f_route_del_vrf(struct cli_conn *conn, const char *s);
void f_route_del_v6(struct cli_conn *conn, const char *s);
void f_route_add_dev_to_dev(struct cli_conn *conn, const char *s);
void f_help_route(struct cli_conn *conn, const char *s);

void f_debug(struct cli_conn *conn, const char *s);
void f_debug_show(struct cli_conn *conn, const char *s);
void f_debug_capture(struct cli_conn *conn, const char *s);
void f_debug_info(struct cli_conn *conn, const char *s);
void f_debug_capture_file(struct cli_conn *conn, const char *s);
void f_help_debug(struct cli_conn *conn, const char *s);

void f_loglevel(struct cli_conn *conn, const char *s);
void f_help_loglevel(struct cli_conn *conn, const char *s);
void f_loglevel_show(struct cli_conn *conn, const char *s);

void f_arp(struct cli_conn *conn, const char *s);
void f_arp_flush(struct cli_conn *conn, const char *s);
void f_arp_cleanup(struct cli_conn *conn, const char *s);
void f_help_arp(struct cli_conn *conn, const char *s);

#define ALIAS_TABLE_LEN 16

struct alias_table_s {
	char *name;
	char *cmd;
};

extern struct alias_table_s alias_table[];
void f_alias_set(struct cli_conn *conn, const char *s);
void f_alias_show(struct cli_conn *conn, const char *s);
void f_help_alias(struct cli_conn *conn, const char *s);
void f_add_alias_command(const char *name);

void f_stat_show(struct cli_conn *conn, const char *s);
void f_stat_set(struct cli_conn *conn, const char *s);
void f_stat_perf(struct cli_conn *conn, const char *s);
void f_stat_clear(struct cli_conn *conn, const char *s);
void f_help_stat(struct cli_conn *conn, const char *s);

void f_ifconfig_show(struct cli_conn *conn, const char *s);
void f_help_ifconfig(struct cli_conn *conn, const char *s);
void f_ifconfig(struct cli_conn *conn, const char *s);
void f_ifconfig_v6(struct cli_conn *conn, const char *s);
void f_ifconfig_tun(struct cli_conn *conn, const char *s);
void f_ifconfig_vxlan(struct cli_conn *conn, const char *s);
void f_ifconfig_down(struct cli_conn *conn, const char *s);

void f_sysctl_dump(struct cli_conn *conn, const char *s);
void f_sysctl_read(struct cli_conn *conn, const char *s);
void f_sysctl_write(struct cli_conn *conn, const char *s);

#ifdef OFP_IPSEC
void f_ipsec_spdadd_in_bypass(struct cli_conn *conn, const char *s);
void f_ipsec_spdadd_in_discard(struct cli_conn *conn, const char *s);
void f_ipsec_spdadd_out_bypass(struct cli_conn *conn, const char *s);
void f_ipsec_spdadd_out_discard(struct cli_conn *conn, const char *s);
void f_ipsec_spdadd_out_protect(struct cli_conn *conn, const char *s);

void f_ipsec_spddel_in(struct cli_conn *conn, const char *s);
void f_ipsec_spddel_out(struct cli_conn *conn, const char *s);

void f_ipsec_spdflush(struct cli_conn *conn, const char *s);

void f_ipsec_spddump(struct cli_conn *conn, const char *s);
void sp_dump(int fd, void *sp);

void f_ipsec_sadadd_in(struct cli_conn *conn, const char *s);
void f_ipsec_sadadd_out(struct cli_conn *conn, const char *s);

void f_ipsec_saddel_in(struct cli_conn *conn, const char *s);
void f_ipsec_saddel_out(struct cli_conn *conn, const char *s);

void f_ipsec_sadflush(struct cli_conn *conn, const char *s);

void f_ipsec_saddump(struct cli_conn *conn, const char *s);
void sa_dump(int fd, void *sa, int inbound);

void f_ipsec_cacheflush_in(struct cli_conn *conn, const char *s);
void f_ipsec_cacheflush_out(struct cli_conn *conn, const char *s);

void f_ipsec_cachedump_in(struct cli_conn *conn, const char *s);
void cachein_dump(int fd, void *entry);

void f_ipsec_cachedump_out(struct cli_conn *conn, const char *s);
void cacheout_dump(int fd, void *entry);

void f_ipsec_cacheupdate_in(struct cli_conn *conn, const char *s);
void f_ipsec_cacheupdate_out(struct cli_conn *conn, const char *s);

void f_ipsec_show(struct cli_conn *conn, const char *s);

void f_ipsec_flush(struct cli_conn *conn, const char *s);

void f_ipsec_help(struct cli_conn *conn, const char *s);

void f_ipsec_boundary_set(struct cli_conn *conn, const char *s);
void f_ipsec_boundary_clr(struct cli_conn *conn, const char *s);

int ofp_ipsec_nlp_token_ok(char *val);
int ofp_ipsec_nlp_dep_token_ok(char *val);
int ofp_ipsec_proto_token_ok(char *val);
int ofp_ipsec_mode_token_ok(char *val);
int ofp_ipsec_auth_token_ok(char *val);
int ofp_ipsec_enc_token_ok(char *val);
int ofp_ipsec_flags_token_ok(char *val);

#endif /*OFP_IPSEC*/
#endif
