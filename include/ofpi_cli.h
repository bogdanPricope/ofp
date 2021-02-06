/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _CLI_H_
#define _CLI_H_

#include <stdint.h>
#include "ofpi_api_cli.h"

void ofpcli_ipsec_init(void);

#define PASSWORD_LEN 32

#define NUM_OLD_BUFS 8

/** cli_conn: CLI connection context
 */
struct cli_conn {
	int           status;
	int           fd;
	char          inbuf[200];
	char          oldbuf[NUM_OLD_BUFS][200];
	int           old_put_cnt;
	int           old_get_cnt;
	unsigned int  pos;
	unsigned char ch1;
	char          passwd[PASSWORD_LEN + 1];
	int           close_cli;
};

/** CLI Command descriptor
 */
struct cli_command {
	const char *command;
	const char *help;
	void (*func)(struct cli_conn *conn, const char *s);
};

/* API implementation */
int ofp_start_cli_thread_imp(int core_id, char *cli_file);
int ofp_stop_cli_thread_imp(void);
void ofp_cli_add_command_imp(const char *cmd, const char *help,
			     ofp_cli_cb_func func);
int ofp_cli_get_fd_imp(void *handle);

/** CLI parser
 */
void ofp_cli_parser_parse(struct cli_conn *conn, int extra);
void ofp_cli_parser_add_command(struct cli_command *cc);
void ofp_cli_parser_print_nodes(int fd);

/** utils
 */
void sendcrlf(struct cli_conn *conn);
void sendstr(struct cli_conn *conn, const char *s); /* To Change*/
int ip4addr_get(const char *tk, uint32_t *addr);
int ip4net_get(const char *tk, uint32_t *addr, int *mask);
int ip6addr_get(const char *tk, int tk_len, uint8_t *addr);

void cli_init_commands(void);
void cli_process_file(char *file_name);
void close_connections(void);
struct cli_conn *cli_conn_accept(int fd);
int cli_conn_recv(struct cli_conn *conn, unsigned char c);

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
void f_debug_print_file(struct cli_conn *conn, const char *s);
void f_debug_capture_file(struct cli_conn *conn, const char *s);
void f_help_debug(struct cli_conn *conn, const char *s);

void f_loglevel(struct cli_conn *conn, const char *s);
void f_help_loglevel(struct cli_conn *conn, const char *s);
void f_loglevel_show(struct cli_conn *conn, const char *s);

void f_arp(struct cli_conn *conn, const char *s);
void f_arp_flush(struct cli_conn *conn, const char *s);
void f_arp_cleanup(struct cli_conn *conn, const char *s);
void f_arp_add(struct cli_conn *conn, const char *s);
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

void f_address_show(struct cli_conn *conn, const char *s);
void f_address_add(struct cli_conn *conn, const char *s);
void f_address_del(struct cli_conn *conn, const char *s);
void f_address_help(struct cli_conn *conn, const char *s);

void f_help_sysctl(struct cli_conn *conn, const char *s);
void f_sysctl_dump(struct cli_conn *conn, const char *s);
void f_sysctl_read(struct cli_conn *conn, const char *s);
void f_sysctl_write(struct cli_conn *conn, const char *s);

void f_help_netstat(struct cli_conn *conn, const char *s);
void f_netstat_all(struct cli_conn *conn, const char *s);
void f_netstat_tcp(struct cli_conn *conn, const char *s);
void f_netstat_udp(struct cli_conn *conn, const char *s);

void f_shutdown(struct cli_conn *conn, const char *s);
void f_help_shutdown(struct cli_conn *conn, const char *s);

#endif
