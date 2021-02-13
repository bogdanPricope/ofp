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
#include "ofpi_print.h"

#define PASSWORD_LEN 32

#define NUM_OLD_BUFS 8

typedef enum {
	OFPCLI_CONN_TYPE_SOCKET_OS = 0,
	OFPCLI_CONN_TYPE_SOCKET_OFP,
	OFPCLI_CONN_TYPE_CNT
} ofpcli_connection_type_t;

/** cli_conn: CLI connection context
 */
struct cli_conn {
	int           status;
	ofp_print_t   pr;
	int           fd;
	char          inbuf[200];
	char          oldbuf[NUM_OLD_BUFS][200];
	int           old_put_cnt;
	int           old_get_cnt;
	unsigned int  pos;
	unsigned char ch1;
	char          passwd[PASSWORD_LEN + 1];
	int           close_cli;
	int           num_dsp_chars;
};

/** CLI Command descriptor
 */
struct cli_command {
	const char *command;
	const char *help;
	void (*func)(ofp_print_t *pr, const char *s);
};

/* API implementation */
int ofp_start_cli_thread_imp(int core_id, char *cli_file);
int ofp_stop_cli_thread_imp(void);
int ofp_cli_add_command_imp(const char *cmd, const char *help,
			    ofp_cli_cb_func func);

/** CLI parser
 */
int ofp_cli_parser_init(void);
void ofp_cli_parser_parse(struct cli_conn *conn, int extra);
int ofp_cli_parser_add_command(struct cli_command *cc);
void ofp_cli_parser_print_nodes(ofp_print_t *pr);

/** CLI IPsec
 */
int ofpcli_ipsec_init(void);

/** CLI operations
 */
int cli_init_commands(void);
void cli_process_file(char *file_name);
void close_connection(struct cli_conn *conn);
void close_connections(void);
struct cli_conn *cli_conn_accept(int fd, ofpcli_connection_type_t type);
int cli_conn_recv(struct cli_conn *conn, unsigned char c);

/** utils
 */
void sendcrlf(struct cli_conn *conn);
int ip4addr_get(const char *tk, uint32_t *addr);
int ip4net_get(const char *tk, uint32_t *addr, int *mask);
int ip6addr_get(const char *tk, int tk_len, uint8_t *addr);

/** commands
 */
void f_exit(ofp_print_t *pr, const char *s);
void f_route_show(ofp_print_t *pr, const char *s);
void f_route_add(ofp_print_t *pr, const char *s);
void f_route_add_v6(ofp_print_t *pr, const char *s);
void f_route_add_vrf(ofp_print_t *pr, const char *s);
void f_route_del(ofp_print_t *pr, const char *s);
void f_route_del_vrf(ofp_print_t *pr, const char *s);
void f_route_del_v6(ofp_print_t *pr, const char *s);
void f_route_add_dev_to_dev(ofp_print_t *pr, const char *s);
void f_help_route(ofp_print_t *pr, const char *s);

void f_debug(ofp_print_t *pr, const char *s);
void f_debug_show(ofp_print_t *pr, const char *s);
void f_debug_capture(ofp_print_t *pr, const char *s);
void f_debug_info(ofp_print_t *pr, const char *s);
void f_debug_print_file(ofp_print_t *pr, const char *s);
void f_debug_capture_file(ofp_print_t *pr, const char *s);
void f_help_debug(ofp_print_t *pr, const char *s);

void f_loglevel(ofp_print_t *pr, const char *s);
void f_help_loglevel(ofp_print_t *pr, const char *s);
void f_loglevel_show(ofp_print_t *pr, const char *s);

void f_arp(ofp_print_t *pr, const char *s);
void f_arp_flush(ofp_print_t *pr, const char *s);
void f_arp_cleanup(ofp_print_t *pr, const char *s);
void f_arp_add(ofp_print_t *pr, const char *s);
void f_help_arp(ofp_print_t *pr, const char *s);

void f_alias_set(ofp_print_t *pr, const char *s);
void f_alias_show(ofp_print_t *pr, const char *s);
void f_help_alias(ofp_print_t *pr, const char *s);
void f_run_alias(ofp_print_t *pr, const char *s);
int f_add_alias_command(const char *name);

void f_stat_show(ofp_print_t *pr, const char *s);
void f_stat_set(ofp_print_t *pr, const char *s);
void f_stat_perf(ofp_print_t *pr, const char *s);
void f_stat_clear(ofp_print_t *pr, const char *s);
void f_help_stat(ofp_print_t *pr, const char *s);

void f_ifconfig_show(ofp_print_t *pr, const char *s);
void f_help_ifconfig(ofp_print_t *pr, const char *s);
void f_ifconfig(ofp_print_t *pr, const char *s);
void f_ifconfig_v6(ofp_print_t *pr, const char *s);
void f_ifconfig_tun(ofp_print_t *pr, const char *s);
void f_ifconfig_vxlan(ofp_print_t *pr, const char *s);
void f_ifconfig_down(ofp_print_t *pr, const char *s);

void f_address_show(ofp_print_t *pr, const char *s);
void f_address_add(ofp_print_t *pr, const char *s);
void f_address_del(ofp_print_t *pr, const char *s);
void f_address_help(ofp_print_t *pr, const char *s);

void f_help_sysctl(ofp_print_t *pr, const char *s);
void f_sysctl_dump(ofp_print_t *pr, const char *s);
void f_sysctl_read(ofp_print_t *pr, const char *s);
void f_sysctl_write(ofp_print_t *pr, const char *s);

void f_help_netstat(ofp_print_t *pr, const char *s);
void f_netstat_all(ofp_print_t *pr, const char *s);
void f_netstat_tcp(ofp_print_t *pr, const char *s);
void f_netstat_udp(ofp_print_t *pr, const char *s);

void f_shutdown(ofp_print_t *pr, const char *s);
void f_help_shutdown(ofp_print_t *pr, const char *s);

#endif
