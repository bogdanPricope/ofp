/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>

#include <odp_api.h>

#include "ofp_errno.h"

#include "ofpi.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_cli.h"
#include "ofpi_cli_shm.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_portconf.h"

/*
 * Only core 0 runs this.
 */

/* status bits */
#define CONNECTION_ON		1
#define DO_ECHO			2 /* telnet */
#define DO_SUPPRESS		4 /* telnet */
#define WILL_SUPPRESS		8 /* telnet */
#define WAITING_TELNET_1	16
#define WAITING_TELNET_2	32
#define WAITING_ESC_1		64
#define WAITING_ESC_2		128
#define WAITING_PASSWD		256
#define ENABLED_OK		512

static struct cli_conn connection;

static __thread int ofp_run_alias = -1;

static uint8_t txt_to_hex(char val)
{
	if (val >= '0' && val <= '9')
		return(val - '0');
	if (val >= 'a' && val <= 'f')
		return(val - 'a' + 10);
	if (val >= 'A' && val <= 'F')
		return(val - 'A' + 10);

	return 255;
}

int ip4addr_get(const char *tk, uint32_t *addr)
{
	int a, b, c, d;

	if (sscanf(tk, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

int ip4net_get(const char *tk, uint32_t *addr, int *mask)
{
	int a, b, c, d;

	if (sscanf(tk, "%d.%d.%d.%d/%d", &a, &b, &c, &d, mask) < 5)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

int ip6addr_get(const char *tk, int tk_len, uint8_t *addr)
{
	const char *it, *last;
	const char *last_colon;
	const char *group_start;
	int group_cnt;
	int group_len;
	int dbl_colon_pos;
	int i;

	memset(addr, 0, 16);

	it = tk;
	last = it + tk_len;
	last_colon = NULL;
	group_cnt = 0;
	dbl_colon_pos = -1;

	while (it < last) {
		if ((*it) == ':') {
			if ((last_colon != NULL) &&
				(it - 1 == last_colon)) {
				if (dbl_colon_pos != -1)
					return 0;
				dbl_colon_pos = group_cnt;
			}
			last_colon = it;
			it++;
		} else if (((*it) >= '0' && (*it) <= '9') ||
			((*it) >= 'a' && (*it) <= 'f') ||
			((*it) >= 'A' && (*it) <= 'F')) {
			group_start = it;
			while ((it < last) &&
				(((*it) >= '0' && (*it) <= '9') ||
				((*it) >= 'a' && (*it) <= 'f') ||
				((*it) >= 'A' && (*it) <= 'F'))) {
					it++;
			}
			group_len = it - group_start;
			if ((group_len > 4) ||
				(group_len == 0))
				return 0;

			if (group_len >= 1)
				addr[group_cnt * 2 + 1] =
					txt_to_hex(*(it - 1));
			if (group_len >= 2)
				addr[group_cnt * 2 + 1] |=
					txt_to_hex(*(it - 2)) << 4;
			if (group_len >= 3)
				addr[group_cnt * 2] =
					txt_to_hex(*(it - 3));
			if (group_len == 4)
				addr[group_cnt * 2] |=
					txt_to_hex(*(it - 4)) << 4;

			group_cnt++;
		} else
			return 0;

	}

	if (dbl_colon_pos != -1) {
		for (i = 0; i < 16  - (dbl_colon_pos * 2); i++) {
			if (i < (group_cnt - dbl_colon_pos) * 2)
				addr[15 - i] =
					addr[group_cnt * 2 - 1 - i];
			else
				addr[15 - i] = 0;
		}
	}

	return 1;
}

void sendcrlf(struct cli_conn *conn)
{
	if ((conn->status & DO_ECHO) == 0)
		ofp_print(&conn->pr, "\n"); /* no extra prompts */
	else if (conn->status & ENABLED_OK)
		ofp_print(&conn->pr, "\r\n# ");
	else
		ofp_print(&conn->pr, "\r\n> ");
}

static void sendprompt(struct cli_conn *conn)
{
	if (conn->status & ENABLED_OK)
		ofp_print(&conn->pr, "\r# ");
	else
		ofp_print(&conn->pr, "\r> ");
}

static void cli_send_welcome_banner(ofp_print_t *pr)
{
	ofp_print(pr,
		  "\r\n"
		  "--==--==--==--==--==--==--\r\n"
		  "-- WELCOME to OFP CLI --\r\n"
		  "--==--==--==--==--==--==--\r\n"
		  );
}

static void cli_send_goodbye_banner(ofp_print_t *pr)
{
	ofp_print(pr,
		  "\r\n"
		  "--==--==--==--\r\n"
		  "-- Goodbye! --\r\n"
		  "--==--==--==--\r\n"
		  );
}

/***********************************************
 * Functions to be called.                     *
 ***********************************************/

void f_exit(ofp_print_t *pr, const char *s)
{
	(void)s;
	cli_send_goodbye_banner(pr);
}

static void f_help(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr, "Display help information for CLI commands:\r\n"
		"  help <command>\r\n"
		"    command: alias, address, arp, debug, exit, ifconfig, ");
	ofp_print(pr, "ipsec, loglevel, netstat, route, show, shutdown,");
	ofp_print(pr, " stat, sysctl\r\n\r\n");
}

static void f_help_exit(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr, "Exit closes the current connection.\r\n"
		"You can type ctl-D, too.");
}


static void f_help_show(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr, "Display current status:\r\n"
		"  show <command>\r\n"
		"    command: alias, address, arp, debug, ifconfig, ipsec, ");
	ofp_print(pr, "loglevel, netstat, route, stat, sysctl\r\n\r\n");
}

static int authenticate(const char *user, const char *passwd)
{
	(void)user;
	(void)passwd;
#if 0
	struct passwd *pw;
	char *epasswd;

	if ((pw = getpwnam(user)) == NULL) return 0;
	if (pw->pw_passwd == 0) return 1;
	epasswd = crypt(passwd, pw->pw_passwd);
	if (strcmp(epasswd, pw->pw_passwd)) return 0;
#endif
	return 1;
}


/*******************************************/

/* CLI Commands list */

/* Command Parameters are indicated by the following keywords:
 * NUMBER,IP4ADDR,TOPNAME,STRING,DEV,IP4NET
 */

struct cli_command commands[] = {
	{
		"exit",
		"Quit the connection",
		f_exit
	},
	{
		"quit",
		"Quit the connection",
		f_exit
	},
	{
		"show",
		"Display information",
		f_help_show
	},
	{
		"show help",
		"Display information",
		f_help_show
	},
	{
		"show arp",
		NULL,
		f_arp
	},
	{
		"show debug",
		NULL,
		f_debug_show
	},
	{
		"show loglevel",
		NULL,
		f_loglevel_show
	},
	{
		"show route",
		NULL,
		f_route_show
	},
	{
		"show alias",
		NULL,
		f_alias_show
	},
	{
		"show stat",
		NULL,
		f_stat_show
	},
	{
		"show ifconfig",
		NULL,
		f_ifconfig_show
	},
	{
		"show netstat",
		NULL,
		f_netstat_all
	},
	{
		"show address",
		NULL,
		f_address_show
	},
	{
		"show sysctl",
		NULL,
		f_sysctl_dump
	},
	{
		"debug",
		"Print traffic to file (and console) or to a pcap file",
		f_debug_show
	},
	{
		"debug NUMBER",
		"Bit mask of categories whose traffic to print (15 or 0xf for everything)",
		f_debug
	},
	{
		"debug help",
		"Print help",
		f_help_debug
	},
	{
		"debug show",
		"Show debug settings",
		f_debug_show
	},
	{
		"debug capture NUMBER",
		"Port mask whose traffic to save in pcap format (15 or 0xf for ports 0-3)",
		f_debug_capture
	},
	{
		"debug capture info NUMBER",
		"Non-zero = Include port number info by overwriting the first octet of dest MAC",
		f_debug_info
	},
	{
		"debug capture file STRING",
		"File to save captured packets",
		f_debug_capture_file
	},
	{
		"debug print file STRING",
		"File to save printed packets",
		f_debug_print_file
	},
	{
		"loglevel",
		"Show or set log level",
		f_loglevel_show
	},
	{
		"loglevel set STRING",
		"Set log level",
		f_loglevel
	},
	{
		"loglevel help",
		"Print help",
		f_help_loglevel
	},
	{
		"loglevel show",
		"Show log level",
		f_loglevel_show
	},
	{
		"help",
		NULL,
		f_help
	},
	{
		"help exit",
		NULL,
		f_help_exit
	},
	{
		"help show",
		NULL,
		f_help_show
	},
	{
		"help debug",
		NULL,
		f_help_debug
	},
	{
		"help loglevel",
		NULL,
		f_help_loglevel
	},
	{
		"help route",
		NULL,
		f_help_route
	},
	{
		"help arp",
		NULL,
		f_help_arp
	},
	{
		"help alias",
		NULL,
		f_help_alias
	},
	{
		"help stat",
		NULL,
		f_help_stat
	},
	{
		"help ifconfig",
		NULL,
		f_help_ifconfig
	},
	{
		"help netstat",
		NULL,
		f_help_netstat
	},
	{
		"help sysctl",
		NULL,
		f_help_sysctl
	},
	{
		"help shutdown",
		NULL,
		f_help_shutdown
	},
	{
		"arp",
		"Show arp table",
		f_arp
	},
	{
		"arp flush",
		"Flush arp table",
		f_arp_flush
	},
	{
		"arp cleanup",
		"Clean old entries from arp table",
		f_arp_cleanup
	},
	{
		"arp set IP4ADDR MAC dev DEV",
		"Add static entry to arp table",
		f_arp_add
	},
	{
		"arp help",
		NULL,
		f_help_arp
	},
	{
		"route",
		"Show route table",
		f_route_show
	},
	{
		"route show",
		"Show route table",
		f_route_show
	},
	{
		"route add IP4NET gw IP4ADDR dev DEV",
		"Add route",
		f_route_add
	},
	{
		"route -A inet4 add IP4NET gw IP4ADDR dev DEV",
		"Add route",
		f_route_add
	},
#ifdef INET6
	{
		"route -A inet6 add IP6NET gw IP6ADDR dev DEV",
		"Add route",
		f_route_add_v6
	},
#endif /* INET6 */
	{
		"route add vrf NUMBER IP4NET gw IP4ADDR dev DEV",
		"Add route to VRF",
		f_route_add_vrf
	},
	{
		"route -A inet4 add vrf NUMBER IP4NET gw IP4ADDR dev DEV",
		"Add route to VRF",
		f_route_add_vrf
	},
	{
		"route delete IP4NET",
		"Delete route",
		f_route_del
	},
	{
		"route -A inet4 delete IP4NET",
		"Delete route",
		f_route_del
	},
	{
		"route delete vrf NUMBER IP4NET",
		"Delete route",
		f_route_del_vrf
	},
	{
		"route -A inet4 delete vrf NUMBER IP4NET",
		"Delete route",
		f_route_del_vrf
	},
#ifdef INET6
	{
		"route -A inet6 delete IP6NET",
		"Delete route",
		f_route_del_v6
	},
#endif /* INET6 */
	{
		"route add from DEV to DEV",
		"Add route from interface to interface",
		f_route_add_dev_to_dev
	},
	{
		"route help",
		NULL,
		f_help_route
	},
	{
		"ifconfig",
		"Show interfaces",
		f_ifconfig_show
	},
	{
		"ifconfig show",
		NULL,
		f_ifconfig_show
	},
	{
		"ifconfig DEV IP4NET",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig -A inet4 DEV IP4NET",
		"Create interface",
		f_ifconfig
	},
#ifdef INET6
	{
		"ifconfig -A inet6 DEV IP6NET",
		"Create interface",
		f_ifconfig_v6
	},
#endif /* INET6 */
	{
		"ifconfig DEV IP4NET vrf NUMBER",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig -A inet4 DEV IP4NET vrf NUMBER",
		"Create interface",
		f_ifconfig
	},
	{
		"ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR",
		"Create GRE tunnel interface",
		f_ifconfig_tun
	},
	{
		"ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR vrf NUMBER",
		"Create GRE tunnel interface",
		f_ifconfig_tun
	},
	{
		"ifconfig vxlan DEV group IP4ADDR dev DEV IP4NET",
		"Create VXLAN interface",
		f_ifconfig_vxlan
	},
	{
		"ifconfig DEV down",
		"Delete interface",
		f_ifconfig_down
	},
	{
		"ifconfig help",
		NULL,
		f_help_ifconfig
	},
	{
		"address add IP4NET DEV",
		"Add IP address to interface",
		f_address_add
	},
	{
		"address del IP4NET DEV",
		"Remove IP address to interface",
		f_address_del
	},
	{
		"address show",
		"Show IP addresses",
		f_address_show
	},
	{
		"help address",
		NULL,
		f_address_help
	},
	{
		"alias",
		NULL,
		f_alias_show
	},
	{
		"alias set STRING STRING",
		"Define an alias",
		f_alias_set
	},
	{
		"alias show",
		NULL,
		f_alias_show
	},
	{
		"alias help",
		NULL,
		f_help_alias
	},
	{
		"stat",
		"Show statistics",
		f_stat_show
	},
	{
		"stat show",
		NULL,
		f_stat_show
	},
	{
		"stat set NUMBER",
		NULL,
		f_stat_set
	},
	{
		"stat perf",
		NULL,
		f_stat_perf
	},
	{
		"stat clear",
		NULL,
		f_stat_clear
	},
	{
		"stat help",
		NULL,
		f_help_stat
	},
	{
		"sysctl",
		"Dump sysctl tree",
		f_sysctl_dump
	},
	{
		"sysctl dump",
		"Dump sysctl tree",
		f_sysctl_dump
	},
	{
		"sysctl r STRING",
		"Read sysctl variable",
		f_sysctl_read
	},
	{
		"sysctl w STRING STRING",
		"Set sysctl variable",
		f_sysctl_write
	},
	{
		"sysctl help",
		NULL,
		f_help_sysctl
	},
	{
		"netstat",
		"Show all open ports",
		f_netstat_all
	},
	{
		"netstat -t",
		"Show TCP open ports",
		f_netstat_tcp
	},
	{
		"netstat -u",
		"Show UDP open ports",
		f_netstat_udp
	},
	{
		"netstat help",
		NULL,
		f_help_netstat
	},
	{
		"shutdown",
		"Shutdown ofp",
		f_shutdown
	},
	{
		"shutdown help",
		NULL,
		f_help_shutdown
	},
	{ NULL, NULL, NULL }
};

void f_run_alias(ofp_print_t *pr, const char *s)
{
	uint32_t i;

	(void)pr;

	for (i = 0; i < V_cli_alias_table_size; i++) {
		if (V_cli_alias_table[i].name[0] == 0 ||
		    V_cli_alias_table[i].cmd[0] == 0)
			continue;
		if (strncmp(s, V_cli_alias_table[i].name,
			    strlen(V_cli_alias_table[i].name)) == 0) {
			ofp_run_alias = i;
			return;
		}
	}
}

int f_add_alias_command(const char *name)
{
	struct cli_command a;

	a.command = name;
	a.help = "Alias command";
	a.func = f_run_alias;
	return ofp_cli_parser_add_command(&a);
}

int ofp_cli_add_command_imp(const char *cmd, const char *help,
			    ofp_cli_cb_func func)
{
	int ret = 0;
	struct cli_command a;

	a.command = cmd;
	a.help = help;
	a.func = (void (*)(ofp_print_t *, const char *))func;

	odp_rwlock_write_lock(&V_cli_lock);
	ret = ofp_cli_parser_add_command(&a);
	odp_rwlock_write_unlock(&V_cli_lock);

	return ret;
}

int cli_init_commands(void)
{
	unsigned i = 0;

	ofp_cli_parser_init();

	/* Add regular commands */
	for (i = 0; commands[i].command; i++)
		if (ofp_cli_parser_add_command(&commands[i]))
			return -1;

	/* Add IPsec commands */
	if (ofpcli_ipsec_init())
		return -1;

	/* Print nodes */
	if (ofp_debug_logging_enabled()) {
		ofp_print_t pr;

		ofp_print_init(&pr, 1, OFP_PRINT_FILE);

	    ofp_print(&pr, "CLI Command nodes:\n");
		ofp_cli_parser_print_nodes(&pr);
	}

	return 0;
}

void cli_process_file(char *file_name)
{
	FILE *f;
	struct cli_conn conn;

	/* virtual connection */
	memset(&conn, 0, sizeof(conn));
	conn.fd = 1; /* stdout */
	conn.status = CONNECTION_ON; /* no prompt */
	ofp_print_init(&conn.pr, conn.fd, OFP_PRINT_FILE);

	if (file_name != NULL) {
		f = fopen(file_name, "r");
		if (!f) {
			OFP_ERR("OFP CLI file not found.\n");
			return;
		}

		while (fgets(conn.inbuf, sizeof(conn.inbuf), f)) {
			if (conn.inbuf[0] == '#' || conn.inbuf[0] <= ' ')
				continue;
			ofp_print(&conn.pr, "CLI: %s\n", conn.inbuf);
			ofp_cli_parser_parse(&conn, 0);
		}

		fclose(f);
	}
	else {
		OFP_DBG("OFP CLI file not set.\n");
	}
}

static char telnet_echo_off[] = {
	0xff, 0xfb, 0x01, /* IAC WILL ECHO */
	0xff, 0xfb, 0x03, /* IAC WILL SUPPRESS_GO_AHEAD */
	0xff, 0xfd, 0x03, /* IAC DO SUPPRESS_GO_AHEAD */
};

int cli_conn_recv(struct cli_conn *conn, unsigned char c)
{
	if (conn->status & WAITING_PASSWD) {
		unsigned int plen = strlen(conn->passwd);
		if (c == 10 || c == 13) {
			conn->status &= ~WAITING_PASSWD;
			if (authenticate("admin", conn->passwd)) {
				conn->status |= ENABLED_OK;
				sendcrlf(conn);
			} else {
				ofp_print(&conn->pr, "Your password fails!");
				sendcrlf(conn);
			}
		} else if (plen < (sizeof(conn->passwd)-1)) {
			conn->passwd[plen] = c;
			conn->passwd[plen+1] = 0;
		}
		return 0;
	} else if (conn->status & WAITING_TELNET_1) {
		conn->ch1 = c;
		conn->status &= ~WAITING_TELNET_1;
		conn->status |= WAITING_TELNET_2;
		return 0;
	} else if (conn->status & WAITING_TELNET_2) {
		if (conn->num_dsp_chars) {
			conn->num_dsp_chars--;
			if (conn->num_dsp_chars == 0)
				conn->status &= ~WAITING_TELNET_2;
			return 0;
		}

		if (conn->ch1 == 0xfd && c == 0x01) {
			conn->status |= DO_ECHO;
		} else if (conn->ch1 == 0xfd && c == 0x03) {
			conn->status |= DO_SUPPRESS;
		} else if (conn->ch1 == 0xfb && c == 0x03) {
			conn->status |= WILL_SUPPRESS;
			// ask for display size
			char com[] = {255, 253, 31};

			ofp_print_buffer(&conn->pr, com, sizeof(com));
		} else if (conn->ch1 == (unsigned char)0x251 && c == 31) {
			// IAC WILL NAWS (display size)
		} else if (conn->ch1 == 250 && c == 31) {
			// (display size info)
			conn->num_dsp_chars = 6;
			return 0;
		}
		conn->status &= ~WAITING_TELNET_2;
		return 0;
	} else if (conn->status & WAITING_ESC_1) {
		conn->ch1 = c;
		conn->status &= ~WAITING_ESC_1;
		conn->status |= WAITING_ESC_2;
		return 0;
	} else if (conn->status & WAITING_ESC_2) {
		conn->status &= ~WAITING_ESC_2;
		if (conn->ch1 != 0x5b)
			return 0;

		switch (c) {
		case 0x41: // up
			c = 0x10; /* arrow up = ctl-P */
			break;
		case 0x42: // down
			c = 0x0e; /* arrow down = ctl-N */
			break;
		case 0x44: // left
			c = 8;    /* arrow left = backspace */
			break;
		case 0x31: // home
		case 0x32: // ins
		case 0x33: // delete
		case 0x34: // end
		case 0x35: // pgup
		case 0x36: // pgdn
		case 0x43: // right
		case 0x45: // 5
			return 0;
		}
	}

	if (c == 4) { /* ctl-D */
		close_connection(conn);
		return 0;
	} else if (c == 0x10 || c == 0x0e) { /* ctl-P or ctl-N */
		strcpy(conn->inbuf, conn->oldbuf[conn->old_get_cnt]);
		if (c == 0x10) {
			conn->old_get_cnt--;
			if (conn->old_get_cnt < 0)
				conn->old_get_cnt = NUM_OLD_BUFS - 1;
		} else {
			conn->old_get_cnt++;
			if (conn->old_get_cnt >= NUM_OLD_BUFS)
				conn->old_get_cnt = 0;
		}
		conn->pos = strlen(conn->inbuf);
		ofp_print(&conn->pr, "\r                                      "
			  "                             ");
		sendprompt(conn);
		ofp_print(&conn->pr, conn->inbuf);
	} else if (c == 0x1b) {
		conn->status |= WAITING_ESC_1;
	} else if (c == 0xff) {
		/* telnet commands */
		conn->status |= WAITING_TELNET_1;
		/*
		  unsigned char c1, c2;
		  recv(conn->fd, &c1, 1, 0);
		  recv(conn->fd, &c2, 1, 0);
		  if      (c1 == 0xfd && c2 == 0x01) conn->status |= DO_ECHO;
		  else if (c1 == 0xfd && c2 == 0x03) conn->status |= DO_SUPPRESS;
		  else if (c1 == 0xfb && c2 == 0x03) conn->status |= WILL_SUPPRESS;
		*/
	} else if (c == 13 || c == 10) {
	char nl[] = {13, 10};
	if (conn->status & DO_ECHO)
		ofp_print_buffer(&conn->pr, nl, sizeof(nl));
	conn->inbuf[conn->pos] = 0;
	if (0 && conn->pos == 0) {
		strcpy(conn->inbuf, conn->oldbuf[conn->old_put_cnt]);
		conn->pos = strlen(conn->inbuf);
		ofp_print(&conn->pr, conn->inbuf);
		ofp_print_buffer(&conn->pr, nl, sizeof(nl));
	} else if (conn->pos > 0 && strcmp(conn->oldbuf[conn->old_put_cnt], conn->inbuf)) {
		conn->old_put_cnt++;
		if (conn->old_put_cnt >= NUM_OLD_BUFS)
			conn->old_put_cnt = 0;
		strcpy(conn->oldbuf[conn->old_put_cnt], conn->inbuf);
	}

	if (conn->pos) {
		ofp_cli_parser_parse(conn, 0);

		if (ofp_run_alias >= 0) {
			strcpy(conn->inbuf,
			       V_cli_alias_table[ofp_run_alias].cmd);
			ofp_run_alias = -1;
			ofp_cli_parser_parse(conn, 0);
		}
	} else
		sendcrlf(conn);

	conn->pos = 0;
	conn->inbuf[0] = 0;
	conn->old_get_cnt = conn->old_put_cnt;
	} else if (c == 8 || c == 127) {
		if (conn->pos > 0) {
			char bs[] = {8, ' ', 8};
			if (conn->status & DO_ECHO)
				ofp_print_buffer(&conn->pr, bs, sizeof(bs));
			conn->pos--;
			conn->inbuf[conn->pos] = 0;
		}
	} else if (c == '?' || c == '\t') {
		ofp_cli_parser_parse(conn, c);
	} else if (c >= ' ' && c < 127) {
		if (conn->pos < (sizeof(conn->inbuf) - 1)) {
			conn->inbuf[conn->pos++] = c;
			conn->inbuf[conn->pos] = 0;

			if (conn->status & DO_ECHO)
				ofp_print_buffer(&conn->pr, (char *)&c, 1);
		}
	}

	return 0;
}

static struct cli_conn *init_connection(ofpcli_connection_type_t type, int fd)
{
	struct cli_conn *conn = NULL;
	enum ofp_print_type print_type = OFP_PRINT_LINUX_SOCK;

	if (type == OFPCLI_CONN_TYPE_SOCKET_OS) {
		conn = &V_cli_connections[OFPCLI_CONN_TYPE_SOCKET_OS];
		print_type = OFP_PRINT_LINUX_SOCK;
	} else if (type == OFPCLI_CONN_TYPE_SOCKET_OFP) {
		conn = &V_cli_connections[OFPCLI_CONN_TYPE_SOCKET_OFP];
		print_type = OFP_PRINT_OFP_SOCK;
	} else {
		OFP_ERR("Error: Invalid connection type %d!\r\n", type);
		return NULL;
	}

	odp_memset(conn, 0, sizeof(*conn));

	conn->fd = fd;
	conn->status = 0;
	ofp_print_init(&conn->pr, fd, print_type);

	return conn;
}

struct cli_conn *cli_conn_accept(int fd, ofpcli_connection_type_t type)
{
	struct cli_conn *conn = NULL;

	conn = init_connection(type, fd);
	if (!conn) {
		OFP_ERR("Failed to initialize the CLI connection\r\n");
		return NULL;
	}

	ofp_print_buffer(&conn->pr, telnet_echo_off, sizeof(telnet_echo_off));

	cli_send_welcome_banner(&conn->pr);

	sendcrlf(conn);

	return conn;
}

void close_connection(struct cli_conn *conn)
{
	conn->close_cli = 1;
	OFP_DBG("Closing connection...\r\n");
}

void close_connections(void)
{
	struct cli_conn *conn = &connection;

	close_connection(conn);
}

/*end*/
