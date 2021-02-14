/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <odp_api.h>

#include "ofpi_cli.h"
#include "ofpi_route.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

/* route show */
void f_route_show(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_show_routes(pr, OFP_SHOW_ROUTES);
}

/* route add IP4NET gw IP4ADDR dev DEV */
/* route -A inet4 add IP4NET gw IP4ADDR dev DEV */
void f_route_add(ofp_print_t *pr, const char *s)
{
	uint32_t gwaddr, destaddr;
	int a, b, c, d, e, f, g, h, port, mlen, vlan;
	char dev[16];

	if (sscanf(s, "%d.%d.%d.%d/%d %d.%d.%d.%d %s",
		   &a, &b, &c, &d, &mlen,
		   &e, &f, &g, &h, dev) != 10)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	gwaddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_print(pr, "Invalid port!\r\n");
		return;
	}

	ofp_set_route_params(OFP_ROUTE_ADD, 0 /*vrf*/, vlan, port,
			     destaddr, mlen, gwaddr, OFP_RTF_GATEWAY);
}

/* route add vrf NUMBER IP4NET gw IP4ADDR dev DEV */
/* route -A inet4 add vrf NUMBER IP4NET gw IP4ADDR dev DEV */
void f_route_add_vrf(ofp_print_t *pr, const char *s)
{
	uint32_t gwaddr, destaddr;
	int a, b, c, d, e, f, g, h, port, mlen, vrf, vlan;
	char dev[16];

	if (sscanf(s, "%d %d.%d.%d.%d/%d %d.%d.%d.%d %s",
		   &vrf, &a, &b, &c, &d, &mlen,
		   &e, &f, &g, &h, dev) != 11)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	gwaddr = odp_cpu_to_be_32((e << 24) | (f << 16) | (g << 8) | h);

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_print(pr, "Invalid port!\r\n");
		return;
	}

	ofp_set_route_params(OFP_ROUTE_ADD, vrf, vlan, port, destaddr,
			     mlen, gwaddr, OFP_RTF_GATEWAY);
}

/* route -A inet6 add IP6NET gw IP6ADDR dev DEV */
#ifdef INET6
void f_route_add_v6(ofp_print_t *pr, const char *s)
{
	uint8_t dst6[16];
	uint8_t gw6[16];
	int port, vlan, mlen;
	const char *tk;
	const char *tk_end;
	const char *last;

	last = s + strlen(s);

/* get IP6NET address*/
	tk = s;
	tk_end = strstr(tk, "/");
	if (!tk_end) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	if (!ofp_parse_ip6_addr(tk, tk_end - tk, dst6)) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	tk_end = strstr(tk, " ");
	if (!tk_end || (tk == tk_end)) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	mlen = atoi(tk);

/* get IP6ADDR */
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}
	tk_end = strstr(tk, " ");
	if (tk_end == NULL) {
		ofp_print(pr, "Invalid IP6ADDR\r\n");
		return;
	}

	if (!ofp_parse_ip6_addr(tk, tk_end - tk, gw6)) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

/* get DEV */
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_print(pr, "Invalid DEV\r\n");
		return;
	}
	tk_end = last;

	port = ofp_name_to_port_vlan(tk, &vlan);
	if (port < 0 || port >= ofp_get_num_ports()) {
		ofp_print(pr, "Invalid port!\r\n");
		return;
	}

	ofp_set_route6_params(OFP_ROUTE6_ADD, 0 /*vrf*/, vlan, port, dst6,
			      mlen, gw6, OFP_RTF_GATEWAY);
}
#endif /* INET6*/

/* route delete IP4NET */
/* route -A inet4 delete IP4NET */
void f_route_del(ofp_print_t *pr, const char *s)
{
	uint32_t destaddr;
	int a, b, c, d, mlen;

	(void)pr;

	if (sscanf(s, "%d.%d.%d.%d/%d",
		&a, &b, &c, &d, &mlen) != 5)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	ofp_set_route_params(OFP_ROUTE_DEL, 0 /*vrf*/, 0 /*vlan*/, 0 /*port*/,
			     destaddr, mlen, 0 /*gw*/, 0 /*flags*/);
}

/* route delete vrf NUMBER IP4NET */
/* route -A inet4 delete vrf NUMBER IP4NET */
void f_route_del_vrf(ofp_print_t *pr, const char *s)
{
	uint32_t destaddr;
	int a, b, c, d, mlen, vrf;

	(void)pr;

	if (sscanf(s, "%d %d.%d.%d.%d/%d",
		&vrf, &a, &b, &c, &d, &mlen) != 6)
		return;
	destaddr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	ofp_set_route_params(OFP_ROUTE_DEL, vrf, 0 /*vlan*/, 0 /*port*/,
			     destaddr, mlen, 0 /*gw*/, 0 /*flags*/);
}

/* route -A inet6 delete IP6NET */
#ifdef INET6
void f_route_del_v6(ofp_print_t *pr, const char *s)
{
	uint8_t dst6[16];
	int mlen;
	const char *tk;
	const char *tk_end;
	const char *last;

	last = s + strlen(s);

/* get IP6NET address*/
	tk = s;
	tk_end = strstr(tk, "/");
	if (!tk_end) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	if (!ofp_parse_ip6_addr(tk, tk_end - tk, dst6)) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (tk >= last) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	tk_end = last;
	if (tk == tk_end) {
		ofp_print(pr, "Invalid IP6NET\r\n");
		return;
	}

	mlen = atoi(tk);

	ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, 0 /*vlan*/, 0 /*port*/,
			      dst6, mlen, NULL, 0);
}
#endif /* INET6 */

/* route add from DEV to DEV */
void f_route_add_dev_to_dev(ofp_print_t *pr, const char *s)
{
	char dev[16], from[16];

	(void)pr;

	if (sscanf(s, "%s %s", from, dev) != 2)
		return;
}

void f_help_route(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Show configured routes:\r\n"
		"  route show\r\n\r\n");

	ofp_print(pr, "Add IPv4 route:\r\n"
		"  route [-A inet4 ] add [vrf VRF] IP4NET gw IP4ADDR dev DEV\r\n"
		"    VRF: virtual forwarding table instance (a number)\r\n"
		"    IP4NET: network address in a.b.c.d/n format\r\n"
		"    IP4ADDR: IP address in a.b.c.d format\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Examples:\r\n"
		"    route add 192.168.200.0/24 gw 192.168.100.1 dev %s0\r\n"
		"    route add vrf 2 192.168.200.0/24 gw 192.168.100.1"
		" dev %s0\r\n\r\n", OFP_IFNAME_PREFIX, OFP_IFNAME_PREFIX);

	ofp_print(pr, "Delete IPv4 route:\r\n"
		"  route [-A inet4] delete [vrf VRF] IP4NET\r\n"
		"    VRF: virtual forwarding table instance (a number)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Examples:\r\n"
		"    route delete 192.168.200.0/24\r\n"
		"    route del vrf 2 192.168.200.0/24\r\n\r\n");
#ifdef INET6
	ofp_print(pr, "Add IPv6 route:\r\n"
		"  route -A inet6 add IP6NET gw IP6ADDR dev DEV\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"    IP6ADDR: IPv6 address in a:b:c:d:e:f:g:h or"
		" compressed format\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    route -A inet6 add 2000:1baf::/64 gw 2001:db8:0:f101:0:0:0:1"
		" dev %s0\r\n\r\n", OFP_IFNAME_PREFIX);

	ofp_print(pr, "Delete IPv6 route:\r\n"
		"  route -A inet6 delete IP6NET\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"  Example:\r\n"
		"    route -A inet6 delete 2000:1baf::/64\r\n\r\n");
#endif /* INET6 */
	ofp_print(pr, "Show (this) help.\r\n"
		"  route help\r\n\r\n");
}
