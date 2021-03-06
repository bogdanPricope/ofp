/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_util.h"


/* "ifconfig" */
/* "ifconfig show" */
/* "show ifconfig" */
void f_ifconfig_show(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_ifport_ifnet_show(pr);
}

/* "ifconfig help" */
/* "help ifconfig" */
void f_help_ifconfig(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Show interfaces:\r\n"
		"  ifconfig [show]\r\n\r\n");

	ofp_print(pr, "Create or configure an interface:\r\n"
		"  ifconfig [-A inet4] DEV IP4NET [vrf VRF]\r\n"
		"    DEV: ethernet, vlan or loopback interface name.\r\n"
		"         VLAN interfaces are named <phys dev>.<vlan_id>\r\n"
		"         Loopback interfaces are named lo0, lo1, ...\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"    VRF: virtual routing and forwarding instance (a number)\r\n"
		"  Examples:\r\n"
		"    ifconfig %s0 192.168.200.1/24\r\n"
		"    ifconfig %s0.100 192.168.200.1/24\r\n"
		"    ifconfig %s0 192.168.200.1/24 vrf 2\r\n\r\n",
		OFP_IFNAME_PREFIX, OFP_IFNAME_PREFIX, OFP_IFNAME_PREFIX);
	ofp_print(pr, "Create or configure a GRE tunnel:\r\n"
		"  ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR [vrf VRF]\r\n"
		"    DEV: gre interface name\r\n"
		"    local: local tunnel endpoint ip address in a.b.c.d format\r\n"
		"    remote: remote tunnel endpoint ip address in a.b.c.d format\r\n"
		"    peer: pointtopoint ip address in a.b.c.d format\r\n"
		"    IP4ADDR: interface ip address in a.b.c.d format\r\n"
		"    VRF: virtual routing and forwarding instance (a number)\r\n"
		"  Examples:\r\n"
		"    ifconfig tunnel gre %s100 local 192.168.200.1 remote 192.168.200.2 peer 10.10.10.2 10.10.10.1\r\n"
		"    ifconfig tunnel gre %s100 local 192.168.200.1 remote 192.168.200.2 peer 10.10.10.2 10.10.10.1 vrf 2\r\n\r\n",
		OFP_GRE_IFNAME_PREFIX, OFP_GRE_IFNAME_PREFIX);
	ofp_print(pr, "Create or configure a VXLAN interface:\r\n"
		"  ifconfig vxlan DEV group IP4ADDR dev DEV_PHYS IP4NET\r\n"
		"    DEV: vxlan interface name (interface number is the vni)\r\n"
		"    IP4ADDR: group ip address in a.b.c.d format\r\n"
		"    DEV_PHYS: interface name of the physical device\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    ifconfig vxlan %s42 group 239.1.1.1 dev fp0 10.10.10.1/24\r\n"
		"    (vni = 42)\r\n\r\n",
		OFP_VXLAN_IFNAME_PREFIX);
#ifdef INET6
	ofp_print(pr, "Create or configure an IPv6 interface:\r\n"
		"  ifconfig -A inet6 DEV IP6NET\r\n"
		"    DEV: ethernet interface name\r\n"
		"    IP6NET: network address in a:b:c:d:e:f:g:h/n or"
		" compressed format\r\n"
		"  Example:\r\n"
		"    ifconfig -A inet6 %s0 2000:1baf::/64\r\n\r\n",
		OFP_IFNAME_PREFIX);
#endif /* INET6 */
	ofp_print(pr, "Delete or unconfigure an interface:\r\n"
		"  ifconfig DEV down\r\n"
		"    DEV: ethernet interface name\r\n"
		"  Example:\r\n"
		"    ifconfig %s0 down\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_print(pr, "Show (this) help:\r\n"
		"  ifconfig help\r\n\r\n");
}

/* "ifconfig [-A inet 4] DEV IP4NET";*/
void f_ifconfig(ofp_print_t *pr, const char *s)
{

	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	uint32_t addr;
	const char *err;

	if (sscanf(s, "%s %d.%d.%d.%d/%d %d", dev, &a, &b,
		&c, &d, &m, &vrf) < 6)
		return;
	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port == OFP_IFPORT_GRE || port == OFP_IFPORT_VXLAN) {
		ofp_print(pr, "Invalid device name.\r\n");
		return;
	}

	if (OFP_IFPORT_IS_NET(port))
		err = ofp_ifport_net_ipv4_up(port, vlan, vrf, addr, m, 1);
	else
		err = ofp_ifport_local_ipv4_up(vlan, vrf, addr, m, 0);
	if (err != NULL)
		ofp_print(pr, err);
}

/* "ifconfig tunnel gre DEV local IP4ADDR remote IP4ADDR peer IP4ADDR IP4ADDR vrf NUMBER";*/
void f_ifconfig_tun(ofp_print_t *pr, const char *s)
{
	char dev[16], loc[16], rem[16], ip[16], peer[16];
	uint32_t tun_loc, tun_rem, addr, p2p;
	int port, vlan, vrf = 0, masklen = 32;
	const char *err;

	if (sscanf(s, "%s %s %s %s %s %d", dev, loc, rem, peer, ip, &vrf) < 5)
		return;

	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port != OFP_IFPORT_GRE) {
		ofp_print(pr, "Invalid device name.\r\n");
		return;
	}

	if (!ofp_parse_ip_addr(loc, &tun_loc)) {
		ofp_print(pr, "Invalid address: %s.", loc);
		return;
	}
	if (!ofp_parse_ip_addr(rem, &tun_rem)) {
		ofp_print(pr, "Invalid address: %s.", rem);
		return;
	}
	if (!ofp_parse_ip_addr(peer, &p2p)) {
		ofp_print(pr, "Invalid address: %s.", peer);
		return;
	}
	if (!ofp_parse_ip_addr(ip, &addr)) {
		ofp_print(pr, "Invalid address: %s.", ip);
		return;
	}

	err = ofp_ifport_tun_ipv4_up(port, vlan, vrf, tun_loc, tun_rem, p2p,
				     addr, masklen, 1);
	if (err != NULL)
		ofp_print(pr, err);
}

/* ifconfig vxlan DEV group IP4ADDR dev DEV IP4NET */
void f_ifconfig_vxlan(ofp_print_t *pr, const char *s)
{
	char dev[16], physdev[16], group[16];
	uint32_t vxlan_group, addr;
	int n, port, subport_vni, physport, physvlan, a, b, c, d, m;
	const char *err;

	if ((n = sscanf(s, "%s %s %s %d.%d.%d.%d/%d",
			dev, group, physdev,
			&a, &b, &c, &d, &m)) != 8) {
		return;
	}

	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &subport_vni);

	if (port != OFP_IFPORT_VXLAN) {
		ofp_print(pr, "Invalid device name %s.\r\n", dev);
		return;
	}

	physport = ofp_name_to_port_vlan(physdev, &physvlan);

	if (!ofp_parse_ip_addr(group, &vxlan_group)) {
		ofp_print(pr, "Invalid group address.\r\n");
		return;
	}

	/* vrf is copied from the physical port */
	err = ofp_ifport_vxlan_ipv4_up(subport_vni, vxlan_group,
				       physport, physvlan,
				       addr, m, 1);
	if (err != NULL)
		ofp_print(pr, err);
}

/* ifconfig -A inet6 DEV IP6NET */
#ifdef INET6
void f_ifconfig_v6(ofp_print_t *pr, const char *s)
{
	char dev[16];
	uint8_t addr6[16];
	int prefix, port, vlan;
	const char *tk;
	const char *tk_end;
	const char *err;

	/*get DEV*/
	tk = s;
	tk_end = strstr(tk, " ");

	if (!tk_end || ((int)(tk_end - tk) > (int)(sizeof(dev) - 1))) {
		ofp_print(pr, "Invalid device name.\r\n");
		return;
	}
	memcpy(dev, tk, tk_end - tk);
	dev[tk_end - tk] = 0;

	port = ofp_name_to_port_vlan(dev, &vlan);
	if (port == -1 || port == OFP_IFPORT_GRE) {
		ofp_print(pr, "Invalid device name.\r\n");
		return;
	}

	/*get IP6NET address*/
	tk = tk_end + 1;
	tk_end = strstr(tk, "/");

	if (!tk_end || tk_end - tk > 40) {
		ofp_print(pr, "Invalid IP6NET address.\r\n");
		return;
	}

	if (!ofp_parse_ip6_addr(tk, tk_end - tk, addr6)) {
		ofp_print(pr, "Invalid IP6NET address.\r\n");
		return;
	}

	/* get IP6NET prefix len*/
	tk = tk_end + 1;
	if (sscanf(tk, "%d", &prefix) < 1) {
		ofp_print(pr, "Invalid IP6NET prefix.\r\n");
		return;
	}

	if (port == OFP_IFPORT_LOCAL)
		err = ofp_ifport_local_ipv6_up(vlan, addr6, prefix);
	else
		err = ofp_ifport_net_ipv6_up(port, vlan, addr6, prefix, 1);
	if (err != NULL)
		ofp_print(pr, err);
}
#endif /* INET6 */

void f_ifconfig_down(ofp_print_t *pr, const char *s)
{
	/* "ifconfig DEV down"; */
	char dev[16];
	int port, vlan;
	const char *err;

	if (sscanf(s, "%s", dev) < 1)
		return;
	port = ofp_name_to_port_vlan(dev, &vlan);

	err = ofp_ifport_ifnet_down(port, vlan);

	if (err != NULL)
		ofp_print(pr, err);
}
