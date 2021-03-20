/*-
 * Copyright (c) 2018 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_util.h"

void f_address_help(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Add ipv4 address:\r\n"
		"  address add IP4NET DEV\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    address add 192.168.200.1/24 %s0\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_print(pr, "Remove ipv4 address:\r\n"
		"  address del IP4NET DEV\r\n"
		"    DEV: ethernet interface name or local interface(lo0, lo1,...)\r\n"
		"    IP4NET: network address in a.b.c.d/e format\r\n"
		"  Example:\r\n"
		"    address del 192.168.200.1/24 %s0\r\n\r\n",
		OFP_IFNAME_PREFIX);

	ofp_print(pr, "Show ipv4 addresses:\r\n"
			"  address show\r\n"
			"  Example:\r\n"
			"    address show\r\n\r\n");

}

void f_address_show(ofp_print_t *pr, const char *s)
{
	/* addressr [show] */
	(void)s;

	ofp_ifport_net_ipv4_addr_show(pr);
}


void f_address_add(ofp_print_t *pr, const char *s)
{
	/* address add IP4NET DEV */
	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	uint32_t addr;
	const char *err;
	int ret;

	ret = sscanf(s, "%d.%d.%d.%d/%d %s", &a, &b,
		&c, &d, &m, dev);

	if (ret < 6) {
		return;
	}

	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);

	if (port == OFP_IFPORT_GRE || port == OFP_IFPORT_VXLAN ||
	    port == OFP_IFPORT_LOCAL) {
		ofp_print(pr, "Invalid device name.\r\n");
		return;
	}

	err = ofp_ifport_net_ipv4_addr_add(port, vlan, vrf, addr, m);
	if (err != NULL)
		ofp_print(pr, err);
}

void f_address_del(ofp_print_t *pr, const char *s)
{
	/* addressr delete IP4NET DEV */
	char dev[16];
	int port, a, b, c, d, m, vlan, vrf = 0;
	const char *err;
	int ret;
	uint32_t addr;

	ret = sscanf(s, "%d.%d.%d.%d/%d %s", &a, &b,
			&c, &d, &m, dev);

	if (ret < 6) {
		return;
	}
	addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);
	port = ofp_name_to_port_vlan(dev, &vlan);
	err = ofp_ifport_net_ipv4_addr_del(port, vlan, vrf, addr, m);

	if (err != NULL)
		ofp_print(pr, err);
}
