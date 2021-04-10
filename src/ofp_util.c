/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ofpi.h"
#include "ofpi_util.h"
#include "ofpi_log.h"

void *rpl_malloc (size_t n)
{
	if (n == 0)
		n = 1;
	return malloc (n);
}

/**
 * Helper function to print MAC address.
 */
char *ofp_print_mac(uint8_t *mac)
{
	static char buf[2][24];
	static int sel = 0;
	int i, n = 0;

	sel = sel ^ 1;
	for (i = 0; i < 6; i++)
		n += sprintf(&buf[sel][n],
			     "%c%02x", i == 0 ? ' ' : ':', mac[i]);
	return buf[sel];
}

/**
 * Helper function to print IP address.
 */
char *ofp_print_ip_addr(uint32_t addr)
{
	static char buf[4][24];
	static int sel = 0;
	uint32_t ip = odp_be_to_cpu_32(addr);

	sel++;
	if (sel > 3)
		sel = 0;
	sprintf(buf[sel], "%d.%d.%d.%d",
		ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);

	return buf[sel];
}

char *ofp_print_ip6_addr(uint8_t *addr)
{
	int i, n = 0;
	static char buf[2][OFP_INET6_ADDRSTRLEN];
	static int sel = 0;

	sel = sel ^ 1;
	for (i = 0; i < 16; i += 2)
		n += sprintf(buf[sel] + n, "%s%02x%02x",
			     i == 0 ? "" : ":", addr[i], addr[i+1]);

	return buf[sel];
}

int ofp_parse_ip_addr(const char *tk, uint32_t *addr)
{
	int a, b, c, d;

	if (!addr)
		return 0;

	if (sscanf(tk, "%d.%d.%d.%d", &a, &b, &c, &d) < 4)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

int ofp_parse_ip_net(const char *tk, uint32_t *addr, int *mask)
{
	int a, b, c, d;

	if (!addr || !mask)
		return 0;

	if (sscanf(tk, "%d.%d.%d.%d/%d", &a, &b, &c, &d, mask) < 5)
		return 0;

	*addr = odp_cpu_to_be_32((a << 24) | (b << 16) | (c << 8) | d);

	return 1;
}

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

int ofp_parse_ip6_addr(const char *tk, int tk_len, uint8_t addr[16])
{
	const char *it, *last;
	const char *last_colon;
	const char *group_start;
	int group_cnt;
	int group_len;
	int dbl_colon_pos;
	int i;

	odp_memset(addr, 0, 16);

	if (tk_len == 0)
		tk_len = strlen(tk);

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
				((*it) >= 'A' && (*it) <= 'F')))
				it++;

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
		} else {
			return 0;
		}
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

void ofp_print_hex(uint8_t log_level,
	unsigned char *data, int len)
{
	int i;

	if (!data) {
		OFP_LOG_NO_CTX(log_level, "* ofp_print_hex: no data!*");
		return;
	}

	for (i = 0; i < len; i++)
		OFP_LOG_NO_CTX(log_level, "%02x ", data[i]);
}

/*
 * In develepment environment this will generate a core dump.
 * In production environment this should be re-defined to
 * product specific function
 */
void ofp_generate_coredump(void)
{
	int a = 0;
	int b = 7;
	int c = b/a;

	a = c;
}

int ofp_hex_to_num(char *s)
{
	int n = 0;

	while (s && *s) {
		if (*s >= '0' && *s <= '9')
			n = (n << 4) | (*s - '0');
		else if (*s >= 'a' && *s <= 'f')
			n = (n << 4) | (*s - 'a' + 10);
		else if (*s >= 'A' && *s <= 'F')
			n = (n << 4) | (*s - 'A' + 10);
		else
			break;
		s++;
	}

	return n;
}

void ofp_mac_to_link_local(uint8_t *mac, uint8_t *lladdr)
{
	memset(lladdr, 0, 16);
	memcpy(lladdr + 8, mac, 3);
	memcpy(lladdr + 13, mac + 3, 3);
	lladdr[8] ^= 0x02;
	lladdr[11] = 0xff;
	lladdr[12] = 0xfe;
	lladdr[0] = 0xfe;
	lladdr[1] = 0x80;
}

int ofp_has_mac(uint8_t *mac)
{
	int i;

	for (i = 0; i < OFP_ETHER_ADDR_LEN; ++i)
		if (mac[i])
			return 1;

	return 0;
}

void ofp_ip6_masklen_to_mask(int masklen, uint8_t *mask)
{
	int i;
	int bytes = masklen/8;
	int bits = 8 - (masklen%8);

	for (i = 0; i < 16; i++)
		mask[i] = 0;

	for (i = 0; i < bytes; i++)
		mask[i] = 0xff;

	if (i < 16 && bits < 8)
		mask[i] = 0xffff << bits;
}

/*
 * mask in little endian order
 */
int ofp_mask_length(int masklen, uint8_t *mask)
{
	int i, j, m, ml = masklen;

	for (i = 0; i < masklen/8; i++) {
		for (j = 0; j < 8; j++) {
			m = 1 << j;
			if (mask[i] & m)
				return ml;
			ml--;
		}
	}
	return 0;
}

int ofp_name_to_port_vlan(const char *dev, int *vlan)
{
	int port = -1;
	char *p;

	if (!dev)
		return -1;

	/* gre */
	if (strncmp(dev, OFP_GRE_IFNAME_PREFIX,
		    strlen(OFP_GRE_IFNAME_PREFIX)) == 0) {
		*vlan = atoi(dev + strlen(OFP_GRE_IFNAME_PREFIX));
		return OFP_IFPORT_GRE;
	}

	/* vxlan */
	if (strncmp(dev, OFP_VXLAN_IFNAME_PREFIX,
		    strlen(OFP_VXLAN_IFNAME_PREFIX)) == 0) {
		const char *n = dev + strlen(OFP_VXLAN_IFNAME_PREFIX);
		if (*n < '0' || *n > '9')
			return -1;
		*vlan = atoi(n);
		return OFP_IFPORT_VXLAN;
	}

	/* local */
	if (strncmp(dev, OFP_LOCAL_IFNAME_PREFIX,
		    strlen(OFP_LOCAL_IFNAME_PREFIX)) == 0) {
		const char *n = dev + strlen(OFP_LOCAL_IFNAME_PREFIX);
		if (*n < '0' || *n > '9')
			return -1;
		*vlan = atoi(n);
		return OFP_IFPORT_LOCAL;
	}

	/* fp */
	if (strncmp(dev, OFP_IFNAME_PREFIX, strlen(OFP_IFNAME_PREFIX)))
		return -1;

	port = atoi(dev + strlen(OFP_IFNAME_PREFIX));

	p = strchr(dev, '.');

	if (p)
		*vlan = atoi(p+1);
	else
		*vlan = OFP_IFPORT_NET_SUBPORT_ITF;

	return port;
}

char *ofp_port_vlan_to_ifnet_name(int port, int vlan)
{
	static char buf[2][18];
	static int sel = 0;

	sel = sel ^ 1;

	switch (port) {
	case OFP_IFPORT_LOCAL:
		sprintf(buf[sel], "%s%d",
			OFP_LOCAL_IFNAME_PREFIX, vlan);
		break;
	case OFP_IFPORT_GRE:
		sprintf(buf[sel], "%s%d",
			OFP_GRE_IFNAME_PREFIX, vlan);
		break;
	case OFP_IFPORT_VXLAN:
		sprintf(buf[sel], "%s%d",
			OFP_VXLAN_IFNAME_PREFIX, vlan);
		break;
	default:
		if (vlan != OFP_IFPORT_NET_SUBPORT_ITF)
			sprintf(buf[sel], "%s%d.%d",
				OFP_IFNAME_PREFIX, port, vlan);
		else
			sprintf(buf[sel], "%s%d", OFP_IFNAME_PREFIX, port);
	}

	return buf[sel];
}
