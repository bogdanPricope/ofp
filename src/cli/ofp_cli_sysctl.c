/*-
 * Copyright (c) 2015 Nokia Solutions and Networks
 * Copyright (c) 2015 ENEA Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_route.h"
#include "ofpi_arp.h"
#include "ofpi_util.h"
#include "ofpi_sysctl.h"


void f_help_sysctl(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr, "sysctl - configure system parameters at ");
	ofp_print(pr, "runtime.\r\n\r\n");

	ofp_print(pr, "Show sysctl tree:\r\n"
				"  sysctl dump\r\n\r\n");

	ofp_print(pr, "Read sysctl variable value:\r\n"
				"  sysctl r VARIABLE\r\n"
				"  Example:\r\n"
				"    sysctl r net.inet.udp.checksum\r\n\r\n");

	ofp_print(pr, "Write sysctl variable value:\r\n"
				"  sysctl w VARIABLE VALUE\r\n"
				"  Example:\r\n"
				"    sysctl w net.inet.udp.checksum 0\r\n\r\n");

	ofp_print(pr, "Show (this) help:\r\n"
				"  sysctl help\r\n\r\n");
}

void f_sysctl_dump(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_sysctl_write_tree(pr);
}

#define SYSCTL_BUFF 1024
void f_sysctl_read(ofp_print_t *pr, const char *s)
{
	int ret = 0;
	unsigned int var_type;
	size_t var_type_len = sizeof(var_type);
	uint8_t old[SYSCTL_BUFF];
	size_t old_len = SYSCTL_BUFF;

	ret = ofp_sysctl("vartype", &var_type, &var_type_len,
			 s, strlen(s), NULL);
	if (ret != 0) {
		ofp_print(pr, "Variable's type not found: error %d", ret);
		return;
	}

	ret = ofp_sysctl(s, old, &old_len, NULL, 0, NULL);
	if (ret != 0) {
		ofp_print(pr,
			  "Variable not found or type not supported: error %d",
			  ret);
		return;
	}

	ofp_print(pr, "%s = ", s);

	switch (var_type & OFP_CTLTYPE) {
	case OFP_CTLTYPE_INT: {
		int *r = (int *)old;

		ofp_print(pr, "%d\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_UINT: {
		unsigned int *r = (unsigned int *)old;

		ofp_print(pr, "%u\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_LONG: {
		long int *r = (long int *)old;

		ofp_print(pr, "%ld\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_ULONG: {
		unsigned long *r = (unsigned long *)old;

		ofp_print(pr, "%lu\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_STRING: {
		char *r = (char *)old;

		r[old_len] = 0;
		ofp_print(pr, "%s\r\n", r);
		break;
	}
	case OFP_CTLTYPE_U64: {
		uint64_t *r = (uint64_t *)old;

		ofp_print(pr, "%lu\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_S64: {
		int64_t *r = (int64_t *)old;

		ofp_print(pr, "%ld\r\n", *r);
		break;
	}
	case OFP_CTLTYPE_OPAQUE: {
		unsigned int i;
		unsigned char *r = (unsigned char *)old;

		for (i = 0; i < old_len; i++)
			ofp_print(pr, " %02x", r[i]);
		ofp_print(pr, "\r\n");
		break;
	}
	case OFP_CTLTYPE_NODE:
	{
		ofp_print(pr, "Error: Not a variable.\r\n");
		break;
	}
	default:
		ofp_print(pr, "unknown type\r\n");
	}
}

void f_sysctl_write(ofp_print_t *pr, const char *s)
{
	char var_name[SYSCTL_BUFF];
	char val_str[SYSCTL_BUFF];
	char val[SYSCTL_BUFF];
	size_t val_len;
	int ret = 0;
	unsigned int var_type;
	size_t var_type_len = sizeof(var_type);

	if (sscanf(s, "%s %s", var_name, val_str) != 2)
		return;

	ret = ofp_sysctl("vartype", &var_type, &var_type_len,
			 var_name, strlen(var_name), NULL);
	if (ret != 0) {
		ofp_print(pr, "Variable's type not found: error %d", ret);
		return;
	}

	switch (var_type & OFP_CTLTYPE) {
	case OFP_CTLTYPE_UINT: {
		*(unsigned int *)val = (unsigned int)atoi(val_str);
		val_len = sizeof(unsigned int);
		break;
	}
	case OFP_CTLTYPE_INT: {
		*(int *)val = atoi(val_str);
		val_len = sizeof(int);
		break;
	}
	case OFP_CTLTYPE_ULONG: {
		*(unsigned long *)val = (unsigned long)atol(val_str);
		val_len = sizeof(unsigned long);
		break;
	}
	case OFP_CTLTYPE_LONG: {
		*(long *)val = atol(val_str);
		val_len = sizeof(long);
		break;
	}
	case OFP_CTLTYPE_STRING: {
		val_len = strlen(val_str);
		if (val_len > sizeof(val) - 1)
			val_len = sizeof(val) - 1;
		odp_memcpy(val, val_str, val_len);
		val[val_len] = '\0';
		break;
	}
	case OFP_CTLTYPE_S64: {
		*(uint64_t *)val = (uint64_t)atoll(val_str);
		val_len = sizeof(uint64_t);
		break;
	}
	case OFP_CTLTYPE_U64: {
		*(int64_t *)val = atoll(val_str);
		val_len = sizeof(int64_t);
		break;
	}
	default:
		ofp_print(pr, "unsupported type for writing\r\n");
		return;
	}

	ret = ofp_sysctl(var_name, NULL, NULL, val, val_len, NULL);
	if (ret != 0) {
		ofp_print(pr,	"Error %d", ret);
		return;
	}
}
