/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_UTILS_H__
#define __OFP_UTILS_H__

#include <stdint.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

#ifndef _TRUE_FALSE_
#define FALSE 0
#ifndef TRUE
#define TRUE (!FALSE)
#endif
#define _TRUE_FALSE_ 1
#endif

char *ofp_print_mac(uint8_t *mac);
char *ofp_print_ip_addr(uint32_t addr);
char *ofp_print_ip6_addr(uint8_t *addr);

int ofp_parse_ip_addr(const char *tk, uint32_t *addr);
int ofp_parse_ip_net(const char *tk, uint32_t *addr, int *mask);
int ofp_parse_ip6_addr(const char *tk, int tk_len, uint8_t addr[16]);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /*__OFP_UTILS_H__*/
