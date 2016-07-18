/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_IPSEC_COMMON_H__
#define __OFP_IPSEC_COMMON_H__

#define OFP_IPSEC_KEY_SIZE_MAX 32
#define OFP_IPSEC_IV_SIZE_MAX 32

union ofp_ipsec_addr_storage {
	uint8_t addr6[16];
	uint32_t addr4; /* Network byte order */
};

struct ofp_ipsec_addr {
	odp_bool_t addr_type_ipv4;
	union ofp_ipsec_addr_storage addr;
};

enum ofp_ipsec_direction {
	OFP_IPSEC_DIRECTION_IN = 0,
	OFP_IPSEC_DIRECTION_OUT
};

enum ofp_ipsec_protocol {
	OFP_IPSEC_PROTOCOL_ESP = 0,
	OFP_IPSEC_PROTOCOL_AH,
	OFP_IPSEC_PROTOCOL_CNT
};
enum ofp_ipsec_mode {
	OFP_IPSEC_MODE_TUNNEL  = 0,
	OFP_IPSEC_MODE_TRANSPORT,
	OFP_IPSEC_MODE_CNT
};

struct ofp_ipsec_key {
	uint8_t data[OFP_IPSEC_KEY_SIZE_MAX];
	uint32_t length;
};
struct ofp_ipsec_cipher_iv {
	uint8_t data[OFP_IPSEC_IV_SIZE_MAX];
	uint32_t length;
};
#endif /* __OFP_IPSEC_COMMON_H__ */


