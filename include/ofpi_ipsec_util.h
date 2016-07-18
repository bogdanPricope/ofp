/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IPSEC_UTIL_H__
#define __OFPI_IPSEC_UTIL_H__

#include "odp.h"

void ofp_ipsec_generate_iv(uint8_t *iv, uint32_t iv_len,
	uint8_t *iv_ref, uint32_t idx);

static inline uint32_t ofp_ipsec_compute_padding_len(uint32_t data_len, uint32_t block_size)
{
	return ((data_len + (block_size - 1)) / block_size) * block_size - data_len;
}

#endif /*__OFPI_IPSEC_UTIL_H__*/
