/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp.h"
#include "ofpi_ipsec_util.h"

void ofp_ipsec_generate_iv(uint8_t *iv, uint32_t iv_len, uint8_t *iv_ref, uint32_t idx)
{
	uint32_t tmp;

	memcpy(iv, iv_ref, iv_len);
	if (iv_len >= 4) {
		tmp = *(uint32_t *)(iv + iv_len - 4);
		tmp = odp_cpu_to_be_32(odp_be_to_cpu_32(tmp) + idx);
		*(uint32_t *)(iv + iv_len - 4) = tmp;
	}
	else
		*(iv + iv_len - 1) += idx;
}
