/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_ip.h"
#include "ofpi_ip_shm.h"

void ofp_ip_id_assign(struct ofp_ip *ip)
{
	uint16_t id = odp_atomic_fetch_inc_u32(&V_ip_id) & 0xffff;
	/*
	 * The byte swap is not necessary but it produces nicer packet dumps.
	 */
	ip->ip_id = odp_cpu_to_be_16(id);
}

