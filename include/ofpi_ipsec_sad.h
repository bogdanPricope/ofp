/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_IPSEC_SAD_H__
#define __OFPI_IPSEC_SAD_H__

#include "api/ofp_ipsec_sad.h"

enum ofp_sad_id {
	OFP_SAD_INBOUND = 0,
	OFP_SAD_OUTBOUND,
	OFP_SAD_CNT
};

int ofp_ipsec_sad_init_global(void);
int ofp_ipsec_sad_term_global(void);
int ofp_ipsec_sad_lookup_shared_memory(void);

int ofp_ipsec_sad_add_local(enum ofp_sad_id sad_id,
	struct ofp_sad_entry *sad_entry);
int ofp_ipsec_sad_del_local(enum ofp_sad_id sad_id,
	struct ofp_ipsec_selectors *trivial_selectors,
	uint32_t spi,
	enum ofp_ipsec_protocol protocol);

int ofp_ipsec_sad_flush_local(enum ofp_sad_id sad_id);
int ofp_ipsec_sad_dump_local(enum ofp_sad_id sad_id, int fd);
#endif /* __OFPI_IPSEC_SAD_H__ */
