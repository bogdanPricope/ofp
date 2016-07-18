/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_IPSEC_SPD_H__
#define __OFPI_IPSEC_SPD_H__

#include "api/ofp_ipsec_spd.h"

enum ofp_spd_id {
	OFP_SPD_I = 0,
	OFP_SPD_O,
	OFP_SPD_S,
	OFP_SPD_CNT
};

int ofp_ipsec_spd_init_global(void);
int ofp_ipsec_spd_term_global(void);
int ofp_ipsec_spd_lookup_shared_memory(void);

int ofp_ipsec_spd_add_local(enum ofp_spd_id spd_id,
	struct ofp_spd_entry *spd_entry);
int ofp_ipsec_spd_del_local(enum ofp_spd_id spd_id,
	struct ofp_ipsec_selectors *spd_selectors);
int ofp_ipsec_spd_flush_local(enum ofp_spd_id spd_id);
int ofp_ipsec_spd_dump_local(enum ofp_spd_id spd_id, int fd);

struct ofp_spd_entry *ofp_ipsec_spd_search_local(enum ofp_spd_id spd_id,
	struct ofp_ipsec_selectors *spd_selectors);
#endif /* __OFPI_IPSEC_SPD_H__ */


