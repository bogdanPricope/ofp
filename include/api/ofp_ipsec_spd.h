/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFP_IPSEC_SPD_H__
#define __OFP_IPSEC_SPD_H__

#include "ofp_ipsec_common.h"
#include "ofp_ipsec_selectors.h"

enum ofp_spd_action {
	OFP_SPD_ACTION_DISCARD = 0,
	OFP_SPD_ACTION_BYPASS,
	OFP_SPD_ACTION_PROTECT
};

struct ofp_spd_entry {
/* Selectors */
	struct ofp_ipsec_selectors selectors;

/* Policy */
	enum ofp_ipsec_direction direction;
	enum ofp_spd_action action;
	enum ofp_ipsec_protocol protect_protocol;
	enum ofp_ipsec_mode protect_mode;
	struct ofp_ipsec_addr protect_tunnel_src_addr;
	struct ofp_ipsec_addr protect_tunnel_dest_addr;

#if 0 /* Unsupported*/
	odp_bool_t extended_seq_number;
	odp_bool_t stateful_frag_checking;
	odp_bool_t bypass_DF;
	odp_bool_t bypass_DSCP;
#endif /* 0 */
};

int ofp_ipsec_spd_add(struct ofp_spd_entry *);
int ofp_ipsec_spd_del(struct ofp_ipsec_selectors *, enum ofp_ipsec_direction);
int ofp_ipsec_spd_flush(void);
int ofp_ipsec_spd_dump(int fd);

void ofp_ipsec_spd_entry_init(struct ofp_spd_entry *);

#endif /* __OFP_IPSEC_SPD_H__ */
