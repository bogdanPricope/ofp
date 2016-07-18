/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __OFPI_IPSEC_H__
#define __OFPI_IPSEC_H__

#include "odp.h"
#include "api/ofp_types.h"
#include "api/ofp_ipsec.h"
#include "ofpi_socket.h"

int ofp_ipsec_init_global(struct ofp_ipsec_config_param *);
int ofp_ipsec_term_global(void);
int ofp_ipsec_lookup_shared_memory(void);

struct ofp_ipsec_conf {
	struct ofp_ipsec_config_param param;
	uint8_t async_queue_idx;
	odp_rwlock_t async_queue_rwlock;
};


struct ofp_ipsec_conf *ofp_ipsec_config_get(void);

enum ofp_return_code ofp_ah4_input(odp_packet_t , int);
void ofp_ah4_ctlinput(int, struct ofp_sockaddr *, void *);
enum ofp_return_code ofp_esp4_input(odp_packet_t , int);
void ofp_esp4_ctlinput(int, struct ofp_sockaddr *, void *);

#endif /* __OFPI_IPSEC_H__ */

