/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_H__
#define __OFP_IPSEC_H__

#include "odp.h"
#include "ofp_config.h"
#include "ofp_portconf.h"

enum ofp_async_queue_alloc {
	OFP_ASYNC_QUEUE_ALLOC_ROUNDROBIN = 0,
	OFP_ASYNC_QUEUE_ALLOC_CORE
};

struct ofp_ipsec_config_param {
	odp_bool_t		async_mode;
	uint32_t		async_queue_cnt;
	odp_queue_t		async_queues[OFP_IPSEC_ASYNC_QUEUE_SIZE];
	enum ofp_async_queue_alloc async_queue_alloc;

	odp_pool_t		output_pool;
};

void ofp_ipsec_conf_param_init(struct ofp_ipsec_config_param *);

int ofp_ipsec_boundary_interface_set(struct ofp_ifnet *, odp_bool_t);
#endif /* __OFP_IPSEC_H__ */
