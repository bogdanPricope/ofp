/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_IPSEC_PKT_PROCESSING_H__
#define __OFP_IPSEC_PKT_PROCESSING_H__

#include "odp.h"
#include "ofp_types.h"

enum ofp_return_code ofp_ipsec_crypto_compl(odp_packet_t);

#endif /*__OFP_IPSEC_PKT_PROCESSING_H__*/


