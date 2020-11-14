/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_log.h"
#include "ofpi_global_param_shm.h"

enum ofp_log_level_s ofp_loglevel_get(void)
{
	if (!shm_global)
		return OFP_LOG_DISABLED;

	return V_global_loglevel;
}

void ofp_loglevel_set(enum ofp_log_level_s loglevel)
{
	if (!shm_global)
		return;

	V_global_loglevel = loglevel;
}

int ofp_debug_logging_enabled(void)
{
	if (!shm_global)
		return 0;
	return (V_global_loglevel == OFP_LOG_DEBUG);
}

