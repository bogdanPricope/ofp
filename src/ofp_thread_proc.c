/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_log.h"
#include "ofpi_thread_proc.h"

int ofp_get_default_worker_cpumask(int req_num, int req_num_max,
				   odp_cpumask_t *cpumask)
{
	int core_count, num_workers;

	if  (!cpumask)
		return -1;

	core_count = odp_cpu_count();

	if (req_num) {
		num_workers = req_num;
	} else {
		num_workers = core_count;
		if (core_count > 1)
			num_workers--;
	}
	if (req_num_max && num_workers > req_num_max)
		num_workers = req_num_max;

	num_workers = odp_cpumask_default_worker(cpumask, num_workers);
	if (!num_workers)
		return -1;

	return 0;
}

