/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_THREAD_PROC_h__
#define __OFP_THREAD_PROC_h__

#include <odp_api.h>

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * Get default workers to cores distribution
 *
 * By default, first two cores are reserved for control
 * and linux processing while the rest are available for
 * workers. One run-to-completion thread or process can
 * be created for each worker core.
 *
 * Application may use custom distributions. The right
 * distribution depends on usecase and number of cores
 * available.
 *
 * @param req_num The number of worker cores requested. If set 0 then
 * the maximum number of available cores is requested (see 'req_num_max').
 * @param req_num_max If not zero, it represents the upper limit for
 * the number of worker cores returned in 'cpumask'. This parameter is
 * especially useful when 'req_num' is set to zero.
 * @param cpumask The worker to core distribution.
 * @retval 0 Success.
 * @retval -1 Failure.
 */

int ofp_get_default_worker_cpumask(int req_num, int req_num_max,
				   odp_cpumask_t *cpumask);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_THREAD_PROC_h__ */

