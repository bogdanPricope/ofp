/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_log.h"
#include "ofpi_thread_proc.h"
#include "ofpi_global_param_shm.h"

typedef struct {
	int (*start)(void *start_arg); /**< Thread entry point function */
	void *arg;                     /**< Argument for the function */
} ofp_start_thread_arg_t;

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

static void cleanup_thr_param(odph_thread_param_t *thr_param,
			      int st_idx, int cnt)
{
	int i;

	for (i = 0; i < cnt; i++)
		free(thr_param[st_idx + i].arg);
}

static int ofp_thread_start(void *arg)
{
	int ret = 0;
	ofp_start_thread_arg_t *thread_start_arg =
		(ofp_start_thread_arg_t *)arg;

	if (ofp_init_local_resources())
		return -1;

	ret = thread_start_arg->start(thread_start_arg->arg);

	if (ofp_term_local_resources())
		OFP_ERR("ofp_term_local_resources failed");

	free(arg);
	return ret;
}

int ofp_thread_create(ofp_thread_t *thread_tbl,
		      int num,
		      const odp_cpumask_t *cpumask,
		      const ofp_thread_param_t *thread_param)
{
	odph_thread_common_param_t param = {0};
	odph_thread_param_t *thr_param = NULL;
	ofp_start_thread_arg_t *thread_start_arg;
	int i, ret;

	if (!thread_tbl || num <= 0 || !cpumask || !thread_param)
		return -1;

	/* common param */
	param.instance = V_global_odp_instance;
	param.cpumask = cpumask;
	param.thread_model = 0;	/* pthreads */
	param.sync = 0;
	param.share_param = 0;

	/* thread param*/
	thr_param = (odph_thread_param_t *)malloc(num *
						  sizeof(odph_thread_param_t));
	if (!thr_param)
		return -1;

	for (i = 0; i < num; i++) {
		thr_param[i].thr_type = thread_param->thr_type;
		thr_param[i].instance = V_global_odp_instance; /* deprecated */
		thr_param[i].start = ofp_thread_start;

		thread_start_arg = (ofp_start_thread_arg_t *)
			malloc(sizeof(ofp_start_thread_arg_t));
		if (!thread_start_arg) {
			cleanup_thr_param(thr_param, 0, i);
			free(thr_param);
			return -1;
		}

		thread_start_arg->start = thread_param->start;
		thread_start_arg->arg = thread_param->arg;
		thr_param[i].arg = thread_start_arg;
	}

	ret = odph_thread_create(thread_tbl, &param, thr_param, num);
	if (ret == -1)
		cleanup_thr_param(thr_param, 0, num);
	else if (ret < num)
		cleanup_thr_param(thr_param, ret, num - ret);
	free(thr_param);

	return ret;
}

int ofp_thread_join(ofp_thread_t *thread_tbl, int num)
{
	if (!thread_tbl || num <= 0)
		return -1;
	return odph_thread_join(thread_tbl, num);
}

int ofp_process_fork_n(ofp_process_t *proc_tbl,
		       const odp_cpumask_t *mask,
		       const ofp_process_param_t *proc_param)
{
	odph_linux_thr_params_t thr_params = {0};
	int ret = 0;

	if (!proc_tbl || !mask || !proc_param)
		return -1;

	thr_params.start = NULL; /* Ignored */
	thr_params.arg = NULL;   /* Ignored */
	thr_params.thr_type = proc_param->thr_type;
	thr_params.instance = V_global_odp_instance;

	ret = odph_linux_process_fork_n((odph_linux_process_t *)proc_tbl,
					mask, &thr_params);

	if (ret == 0) { /* child process*/
		if (ofp_init_local_resources())
			exit(EXIT_FAILURE);
	}

	return ret;
}

int ofp_process_wait_n(ofp_process_t *proc_tbl, int num)
{
	if (!proc_tbl || !num)
		return -1;

	return odph_linux_process_wait_n((odph_linux_process_t *)proc_tbl, num);
}

