/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "odp.h"
#include "ofpi_vnet.h"
#include "ofpi_thread_proc.h"

struct ofp_cli_mem {
	VNET_DEFINE(ofp_thread_t, os_thread);
	VNET_DEFINE(odp_bool_t, os_thread_is_running);
};

extern __thread struct ofp_cli_mem *shm_cli;

#define	V_cli_os_thread				VNET(shm_cli->os_thread)
#define	V_cli_os_thread_is_running	VNET(shm_cli->os_thread_is_running)

void ofp_cli_init_prepare(void);
int ofp_cli_init_global(void);
int ofp_cli_term_global(void);
int ofp_cli_init_local(void);

