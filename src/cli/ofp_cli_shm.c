/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_udp_shm.h"
#include "ofpi_cli_shm.h"
#include "ofpi_cli.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define SHM_NAME_CLI "OfpCLIShMem"

/*
 * Data per core
 */
__thread struct ofp_cli_mem *shm_cli;

static int ofp_cli_alloc_shared_memory(void)
{
	shm_cli = ofp_shared_memory_alloc(SHM_NAME_CLI, sizeof(*shm_cli));
	if (shm_cli == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}
	return 0;
}

static int ofp_cli_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_CLI) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_cli = NULL;
	return rc;
}

static int ofp_cli_lookup_shared_memory(void)
{
	shm_cli = ofp_shared_memory_lookup(SHM_NAME_CLI);
	if (shm_cli == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

void ofp_cli_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_CLI, sizeof(*shm_cli));
}

int ofp_cli_init_global(void)
{
	uint32_t i;

	HANDLE_ERROR(ofp_cli_alloc_shared_memory());

	memset(shm_cli, 0, sizeof(*shm_cli));

	V_cli_os_thread_is_running = 0;
	V_cli_os_thread_is_stopping = 0;

	odp_rwlock_init(&V_cli_lock);

	/* Alias table */
	V_cli_alias_table_size = sizeof(V_cli_alias_table) /
		sizeof(V_cli_alias_table[0]);

	/* Node table */
	V_cli_node_table_size = sizeof(V_cli_node_table) /
		sizeof(V_cli_node_table[0]);

	for (i = 0; i < V_cli_node_table_size - 1; i++)
		V_cli_node_table[i].next = &V_cli_node_table[i + 1];
	V_cli_node_table[V_cli_node_table_size - 1].next = NULL;

	V_cli_node_free_list = &V_cli_node_table[0];

	if (cli_init_commands())
		return -1;

	return 0;
}

int ofp_cli_term_global(void)
{
	int rc = 0;

	if (ofp_cli_lookup_shared_memory())
		return -1;

	CHECK_ERROR(ofp_cli_free_shared_memory(), rc);

	return rc;
}

int ofp_cli_init_local(void)
{
	if (ofp_cli_lookup_shared_memory())
		return -1;

	return 0;
}

struct cli_node *ofp_alloc_node(void)
{
	struct cli_node *p = V_cli_node_free_list;

	if (V_cli_node_free_list)
		V_cli_node_free_list = V_cli_node_free_list->next;

	return p;
}

