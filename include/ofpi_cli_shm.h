/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "odp.h"
#include "ofpi_vnet.h"
#include "ofpi_config.h"
#include "ofpi_thread_proc.h"
#include "ofpi_cli.h"

#define ALIAS_TABLE_SIZE 10
#define ALIAS_TABLE_NAME_LEN 20
#define ALIAS_TABLE_CMD_LEN 30

struct alias_table_s {
	char name[ALIAS_TABLE_NAME_LEN];
	char cmd[ALIAS_TABLE_CMD_LEN];
};

/** CLI Commands node
 */
struct cli_node {
	void (*func)(ofp_print_t *pr, const char *s);
	struct cli_node *nextword;
	struct cli_node *nextpossibility;
	const char *word;
	const char *help;
	char type;

	struct cli_node *next;	/* free list link*/
};

struct ofp_cli_mem {
	VNET_DEFINE(ofp_thread_t, os_thread);
	VNET_DEFINE(odp_bool_t, os_thread_is_running);

	VNET_DEFINE(odp_rwlock_t, rwlock);

	struct alias_table_s alias_table[ALIAS_TABLE_SIZE];

	VNET_DEFINE(uint32_t, alias_table_size);

	struct cli_node node_table[OFP_CLI_NODE_MAX];

	VNET_DEFINE(uint32_t, node_table_size);
	VNET_DEFINE(struct cli_node *, node_free_list);

	VNET_DEFINE(struct cli_node *, node_end);
	VNET_DEFINE(struct cli_node *, node_start);

	struct cli_conn connections[OFPCLI_CONN_TYPE_CNT];
};

extern __thread struct ofp_cli_mem *shm_cli;

#define	V_cli_os_thread             VNET(shm_cli->os_thread)
#define	V_cli_os_thread_is_running  VNET(shm_cli->os_thread_is_running)
#define	V_cli_lock                  VNET(shm_cli->rwlock)
#define	V_cli_alias_table           VNET(shm_cli->alias_table)
#define	V_cli_alias_table_size      VNET(shm_cli->alias_table_size)
#define	V_cli_node_table            VNET(shm_cli->node_table)
#define	V_cli_node_table_size       VNET(shm_cli->node_table_size)
#define	V_cli_node_free_list        VNET(shm_cli->node_free_list)
#define	V_cli_node_end              VNET(shm_cli->node_end)
#define	V_cli_node_start            VNET(shm_cli->node_start)
#define	V_cli_connections           VNET(shm_cli->connections)

void ofp_cli_init_prepare(void);
int ofp_cli_init_global(void);
int ofp_cli_term_global(void);
int ofp_cli_init_local(void);

struct cli_node *ofp_alloc_node(void);
