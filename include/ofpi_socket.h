/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_SOCKET_H__
#define __OFPI_SOCKET_H__

#include "odp_api.h"
#include "api/ofp_socket.h"
#include "api/ofp_socket_sigevent.h"
#include "ofpi_queue.h"
#include "ofpi_vnet.h"

struct socket;

struct ofp_socket_mem {
	struct socket *free_sockets;
	int sockets_allocated, max_sockets_allocated;
	int socket_zone;

	odp_rwlock_t so_global_mtx;
	odp_rwlock_t ofp_accept_mtx;
	int somaxconn;
	odp_pool_t pool;

	struct sleeper {
		struct sleeper *next;
		void *channel;
		const char *wmesg;
		int   go;
		odp_timer_t tmo;
		int woke_by_timer;
	} *sleep_list;
	struct sleeper *free_sleepers;
	odp_spinlock_t sleep_lock;

	uint32_t socket_list_off;
	uint32_t sleeper_list_off;

	VNET_DEFINE(uint64_t, sb_max);
	VNET_DEFINE(uint64_t, sb_efficiency);
};

extern __thread struct ofp_socket_mem *shm_socket;

#define	V_sb_max VNET(shm_socket->sb_max)
#define	V_sb_efficiency VNET(shm_socket->sb_efficiency)

int ofp_socket_wakeup_all(void);

int ofp_socket_lookup_shared_memory(void);
void ofp_socket_init_prepare(void);
int ofp_socket_init_global(odp_pool_t);
int ofp_socket_term_global(void);

#endif /* __OFPI_SOCKET_H__ */
