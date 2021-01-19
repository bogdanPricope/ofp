/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * @example
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <odp_api.h>

#include "ofpi.h"
#include "ofpi_sysctl.h"
#include "ofpi_util.h"
#include "ofpi_stat.h"
#include "ofpi_portconf.h"
#include "ofpi_route.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_arp.h"
#include "ofpi_avl.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_ifnet.h"
#include "ofpi_ip_shm.h"
#include "ofpi_tcp_shm.h"
#include "ofpi_udp_shm.h"
#include "ofpi_igmp_shm.h"
#include "ofpi_socketvar.h"
#include "ofpi_socket.h"
#include "ofpi_reass.h"
#include "ofpi_inet.h"
#include "ofpi_igmp_var.h"
#include "ofpi_vxlan.h"
#include "ofpi_uma.h"
#include "ofpi_ipsec.h"

#include "ofpi_cli.h"

#include "ofpi_log.h"
#include "ofpi_debug.h"
#ifdef INET6
#include "ofpi_ip6_shm.h"
#endif /*INET6*/

#ifdef SP
#	include "ofpi_sp_shm.h"
#endif /*SP*/

static void drain_scheduler(void);
static void drain_scheduler_for_global_term(void);
static void cleanup_pkt_queue(odp_queue_t pkt_queue);
static int cleanup_interface(struct ofp_ifnet *ifnet);

static int ofp_terminate_stack_global(const char *pool_name);

#ifdef OFP_USE_LIBCONFIG

#include <ctype.h>
#include <libconfig.h>

#define OFP_CONF_FILE_ENV "OFP_CONF_FILE"
#define STR(x) #x

struct lookup_entry {
	const char *name;
	int value;
};

#define ENTRY(x) { #x, (int)x }

struct lookup_entry lt_pktin_mode[] = {
	ENTRY(ODP_PKTIN_MODE_DIRECT),
	ENTRY(ODP_PKTIN_MODE_SCHED),
	ENTRY(ODP_PKTIN_MODE_QUEUE),
	ENTRY(ODP_PKTIN_MODE_DISABLED),
};

struct lookup_entry lt_pktout_mode[] = {
	ENTRY(ODP_PKTOUT_MODE_DIRECT),
	ENTRY(ODP_PKTOUT_MODE_QUEUE),
	ENTRY(ODP_PKTOUT_MODE_TM),
	ENTRY(ODP_PKTOUT_MODE_DISABLED),
};

struct lookup_entry lt_sched_sync[] = {
	ENTRY(ODP_SCHED_SYNC_PARALLEL),
	ENTRY(ODP_SCHED_SYNC_ATOMIC),
	ENTRY(ODP_SCHED_SYNC_ORDERED),
};

struct lookup_entry lt_sched_group[] = {
	ENTRY(ODP_SCHED_GROUP_ALL),
	ENTRY(ODP_SCHED_GROUP_WORKER),
	ENTRY(ODP_SCHED_GROUP_CONTROL),
};

struct lookup_entry lt_ipsec_op_mode[] = {
	ENTRY(ODP_IPSEC_OP_MODE_SYNC),
	ENTRY(ODP_IPSEC_OP_MODE_ASYNC),
	ENTRY(ODP_IPSEC_OP_MODE_INLINE),
	ENTRY(ODP_IPSEC_OP_MODE_DISABLED),
};

struct lookup_entry lt_loglevel[] = {
	{"DISABLED",	OFP_LOG_DISABLED},
	{"ERROR",	OFP_LOG_ERROR},
	{"WARNING",	OFP_LOG_WARNING},
	{"INFO",	OFP_LOG_INFO},
	{"DEBUG",	OFP_LOG_DEBUG}
};

/*
 * Based on a string, lookup a value in a struct lookup_entry
 * array. Return the value from the entry or -1 if not found.
 */
static int lookup(const struct lookup_entry *table, int n, const char *str)
{
#define BUF_LEN 32
	int i, len = strnlen(str, BUF_LEN-1);
	char ustr[BUF_LEN];

	memcpy(ustr, str, len);
	ustr[len] = 0;

	for (i = 0; i < len; i++)
		ustr[i] = toupper(ustr[i]);

	for (i = 0; i < n; i++)
		if (strstr(table[i].name, ustr))
			return table[i].value;

	return -1;
}

static void read_conf_file(ofp_initialize_param_t *params, const char *filename)
{
	config_t conf;
	config_setting_t *setting;
	int length;
	const char *str;
	size_t str_len;
	int i;

	if (!filename) {
		filename = OFP_DEFAULT_CONF_FILE;
		char *filename_env = getenv(OFP_CONF_FILE_ENV);
		if (filename_env) filename = filename_env;
	}

	if (!*filename) return;

	config_init(&conf);
	OFP_DBG("Using configuration file: %s\n", filename);

	if (!config_read_file(&conf, filename)) {
		OFP_ERR("%s(%d): %s\n", config_error_file(&conf),
			config_error_line(&conf), config_error_text(&conf));
		goto done;
	}

	setting = config_lookup(&conf, "ofp_global_param.if_names");

	if (setting && (length = config_setting_length(setting)) > 0) {
		for (i = 0; i < length && i < OFP_FP_INTERFACE_MAX; i++) {
			strncpy(params->if_names[i],
				config_setting_get_string_elem(setting, i),
				OFP_IFNAMSIZ);
			params->if_names[i][OFP_IFNAMSIZ - 1] = '\0';
		}
		params->if_count = i;
	}

#define GET_CONF_STR(lt, p)							\
	if (config_lookup_string(&conf, "ofp_global_param." STR(p), &str)) { \
		i = lookup(lt_ ## lt, sizeof(lt_ ## lt) / sizeof(lt_ ## lt[0]), str); \
		if (i >= 0) params->p = i;				\
	}

#define GET_CONF_STRING(p) do {					\
	if (config_lookup_string(&conf, "ofp_global_param." STR(p), &str)) { \
		str_len  = strlen(str);					\
		if (str_len >= sizeof(params->p) - 1)			\
			str_len = sizeof(params->p) - 1;		\
		strncpy(params->p, str, str_len);			\
		params->p[str_len] = '\0';				\
	}								\
} while (0)

#define GET_CONF_INT(type, p)						\
	if (config_lookup_ ## type(&conf, "ofp_global_param." STR(p), &i)) \
		params->p = i;

	GET_CONF_STR(pktin_mode, pktin_mode);
	GET_CONF_STR(pktout_mode, pktout_mode);
	GET_CONF_STR(sched_sync, sched_sync);
	GET_CONF_STR(sched_group, sched_group);

	GET_CONF_INT(int, linux_core_id);
	GET_CONF_INT(bool, enable_nl_thread);
	GET_CONF_INT(int, arp.entries);
	GET_CONF_INT(int, arp.hash_bits);
	GET_CONF_INT(int, arp.entry_timeout);
	GET_CONF_INT(int, arp.saved_pkt_timeout);
	GET_CONF_INT(bool, arp.check_interface);
	GET_CONF_INT(int, evt_rx_burst_size);
	GET_CONF_INT(int, pkt_tx_burst_size);
	GET_CONF_INT(int, pkt_pool.nb_pkts);
	GET_CONF_INT(int, pkt_pool.buffer_size);
	GET_CONF_INT(int, num_vlan);
	GET_CONF_INT(int, mtrie.routes);
	GET_CONF_INT(int, mtrie.table8_nodes);
	GET_CONF_INT(int, num_vrf);
	GET_CONF_INT(bool, chksum_offload.ipv4_rx_ena);
	GET_CONF_INT(bool, chksum_offload.udp_rx_ena);
	GET_CONF_INT(bool, chksum_offload.tcp_rx_ena);
	GET_CONF_INT(bool, chksum_offload.ipv4_tx_ena);
	GET_CONF_INT(bool, chksum_offload.udp_tx_ena);
	GET_CONF_INT(bool, chksum_offload.tcp_tx_ena);
	GET_CONF_INT(int, ipsec.max_num_sp);
	GET_CONF_INT(int, ipsec.max_num_sa);
	GET_CONF_INT(int, ipsec.max_inbound_spi);
	GET_CONF_STR(ipsec_op_mode, ipsec.inbound_op_mode);
	GET_CONF_STR(ipsec_op_mode, ipsec.outbound_op_mode);

	GET_CONF_INT(int, socket.num_max);
	GET_CONF_INT(int, socket.sd_offset);

	GET_CONF_INT(int, tcp.pcb_tcp_max);
	GET_CONF_INT(int, tcp.pcb_hashtbl_size);
	GET_CONF_INT(int, tcp.pcbport_hashtbl_size);
	GET_CONF_INT(int, tcp.syncache_hashtbl_size);
	GET_CONF_INT(int, tcp.sackhole_max);

	GET_CONF_INT(int, udp.pcb_udp_max);
	GET_CONF_INT(int, udp.pcb_hashtbl_size);
	GET_CONF_INT(int, udp.pcbport_hashtbl_size);

	GET_CONF_INT(bool, if_loopback);

	GET_CONF_STR(loglevel, loglevel);

	GET_CONF_INT(int, debug.flags);
	GET_CONF_STRING(debug.print_filename);
	GET_CONF_INT(int, debug.capture_ports);
	GET_CONF_STRING(debug.capture_filename);
done:
	config_destroy(&conf);
}

#else
#define read_conf_file(params, filename) ((void)filename)
#endif

void ofp_initialize_param_from_file(ofp_initialize_param_t *params,
				    const char *filename)
{
	uint32_t htcp_dflt = 0;
	uint32_t hudp_dflt = 0;

	memset(params, 0, sizeof(*params));
	params->instance = OFP_ODP_INSTANCE_INVALID;
	params->pktin_mode = ODP_PKTIN_MODE_SCHED;
	params->pktout_mode = ODP_PKTIN_MODE_DIRECT;
	params->sched_sync = ODP_SCHED_SYNC_ATOMIC;
	params->sched_group = ODP_SCHED_GROUP_ALL;
#ifdef SP
	params->enable_nl_thread = 1;
#endif /* SP */
	params->arp.entries = OFP_ARP_ENTRIES;
	params->arp.hash_bits = OFP_ARP_HASH_BITS;
	params->arp.entry_timeout = OFP_ARP_ENTRY_TIMEOUT;
	params->arp.saved_pkt_timeout = OFP_ARP_SAVED_PKT_TIMEOUT;
	params->evt_rx_burst_size = OFP_EVT_RX_BURST_SIZE;
	params->pkt_pool.nb_pkts = SHM_PKT_POOL_NB_PKTS;
	params->pkt_pool.buffer_size = SHM_PKT_POOL_BUFFER_SIZE;
	params->pkt_tx_burst_size = OFP_PKT_TX_BURST_SIZE;
	params->num_vlan = OFP_NUM_VLAN;
	params->mtrie.routes = OFP_ROUTES;
	params->mtrie.table8_nodes = OFP_MTRIE_TABLE8_NODES;
	params->num_vrf = OFP_NUM_VRF;
	params->chksum_offload.ipv4_rx_ena = OFP_CHKSUM_OFFLOAD_IPV4_RX;
	params->chksum_offload.udp_rx_ena = OFP_CHKSUM_OFFLOAD_UDP_RX;
	params->chksum_offload.tcp_rx_ena = OFP_CHKSUM_OFFLOAD_TCP_RX;
	params->chksum_offload.ipv4_tx_ena = OFP_CHKSUM_OFFLOAD_IPV4_TX;
	params->chksum_offload.udp_tx_ena = OFP_CHKSUM_OFFLOAD_UDP_TX;
	params->chksum_offload.tcp_tx_ena = OFP_CHKSUM_OFFLOAD_TCP_TX;
	ofp_ipsec_param_init(&params->ipsec);

	params->socket.num_max = OFP_NUM_SOCKETS_MAX;
	params->socket.sd_offset = OFP_SOCK_NUM_OFFSET;

	params->tcp.pcb_tcp_max = OFP_NUM_PCB_TCP_MAX;
	params->tcp.sackhole_max = 0; /* to be computed */
	params->tcp.pcb_hashtbl_size = 0; /* to be computed */
	params->tcp.pcbport_hashtbl_size = 0; /* to be computed */
	params->tcp.syncache_hashtbl_size = 0; /* to be computed */

	params->udp.pcb_udp_max = OFP_NUM_PCB_UDP_MAX;
	params->udp.pcb_hashtbl_size = 0; /* to be computed */
	params->udp.pcbport_hashtbl_size = 0; /* to be computed */

	params->if_loopback = 0;

#ifdef OFP_DEBUG
	params->loglevel = OFP_LOG_DEBUG;
#else
	params->loglevel = OFP_LOG_INFO;
#endif

	params->debug.flags = 0;
	params->debug.print_filename[0] = 0;
	params->debug.capture_ports = 0;
	params->debug.capture_filename[0] = 0;

	read_conf_file(params, filename);

	htcp_dflt = ofp_hashsize_dflt(params->tcp.pcb_tcp_max);
	if (!params->tcp.pcb_hashtbl_size)
		params->tcp.pcb_hashtbl_size = (int)
			ofp_hashsize_pow2(htcp_dflt);
	else
		params->tcp.pcb_hashtbl_size = (int)
			ofp_hashsize_pow2(params->tcp.pcb_hashtbl_size);

	if (!params->tcp.pcbport_hashtbl_size)
		params->tcp.pcbport_hashtbl_size = (int)
			ofp_hashsize_pow2(htcp_dflt);
	else
		params->tcp.pcbport_hashtbl_size = (int)
			ofp_hashsize_pow2(params->tcp.pcbport_hashtbl_size);

	if (!params->tcp.syncache_hashtbl_size)
		params->tcp.syncache_hashtbl_size = (int)
			ofp_hashsize_pow2(htcp_dflt);
	else
		params->tcp.syncache_hashtbl_size = (int)
			ofp_hashsize_pow2(params->tcp.syncache_hashtbl_size);

	hudp_dflt = ofp_hashsize_dflt(params->udp.pcb_udp_max);
	if (!params->udp.pcb_hashtbl_size)
		params->udp.pcb_hashtbl_size = (int)
			ofp_hashsize_pow2(hudp_dflt);
	else
		params->udp.pcb_hashtbl_size = (int)
			ofp_hashsize_pow2(params->udp.pcb_hashtbl_size);

	if (!params->udp.pcbport_hashtbl_size)
		params->udp.pcbport_hashtbl_size = (int)
			ofp_hashsize_pow2(hudp_dflt);
	else
		params->udp.pcbport_hashtbl_size = (int)
			ofp_hashsize_pow2(params->udp.pcbport_hashtbl_size);

	if (!params->tcp.sackhole_max)
		params->tcp.sackhole_max = 4 * params->tcp.pcb_tcp_max;
}

void ofp_initialize_param(ofp_initialize_param_t *params)
{
	ofp_initialize_param_from_file(params, NULL);
}

static void ofp_init_prepare(void)
{
	/*
	 * Shared memory preallocations or other preparations before
	 * actual global initializations can be done here.
	 *
	 * ODP has been fully initialized but OFP not yet. At this point
	 * global_param can be accessed and ofp_shared_memory_prealloc()
	 * can be called.
	 */
	ofp_uma_init_prepare();
#ifdef SP
	ofp_sp_init_prepare();
#endif /*SP*/
	ofp_sysctl_init_prepare();
	ofp_avl_init_prepare();
	ofp_reassembly_init_prepare();
	ofp_debug_init_prepare();
	ofp_stat_init_prepare();
	ofp_timer_init_prepare();
	ofp_hook_init_prepare();
	ofp_arp_init_prepare();
	ofp_route_init_prepare();
	ofp_portconf_init_prepare();
	ofp_vlan_init_prepare();
	ofp_vxlan_init_prepare();
	ofp_socket_init_prepare();
	ofp_tcp_var_init_prepare();
	ofp_udp_var_init_prepare();
	ofp_igmp_var_init_prepare();
	ofp_ip_init_prepare();
#ifdef INET6
	ofp_ip6_init_prepare();
#endif /*INET6*/
	ofp_ipsec_init_prepare(&global_param->ipsec);
}

static int ofp_initialize_stack_global(ofp_initialize_param_t *params,
				       odp_instance_t instance,
				       odp_bool_t instance_owner)
{
	/*
	 * Allocate and initialize global config memory first so that it
	 * is available to later init phases.
	 */
	HANDLE_ERROR(ofp_global_param_init_global(params, instance,
						  instance_owner));

	/* Initialize shared memory infra before preallocations */
	HANDLE_ERROR(ofp_shared_memory_init_global());
	/* Let different code modules preallocate shared memory */
	ofp_init_prepare();
	/* Finish preallocation phase before the corresponding allocations */
	HANDLE_ERROR(ofp_shared_memory_prealloc_finish());

	HANDLE_ERROR(ofp_sysctl_init_global());

	/* Initialize the UM allocator before doing other inits */
	HANDLE_ERROR(ofp_uma_init_global());

#ifdef SP
	HANDLE_ERROR(ofp_sp_init_global());
#endif /*SP*/

	HANDLE_ERROR(ofp_avl_init_global());

	HANDLE_ERROR(ofp_reassembly_init_global());

	HANDLE_ERROR(ofp_debug_init_global());

	HANDLE_ERROR(ofp_stat_init_global());

	HANDLE_ERROR(ofp_timer_init_global(OFP_TIMER_RESOLUTION_US,
			OFP_TIMER_MIN_US,
			OFP_TIMER_MAX_US,
			OFP_TIMER_TMO_COUNT,
			params->sched_group));

	HANDLE_ERROR(ofp_hook_init_global(params->pkt_hook));

	HANDLE_ERROR(ofp_arp_init_global());

	HANDLE_ERROR(ofp_route_init_global());

	HANDLE_ERROR(ofp_vlan_init_global());

	HANDLE_ERROR(ofp_portconf_init_global());

	HANDLE_ERROR(ofp_vxlan_init_global());

	odp_pool_param_t pool_params;
	odp_pool_param_init(&pool_params);
	/* Define pkt.seg_len so that l2/l3/l4 offset fits in first segment */
	pool_params.pkt.seg_len    = global_param->pkt_pool.buffer_size;
	pool_params.pkt.len        = global_param->pkt_pool.buffer_size;
	pool_params.pkt.num        = params->pkt_pool.nb_pkts;
	pool_params.pkt.uarea_size = ofp_packet_min_user_area();
	pool_params.type           = ODP_POOL_PACKET;

	V_global_packet_pool = ofp_pool_create(SHM_PKT_POOL_NAME, &pool_params);
	if (V_global_packet_pool == ODP_POOL_INVALID) {
		OFP_ERR("odp_pool_create failed");
		return -1;
	}

	HANDLE_ERROR(ofp_socket_init_global(V_global_packet_pool));
	HANDLE_ERROR(ofp_ip_init_global());
#ifdef INET6
	HANDLE_ERROR(ofp_ip6_init_global());
#endif /*INET6*/
	HANDLE_ERROR(ofp_tcp_var_init_global());
	HANDLE_ERROR(ofp_udp_var_init_global());
	HANDLE_ERROR(ofp_igmp_var_init_global());
	HANDLE_ERROR(ofp_inet_init());
	HANDLE_ERROR(ofp_ipsec_init_global(&params->ipsec));

	return 0;
}

enum ofp_init_state {
	OFP_INIT_STATE_NOT_INIT = 0,
	OFP_INIT_STATE_ODP_INIT,
	OFP_INIT_STATE_STACK_INIT,
	OFP_INIT_STATE_VXLAN_INIT,
	OFP_INIT_STATE_INTERFACES_INIT,
	OFP_INIT_STATE_NL_INIT,
	OFP_INIT_STATE_LOOPBACK_INIT,
	OFP_INIT_STATE_OFP_LOCAL_INIT
};

int ofp_initialize(ofp_initialize_param_t *params)
{
	int i;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	const char *err;
	odp_instance_t instance;
	odp_bool_t instance_owner = 0;
	enum ofp_init_state state = OFP_INIT_STATE_NOT_INIT;

	if (!params) {
		OFP_LOG_NO_CTX_NO_LEVEL("Invalid argument (null).");
		return -1;
	}

	instance = params->instance;

	state = OFP_INIT_STATE_ODP_INIT;
	/* Create odp instance  if not provided as argument */
	if (instance == OFP_ODP_INSTANCE_INVALID) {
		if (odp_init_global(&instance, NULL, NULL)) {
			OFP_LOG_NO_CTX_NO_LEVEL("Error: ODP global init "
						"failed.\n");
			return -1;
		}
		if (odp_init_local(instance, ODP_THREAD_CONTROL) != 0) {
			OFP_LOG_NO_CTX_NO_LEVEL("Error: ODP local init "
						"failed.\n");
			odp_term_global(instance);
			return -1;
		}
		instance_owner = 1;
	}

#if ODP_VERSION_API_GENERATION >= 1 && ODP_VERSION_API_MAJOR >= 21
	odp_schedule_config(NULL);
#endif

	state = OFP_INIT_STATE_STACK_INIT;
	if (ofp_initialize_stack_global(params, instance, instance_owner))
		goto init_error;

	state = OFP_INIT_STATE_VXLAN_INIT;
	if (ofp_set_vxlan_interface_queue())
		goto init_error;

	state = OFP_INIT_STATE_INTERFACES_INIT;
	/* Create interfaces */
	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = params->pktin_mode;
	pktio_param.out_mode = params->pktout_mode;

	ofp_pktin_queue_param_init(&pktin_param, pktio_param.in_mode,
				   params->sched_sync,
				   params->sched_group);

	for (i = 0; i < params->if_count; ++i) {
		if (ofp_ifnet_create(params->if_names[i],
				     &pktio_param, &pktin_param, NULL)) {
			OFP_LOG_NO_CTX_NO_LEVEL("Error: failed to create "
					"interface %s.\n", params->if_names[i]);
			goto init_error;
		}
	}

#ifdef SP
	OFP_INFO("Slow path threads on core %d",
		 odp_cpumask_first(&V_global_linux_cpumask));

	state = OFP_INIT_STATE_NL_INIT;
	if (params->enable_nl_thread) {
		odph_odpthread_params_t thr_params;

		/* Start Netlink server process */
		thr_params.start = START_NL_SERVER;
		thr_params.arg = NULL;
		thr_params.thr_type = ODP_THREAD_CONTROL;
		thr_params.instance = V_global_odp_instance;
		if (!odph_odpthreads_create(&V_global_nl_thread,
					    &V_global_linux_cpumask,
					    &thr_params)) {
			OFP_ERR("Failed to start Netlink thread.");
			goto init_error;
		}
		V_global_nl_thread_is_running = 1;
	}
#endif /* SP */

	state = OFP_INIT_STATE_LOOPBACK_INIT;
	if (params->if_loopback) {
		uint32_t loop_addr = odp_cpu_to_be_32(OFP_INADDR_LOOPBACK);

		err = ofp_config_interface_up_local(0, 0, loop_addr, 8);
		if (err != NULL) {
			OFP_ERR("Failed to create the interface: %s.", err);
			state = OFP_INIT_STATE_LOOPBACK_INIT;
			goto init_error;
		}
	}

	odp_schedule_resume();

	state = OFP_INIT_STATE_OFP_LOCAL_INIT;
	if (ofp_init_local_resources() != 0) {
		OFP_ERR("Failed to thread local settings");
		goto init_error;
	}

	return 0;

init_error:
	switch (state) {
	case OFP_INIT_STATE_OFP_LOCAL_INIT:
		ofp_term_local_resources();
		/* Fallthrough */
	case OFP_INIT_STATE_LOOPBACK_INIT:
		ofp_local_interfaces_destroy();
		/* Fallthrough */
	case OFP_INIT_STATE_NL_INIT:
#ifdef SP
		ofp_stop_processing();

		if (V_global_nl_thread_is_running) {
			odph_odpthreads_join(&V_global_nl_thread);
			V_global_nl_thread_is_running = 0;
		}
#endif /* SP */
		/* Fallthrough */
	case OFP_INIT_STATE_INTERFACES_INIT:
		{
			struct ofp_ifnet *ifnet = NULL;

			ofp_stop_processing();

			for (i = 0; PHYS_PORT(i); i++) {
				ifnet = ofp_get_ifnet((uint16_t)i, 0);
				if (!ifnet)
					continue;

				cleanup_interface(ifnet);
			}
		}
		/* Fallthrough */
	case OFP_INIT_STATE_VXLAN_INIT:
		ofp_clean_vxlan_interface_queue();
		/* Fallthrough */
	case OFP_INIT_STATE_STACK_INIT:
		ofp_terminate_stack_global(SHM_PKT_POOL_NAME);

		/* Terminate shared memory */
		ofp_shared_memory_term_global();
		/* Fallthrough */
	case OFP_INIT_STATE_ODP_INIT:
		if (instance_owner) {
			if (odp_term_local() < 0)
				OFP_LOG_NO_CTX_NO_LEVEL("Error: odp_term_local "
						"failed\n");

			if (odp_term_global(instance) < 0)
				OFP_LOG_NO_CTX_NO_LEVEL("Error: odp_term_global"
						" failed\n");
		}
		/* Fallthrough */
	case OFP_INIT_STATE_NOT_INIT:
	default:
		state = OFP_INIT_STATE_NOT_INIT;
	}
	return -1;
}


int ofp_init_local_resources(void)
{
	/* This must be done first */
	HANDLE_ERROR(ofp_shared_memory_init_local());

	/* Lookup shared memories */
	HANDLE_ERROR(ofp_global_param_init_local());
	HANDLE_ERROR(ofp_uma_lookup_shared_memory());
#ifdef SP
	HANDLE_ERROR(ofp_sp_init_local());
#endif /*SP*/
	HANDLE_ERROR(ofp_sysctl_init_local());
	HANDLE_ERROR(ofp_portconf_lookup_shared_memory());
	HANDLE_ERROR(ofp_vlan_lookup_shared_memory());
	HANDLE_ERROR(ofp_route_lookup_shared_memory());
	HANDLE_ERROR(ofp_vrf_route_lookup_shared_memory());
	HANDLE_ERROR(ofp_avl_lookup_shared_memory());
	HANDLE_ERROR(ofp_reassembly_lookup_shared_memory());
	HANDLE_ERROR(ofp_debug_lookup_shared_memory());
	HANDLE_ERROR(ofp_stat_lookup_shared_memory());
	HANDLE_ERROR(ofp_socket_lookup_shared_memory());
	HANDLE_ERROR(ofp_timer_lookup_shared_memory());
	HANDLE_ERROR(ofp_hook_lookup_shared_memory());
	HANDLE_ERROR(ofp_arp_lookup_shared_memory());
	HANDLE_ERROR(ofp_vxlan_lookup_shared_memory());
	HANDLE_ERROR(ofp_in_proto_init_local());
	HANDLE_ERROR(ofp_arp_init_local());
	HANDLE_ERROR(ofp_ip_init_local());
#ifdef INET6
	HANDLE_ERROR(ofp_ip6_init_local());
#endif /*INET6*/
	HANDLE_ERROR(ofp_tcp_var_init_local());
	HANDLE_ERROR(ofp_udp_var_init_local());
	HANDLE_ERROR(ofp_igmp_var_init_local());
	HANDLE_ERROR(ofp_send_pkt_out_init_local());
	HANDLE_ERROR(ofp_ipsec_init_local());

	return 0;
}

int ofp_terminate(void)
{
	int rc = 0;
	uint16_t i;
	struct ofp_ifnet *ifnet;
	odp_instance_t odp_instance = OFP_ODP_INSTANCE_INVALID;
	odp_bool_t odp_instance_owner = 0;

	CHECK_ERROR(ofp_term_local_resources(), rc);

	odp_instance = V_global_odp_instance;
	odp_instance_owner = V_global_odp_instance_owner;

	ofp_stop_processing();
#ifdef CLI
	/* Terminate CLI thread*/
	CHECK_ERROR(ofp_stop_cli_thread(), rc);
#endif

#ifdef SP
	/* Terminate Netlink thread*/
	if (V_global_nl_thread_is_running) {
		odph_odpthreads_join(&V_global_nl_thread);
		V_global_nl_thread_is_running = 0;
	}
#endif /* SP */

	/* Cleanup interfaces: queues and pktios*/
	for (i = 0; PHYS_PORT(i); i++) {
		ifnet = ofp_get_ifnet((uint16_t)i, 0);
		if (!ifnet) {
			OFP_ERR("Failed to locate interface for port %d", i);
			rc = -1;
			continue;
		}

		if (cleanup_interface(ifnet)) {
			rc = -1;
			continue;
		}
	}

	CHECK_ERROR(ofp_clean_vxlan_interface_queue(), rc);
	CHECK_ERROR(ofp_local_interfaces_destroy(), rc);

	if (ofp_terminate_stack_global(SHM_PKT_POOL_NAME)) {
		OFP_ERR("Failed to cleanup resources\n");
		rc = -1;
	}

	/* Terminate shared memory now that all blocks have been freed. */
	CHECK_ERROR(ofp_shared_memory_term_global(), rc);

	if (odp_instance_owner) {
		if (odp_term_local() < 0)
			OFP_LOG_NO_CTX_NO_LEVEL("Error: odp_term_local "
					"failed\n");

		if (odp_term_global(odp_instance) < 0)
			OFP_LOG_NO_CTX_NO_LEVEL("Error: odp_term_global "
					"failed\n");
	}

	return rc;
}

int ofp_terminate_stack_global(const char *pool_name)
{
	odp_pool_t pool;
	int rc = 0;

	/* Cleanup sockets */
	CHECK_ERROR(ofp_socket_term_global(), rc);

	/* Cleanup of IGMP content */
	CHECK_ERROR(ofp_igmp_var_term_global(), rc);

	/* Cleanup of TCP content */
	CHECK_ERROR(ofp_tcp_var_term_global(), rc);

	/* Cleanup of UDP content */
	CHECK_ERROR(ofp_udp_var_term_global(), rc);

	/* Cleanup of IP content */
	CHECK_ERROR(ofp_ip_term_global(), rc);

#ifdef INET6
	/* Cleanup of IP6 content */
	CHECK_ERROR(ofp_ip6_term_global(), rc);
#endif /*INET6*/

	/* Cleanup vxlan */
	CHECK_ERROR(ofp_vxlan_term_global(), rc);

	/* Cleanup interface related objects */
	CHECK_ERROR(ofp_portconf_term_global(), rc);
	CHECK_ERROR(ofp_vlan_term_global(), rc);

	/* Cleanup routes */
	CHECK_ERROR(ofp_route_term_global(), rc);

	/* Cleanup ARP*/
	CHECK_ERROR(ofp_arp_term_global(), rc);

	/* Cleanup hooks */
	CHECK_ERROR(ofp_hook_term_global(), rc);

	/* Cleanup stats */
	CHECK_ERROR(ofp_stat_term_global(), rc);

	/* Cleanup debug */
	CHECK_ERROR(ofp_debug_term_global(), rc);

	/* Cleanup reassembly queues*/
	CHECK_ERROR(ofp_reassembly_term_global(), rc);

	/* Cleanup avl trees*/
	CHECK_ERROR(ofp_avl_term_global(), rc);

	/* Cleanup timers - phase 1*/
	CHECK_ERROR(ofp_timer_stop_global(), rc);

	/* Stop IPsec. This may generate events that need to be handled. */
	CHECK_ERROR(ofp_ipsec_stop_global(), rc);

	/*
	 * ofp_term_local_resources() has paused scheduling for this thread.
	 * Resume scheduling temporarily for draining events created during
	 * global termination.
	 */
	odp_schedule_resume();

	/* Cleanup pending events */
	drain_scheduler_for_global_term();

	/*
	 * Now pause scheduling permanently and drain events once more
	 * as suggested by the ODP API.
	 */
	odp_schedule_pause();
	drain_scheduler();

	/* Cleanup timers - phase 2*/
	CHECK_ERROR(ofp_timer_term_global(), rc);

	/* Cleanup IPsec */
	CHECK_ERROR(ofp_ipsec_term_global(), rc);

	/* Cleanup packet pool */
	pool = odp_pool_lookup(pool_name);
	if (pool == ODP_POOL_INVALID) {
		OFP_ERR("Failed to locate pool %s\n", pool_name);
		rc = -1;
	} else if (odp_pool_destroy(pool) < 0) {
		OFP_ERR("Failed to destroy pool %s.\n", pool_name);
		rc = -1;
		pool = ODP_POOL_INVALID;
	}

	CHECK_ERROR(ofp_sysctl_term_global(), rc);

#ifdef SP
	CHECK_ERROR(ofp_sp_term_global(), rc);
#endif /*SP*/

	CHECK_ERROR(ofp_uma_term_global(), rc);

	CHECK_ERROR(ofp_global_param_term_global(), rc);

	return rc;
}

int ofp_term_local_resources(void)
{
	int rc = 0;

	odp_schedule_pause();
	drain_scheduler();

	CHECK_ERROR(ofp_ip_term_local(), rc);
#ifdef INET6
	CHECK_ERROR(ofp_ip6_term_local(), rc);
#endif /*INET6*/
	CHECK_ERROR(ofp_send_pkt_out_term_local(), rc);

	return rc;
}

static void drain_scheduler(void)
{
	odp_event_t evt;
	odp_queue_t from;

	while (1) {
		evt = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (evt == ODP_EVENT_INVALID)
			break;
		switch (odp_event_type(evt)) {
		case ODP_EVENT_TIMEOUT:
			{
				ofp_timer_evt_cleanup(evt);
				break;
			}
		case ODP_EVENT_IPSEC_STATUS:
			if (ofp_ipsec_sad_init_local())
				odp_event_free(evt);
			else
				ofp_ipsec_status_event(evt, from);
			break;
		default:
			odp_event_free(evt);
		}
	}
}

static void drain_scheduler_for_global_term(void)
{
	odp_time_t start, now;

	start = odp_time_local();

	while (1) {
		drain_scheduler();
		if (ofp_ipsec_term_global_ok())
			break;
		now = odp_time_local();
		if (odp_time_diff_ns(now, start) > NS_PER_SEC) {
			OFP_ERR("Giving up waiting ODP IPsec SA destruction");
			break;
		}
	}
}

static void cleanup_pkt_queue(odp_queue_t pkt_queue)
{
	odp_event_t evt;

	if (odp_queue_type(pkt_queue) == ODP_QUEUE_TYPE_SCHED)
		return;

	while (1) {
		evt = odp_queue_deq(pkt_queue);
		if (evt == ODP_EVENT_INVALID)
			break;
		if (odp_event_type(evt) == ODP_EVENT_PACKET)
			odp_packet_free(odp_packet_from_event(evt));
	}
}

static int cleanup_interface(struct ofp_ifnet *ifnet)
{
	int rc = 0;
	uint16_t j = 0;

	if (!ifnet) {
		OFP_ERR("Error: Invalid argument");
		return -1;
	}

	if (ifnet->if_state == OFP_IFT_STATE_FREE)
		return 0;

	if (ifnet->pktio == ODP_PKTIO_INVALID)
		return 0;

	OFP_INFO("Cleaning device '%s' addr %s", ifnet->if_name,
		 ofp_print_mac((uint8_t *)ifnet->mac));

	CHECK_ERROR(odp_pktio_stop(ifnet->pktio), rc);
#ifdef SP
	odph_odpthreads_join(ifnet->rx_tbl);
	odph_odpthreads_join(ifnet->tx_tbl);
	close(ifnet->fd);
	ifnet->fd = -1;
#endif /*SP*/

	/* Multicasting. */
	ofp_igmp_domifdetach(ifnet);
	ifnet->ii_inet.ii_igmp = NULL;

	if (ifnet->loopq_def != ODP_QUEUE_INVALID) {
		if (odp_queue_destroy(ifnet->loopq_def) < 0) {
			OFP_ERR("Failed to destroy loop queue for %s",
				ifnet->if_name);
			rc = -1;
		}
		ifnet->loopq_def = ODP_QUEUE_INVALID;
	}
#ifdef SP
	if (ifnet->spq_def != ODP_QUEUE_INVALID) {
		cleanup_pkt_queue(ifnet->spq_def);
		if (odp_queue_destroy(ifnet->spq_def) < 0) {
			OFP_ERR("Failed to destroy slow path "
				"queue for %s", ifnet->if_name);
			rc = -1;
		}
		ifnet->spq_def = ODP_QUEUE_INVALID;
	}
#endif /*SP*/
	for (j = 0; j < OFP_PKTOUT_QUEUE_MAX; j++)
		ifnet->out_queue_queue[j] = ODP_QUEUE_INVALID;

	if (ifnet->pktio != ODP_PKTIO_INVALID) {
		int num_queues = odp_pktin_event_queue(ifnet->pktio, NULL, 0);
		odp_queue_t in_queue[num_queues];
		int num_in_queue, idx;

		num_in_queue = odp_pktin_event_queue(ifnet->pktio,
						     in_queue, num_queues);

		for (idx = 0; idx < num_in_queue; idx++)
			cleanup_pkt_queue(in_queue[idx]);

		if (odp_pktio_close(ifnet->pktio) < 0) {
			OFP_ERR("Failed to destroy pktio for %s",
				ifnet->if_name);
			rc = -1;
		}
		ifnet->pktio = ODP_PKTIO_INVALID;
	}

	return rc;
}

