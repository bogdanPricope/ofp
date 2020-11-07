/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_init.h"
#include "ofpi_tcp_shm.h"
#include "ofpi_tcp_timer.h"

#define SHM_NAME_TCP_VAR "OfpTcpVarShMem"

/*
 * Data per core
 */
__thread struct ofp_tcp_var_mem *shm_tcp;
__thread struct inpcbhead *shm_tcp_hashtbl;
__thread struct inpcbporthead *shm_tcp_porthashtbl;
__thread struct syncache_head *shm_tcp_syncachehashtbl;

static uint64_t get_shm_tcp_hashtbl_size(void)
{
#ifdef OFP_RSS
	return OFP_MAX_NUM_CPU *
		global_param->tcp.pcb_hashtbl_size *
		sizeof(struct inpcbhead);
#else
	return global_param->tcp.pcb_hashtbl_size *
		sizeof(struct inpcbhead);
#endif /*OFP_RSS*/
}

static uint64_t get_shm_tcp_porthashtbl_size(void)
{
#ifdef OFP_RSS
	return OFP_MAX_NUM_CPU *
		global_param->tcp.pcbport_hashtbl_size *
		sizeof(struct inpcbporthead);
#else
	return global_param->tcp.pcbport_hashtbl_size *
		sizeof(struct inpcbporthead);
#endif /*OFP_RSS*/
}

static uint64_t get_shm_tcp_syncachehashtbl_size(void)
{
	return global_param->tcp.syncache_hashtbl_size *
		sizeof(struct syncache_head);
}

static uint64_t ofp_tcp_var_get_shm_size(void)
{
	return sizeof(*shm_tcp) +
		get_shm_tcp_hashtbl_size() +
		get_shm_tcp_porthashtbl_size() +
		get_shm_tcp_syncachehashtbl_size();
}

static int ofp_tcp_var_alloc_shared_memory(void)
{
	shm_tcp = ofp_shared_memory_alloc(SHM_NAME_TCP_VAR,
					  ofp_tcp_var_get_shm_size());
	if (shm_tcp == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_tcp_var_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_TCP_VAR) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_tcp = NULL;

	return rc;
}

static int ofp_tcp_var_lookup_shared_memory(void)
{
	shm_tcp = ofp_shared_memory_lookup(SHM_NAME_TCP_VAR);
	if (shm_tcp == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	shm_tcp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_tcp + shm_tcp->hashtbl_off);
	shm_tcp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_tcp + shm_tcp->porthashtbl_off);
	shm_tcp_syncachehashtbl = (struct syncache_head *)
		((uint8_t *)shm_tcp + shm_tcp->syncachehashtbl_off);

	return 0;
}

void ofp_tcp_var_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_TCP_VAR,
				   ofp_tcp_var_get_shm_size());
}

int ofp_tcp_var_init_global(void)
{
	HANDLE_ERROR(ofp_tcp_var_alloc_shared_memory());
	memset(shm_tcp, 0, (size_t)ofp_tcp_var_get_shm_size());

	shm_tcp->hashtbl_off = sizeof(*shm_tcp);
	shm_tcp->hashtbl_size = (uint32_t)global_param->tcp.pcb_hashtbl_size;

	shm_tcp->porthashtbl_off =
		shm_tcp->hashtbl_off + get_shm_tcp_hashtbl_size();
	shm_tcp->porthashtbl_size =
		(uint32_t)global_param->tcp.pcbport_hashtbl_size;

	shm_tcp->syncachehashtbl_off =
		shm_tcp->porthashtbl_off + get_shm_tcp_porthashtbl_size();
	shm_tcp->syncachehashtbl_size =
		(uint32_t)global_param->tcp.syncache_hashtbl_size;

	shm_tcp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_tcp + shm_tcp->hashtbl_off);
	shm_tcp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_tcp + shm_tcp->porthashtbl_off);
	shm_tcp_syncachehashtbl = (struct syncache_head *)
		((uint8_t *)shm_tcp + shm_tcp->syncachehashtbl_off);

	/* TCP input*/
	V_tcp_log_in_vain = 0;
	V_tcp_blackhole = 0;
	V_tcp_delack_enabled = 1;
	V_tcp_drop_synfin = 0;
	V_tcp_do_rfc3042 = 0;
	V_tcp_do_rfc3390 = 1;
	V_tcp_do_rfc3465 = 1;
	V_tcp_abc_l_var = 2;
	V_tcp_do_ecn = 0;
	V_tcp_ecn_maxretries = 1;

	V_tcp_insecure_rst = 0;
	V_tcp_do_autorcvbuf = 1;
	V_tcp_autorcvbuf_inc = 16 * 1024;
	V_tcp_autorcvbuf_max = 2 * 1024 * 1024;
	V_tcp_passive_trace = 0;

	/*TCP output*/
	V_tcp_path_mtu_discovery = 1;
	V_tcp_ss_fltsz = 1;
	V_tcp_ss_fltsz_local = 4;
	V_tcp_do_tso = 1;
	V_tcp_do_autosndbuf = 1;
	V_tcp_autosndbuf_inc = 8 * 1024;
	V_tcp_autosndbuf_max = 2 * 1024 * 1024;

	/*TCP userreq*/
	V_tcp_sendspace = 1024 * 32;
	V_tcp_recvspace = 1024 * 64;

	/*TCP SACK*/
	V_tcp_do_sack = 1;
	V_tcp_sack_maxholes = 128;
	V_tcp_sack_globalmaxholes = 65536;
	V_tcp_sack_globalholes = 0;

	/*TCP syncookies*/
	V_tcp_syncookies = 1;
	V_tcp_syncookiesonly = 0;
	V_tcp_sc_rst_sock_fail = 1;

	/* TCP REASSEMBLY*/
	V_tcp_reass_maxseg = 0;
	V_tcp_reass_qsize = 0;
	V_tcp_reass_overflows = 0;

	/* TCP timewait */
	V_tcp_maxtcptw = 0;
	V_nolocaltimewait = 0;

	/* TCP subr */
	V_tcp_maxprotohdr = 0;
	V_tcp_mssdflt = OFP_TCP_MSS;
#ifdef INET6
	V_tcp_v6mssdflt = OFP_TCP6_MSS;
#endif /*INET6*/
	V_tcp_minmss = OFP_TCP_MINMSS;
	V_tcp_do_rfc1323 = 1;
	V_tcp_log_debug = 0;
	V_tcp_tcbhashsize = 0;
	V_tcp_do_tcpdrain = 1;
	V_tcp_icmp_may_rst = 1;
	V_tcp_isn_reseed_interval = 0;
	V_tcp_soreceive_stream = 0;
	V_tcp_keepinit = 0;		/* initialized with ofp_tcp_init */
	V_tcp_keepidle = 0;		/* initialized with ofp_tcp_init */
	V_tcp_keepintvl = 0;	/* initialized with ofp_tcp_init */
	V_tcp_delacktime = 0;	/* initialized with ofp_tcp_init */
	V_tcp_msl = 0;			/* initialized with ofp_tcp_init */
	V_tcp_rexmit_min = 0;	/* initialized with ofp_tcp_init */
	V_tcp_rexmit_slop = 0;	/* initialized with ofp_tcp_init */
	V_tcp_always_keepalive = 1;
	V_tcp_fast_finwait2_recycle = 0;
	V_tcp_finwait2_timeout = 0;	/* initialized with ofp_tcp_init */
	V_tcp_keepcnt = TCPTV_KEEPCNT;
	V_tcp_maxpersistidle = 0;	/* initialized with ofp_tcp_init */
	V_tcp_timer_race = 0;
	return 0;
}

int ofp_tcp_var_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_tcp_var_free_shared_memory(), rc);

	return rc;
}

int ofp_tcp_var_init_local(void)
{
	if (ofp_tcp_var_lookup_shared_memory()) {
		OFP_ERR("ofp_tcp_var_lookup_shared_memory failed");
		return -1;
	}

	if (ofp_tcp_input_init_local()) {
		OFP_ERR("ofp_tcp_input_init_local failed");
		return -1;
	}

	if (ofp_tcp_output_init_local()) {
		OFP_ERR("ofp_tcp_output_init_local failed");
		return -1;
	}

	if (ofp_tcp_usrreq_init_local()) {
		OFP_ERR("ofp_tcp_usrreq_init_local failed");
		return -1;
	}

	if (ofp_tcp_sack_init_local()) {
		OFP_ERR("ofp_tcp_sack_init_local failed");
		return -1;
	}

	if (ofp_tcp_syncache_init_local()) {
		OFP_ERR("ofp_tcp_syncache_init_local failed");
		return -1;
	}

	if (ofp_tcp_reass_init_local()) {
		OFP_ERR("ofp_tcp_reass_init_local failed");
		return -1;
	}

	if (ofp_tcp_timewait_init_local()) {
		OFP_ERR("ofp_tcp_timewait_init_local failed");
		return -1;
	}

	if (ofp_tcp_subr_init_local()) {
		OFP_ERR("ofp_tcp_subr_init_local failed");
		return -1;
	}

	if (ofp_tcp_timer_init_local()) {
		OFP_ERR("ofp_tcp_timer_init_local failed");
		return -1;
	}
	return 0;
}
