/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_TCP_SHM_H__
#define __OFPI_TCP_SHM_H__

#include "ofpi_in_pcb.h"
#include "ofpi_callout.h"
#include "ofpi_tcp_var.h"
#include "ofpi_tcp_syncache.h"
#include "ofpi_config.h"

#include "api/ofp_timer.h"

/*
 * Shared data format
 */
struct ofp_tcp_var_mem {
#ifdef OFP_RSS
	VNET_DEFINE(struct inpcbhead, ofp_tcb[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo[OFP_MAX_NUM_CPU]);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl[OFP_MAX_NUM_CPU]);
	odp_timer_t ofp_tcp_slow_timer[OFP_MAX_NUM_CPU];
#else
	VNET_DEFINE(struct inpcbhead, ofp_tcb);/* queue of active tcpcb's */
	VNET_DEFINE(struct inpcbinfo, ofp_tcbinfo);
	VNET_DEFINE(OFP_TAILQ_HEAD(, tcptw), twq_2msl);
	odp_timer_t ofp_tcp_slow_timer;
#endif

	VNET_DEFINE(struct tcp_syncache, tcp_syncache);

	VNET_DEFINE(uma_zone_t, tcp_reass_zone);
	VNET_DEFINE(uma_zone_t, tcp_syncache_zone);
	VNET_DEFINE(uma_zone_t, tcpcb_zone);
	VNET_DEFINE(uma_zone_t, tcptw_zone);
	VNET_DEFINE(uma_zone_t, ofp_sack_hole_zone);

	VNET_DEFINE(uint32_t, hashtbl_off);
	VNET_DEFINE(uint32_t, hashtbl_size);

	VNET_DEFINE(uint32_t, porthashtbl_off);
	VNET_DEFINE(uint32_t, porthashtbl_size);

	VNET_DEFINE(uint32_t, syncachehashtbl_off);
	VNET_DEFINE(uint32_t, syncachehashtbl_size);

	/* TCP input*/
	VNET_DEFINE(struct ofp_tcpstat, tcpstat);
	VNET_DEFINE(int, tcp_log_in_vain);
	VNET_DEFINE(int, blackhole);
	VNET_DEFINE(int, tcp_delack_enabled);
	VNET_DEFINE(int, tcp_drop_synfin);
	VNET_DEFINE(int, tcp_do_rfc3042);
	VNET_DEFINE(int, tcp_do_rfc3390);
	VNET_DEFINE(int, tcp_do_rfc3465);
	VNET_DEFINE(int, tcp_abc_l_var);
	VNET_DEFINE(int, tcp_do_ecn);
	VNET_DEFINE(int, tcp_ecn_maxretries);

	VNET_DEFINE(int, tcp_insecure_rst);
	VNET_DEFINE(int, tcp_do_autorcvbuf);
	VNET_DEFINE(int, tcp_autorcvbuf_inc);
	VNET_DEFINE(int, tcp_autorcvbuf_max);
	VNET_DEFINE(int, tcp_passive_trace);

	/*TCP output*/
	VNET_DEFINE(int, tcp_path_mtu_discovery);
	VNET_DEFINE(int, tcp_ss_fltsz);
	VNET_DEFINE(int, tcp_ss_fltsz_local);
	VNET_DEFINE(int, tcp_do_tso);
	VNET_DEFINE(int, tcp_do_autosndbuf);
	VNET_DEFINE(int, tcp_autosndbuf_inc);
	VNET_DEFINE(int, tcp_autosndbuf_max);

	/*TCP userreq*/
	/*
	* tcp_sendspace and tcp_recvspace are the default send and receive
	* window sizes, respectively.  These are obsolescent (this information
	* should be set by the route).
	*/
	VNET_DEFINE(uint64_t, tcp_sendspace);
	VNET_DEFINE(uint64_t, tcp_recvspace);

	/*TCP SACK*/
	VNET_DEFINE(int, tcp_do_sack);	/* SACK enabled/disabled */
	VNET_DEFINE(int, tcp_sack_maxholes);
	VNET_DEFINE(int, tcp_sack_globalmaxholes);
	VNET_DEFINE(int, tcp_sack_globalholes);

	/*TCP SYNCACHE*/
	VNET_DEFINE(int, tcp_syncookies);
	VNET_DEFINE(int, tcp_syncookiesonly);
	VNET_DEFINE(int, tcp_sc_rst_sock_fail);	/* RST on sock alloc failure */

	/* TCP REASSEMBLY*/
	VNET_DEFINE(int, tcp_reass_maxseg);
	VNET_DEFINE(int, tcp_reass_qsize);
	VNET_DEFINE(int, tcp_reass_overflows);

	/* TCP timewait*/
	VNET_DEFINE(int, maxtcptw);
	VNET_DEFINE(int, nolocaltimewait);

	/* TCP subr */
	VNET_DEFINE(unsigned int, max_protohdr);
	VNET_DEFINE(int, tcp_mssdflt);
#ifdef INET6
	VNET_DEFINE(int, tcp_v6mssdflt);
#endif
/*
 * Minimum MSS we accept and use. This prevents DoS attacks where
 * we are forced to a ridiculous low MSS like 20 and send hundreds
 * of packets instead of one. The effect scales with the available
 * bandwidth and quickly saturates the CPU and network interface
 * with packet generation and sending. Set to zero to disable MINMSS
 * checking. This setting prevents us from sending too small packets.
 */
	VNET_DEFINE(int, tcp_minmss);

	VNET_DEFINE(int, tcp_do_rfc1323);
	VNET_DEFINE(int, tcp_log_debug);
	VNET_DEFINE(int, tcp_tcbhashsize);
	VNET_DEFINE(int, do_tcpdrain);
	VNET_DEFINE(int, icmp_may_rst);
	VNET_DEFINE(int, tcp_isn_reseed_interval);
	VNET_DEFINE(int, tcp_soreceive_stream);
	VNET_DEFINE(odp_spinlock_t, isn_mtx);

	/* TCP timer */
	VNET_DEFINE(int, tcp_keepinit); /* time to establish connection */
	VNET_DEFINE(int, tcp_keepidle); /* time before keepalive probes begin */
	VNET_DEFINE(int, tcp_keepintvl); /* time between keepalive probes */
	VNET_DEFINE(int, tcp_delacktime); /*time before sending a delayed ACK */
	VNET_DEFINE(int, tcp_msl);
	VNET_DEFINE(int, tcp_rexmit_min);
	VNET_DEFINE(int, tcp_rexmit_slop);
	VNET_DEFINE(int, always_keepalive);
	VNET_DEFINE(int, tcp_fast_finwait2_recycle);
	VNET_DEFINE(int, tcp_finwait2_timeout);
	VNET_DEFINE(int, tcp_keepcnt);		/* number of keepalives */
	VNET_DEFINE(int, tcp_maxpersistidle);	/* max idle probes */
	VNET_DEFINE(int, tcp_timer_race);
};

extern __thread struct ofp_tcp_var_mem *shm_tcp;
extern __thread struct inpcbhead *shm_tcp_hashtbl;
extern __thread struct inpcbporthead *shm_tcp_porthashtbl;
extern __thread struct syncache_head *shm_tcp_syncachehashtbl;

#ifdef OFP_RSS
#define	V_tcb			VNET(shm_tcp->ofp_tcb[odp_cpu_id()])
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo[odp_cpu_id()])
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl[odp_cpu_id()])

#define	V_tcbtbl		VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfotbl	VNET(shm_tcp->ofp_tcbinfo)

#else
#define	V_tcb			VNET(shm_tcp->ofp_tcb)
#define	V_tcbinfo		VNET(shm_tcp->ofp_tcbinfo)
#define	V_twq_2msl		VNET(shm_tcp->twq_2msl)

#define	V_tcbtbl		VNET(&(shm_tcp->ofp_tcb))
#define	V_tcbinfotbl	VNET(&(shm_tcp->ofp_tcbinfo))
#endif

#define V_tcp_hashtbl		VNET(shm_tcp_hashtbl)
#define V_tcp_hashtbl_size	VNET(shm_tcp->hashtbl_size)

#define V_tcp_porthashtbl	VNET(shm_tcp_porthashtbl)
#define V_tcp_porthashtbl_size	VNET(shm_tcp->porthashtbl_size)

#define V_tcp_syncachehashtbl		VNET(shm_tcp_syncachehashtbl)
#define V_tcp_syncachehashtbl_size	VNET(shm_tcp->syncachehashtbl_size)

#define V_tcp_syncache			VNET(shm_tcp->tcp_syncache)

#define	V_tcp_reass_zone	VNET(shm_tcp->tcp_reass_zone)
#define	V_tcpcb_zone		VNET(shm_tcp->tcpcb_zone)
#define	V_tcptw_zone		VNET(shm_tcp->tcptw_zone)
#define	V_tcp_syncache_zone	VNET(shm_tcp->tcp_syncache_zone)
#define	V_sack_hole_zone	VNET(shm_tcp->ofp_sack_hole_zone)

#define	V_tcpstat		VNET(shm_tcp->tcpstat)
#define	V_tcp_log_in_vain	VNET(shm_tcp->tcp_log_in_vain)
#define	V_tcp_blackhole		VNET(shm_tcp->blackhole)
#define	V_tcp_delack_enabled	VNET(shm_tcp->tcp_delack_enabled)
#define	V_tcp_drop_synfin	VNET(shm_tcp->tcp_drop_synfin)
#define	V_tcp_do_rfc3042	VNET(shm_tcp->tcp_do_rfc3042)
#define	V_tcp_do_rfc3390	VNET(shm_tcp->tcp_do_rfc3390)
#define	V_tcp_do_rfc3465	VNET(shm_tcp->tcp_do_rfc3465)
#define	V_tcp_abc_l_var		VNET(shm_tcp->tcp_abc_l_var)

#define	V_tcp_do_ecn		VNET(shm_tcp->tcp_do_ecn)
#define	V_tcp_ecn_maxretries	VNET(shm_tcp->tcp_ecn_maxretries)

#define	V_tcp_insecure_rst	VNET(shm_tcp->tcp_insecure_rst)
#define	V_tcp_do_autorcvbuf	VNET(shm_tcp->tcp_do_autorcvbuf)
#define	V_tcp_autorcvbuf_inc	VNET(shm_tcp->tcp_autorcvbuf_inc)
#define	V_tcp_autorcvbuf_max	VNET(shm_tcp->tcp_autorcvbuf_max)
#define	V_tcp_passive_trace	VNET(shm_tcp->tcp_passive_trace)

#define	V_tcp_path_mtu_discovery	VNET(shm_tcp->tcp_path_mtu_discovery)
#define	V_tcp_ss_fltsz	VNET(shm_tcp->tcp_ss_fltsz)
#define	V_tcp_ss_fltsz_local	VNET(shm_tcp->tcp_ss_fltsz_local)
#define	V_tcp_do_tso		VNET(shm_tcp->tcp_do_tso)
#define	V_tcp_do_autosndbuf	VNET(shm_tcp->tcp_do_autosndbuf)
#define	V_tcp_autosndbuf_inc	VNET(shm_tcp->tcp_autosndbuf_inc)
#define	V_tcp_autosndbuf_max	VNET(shm_tcp->tcp_autosndbuf_max)

#define	V_tcp_sendspace	VNET(shm_tcp->tcp_sendspace)
#define	V_tcp_recvspace	VNET(shm_tcp->tcp_recvspace)

#define	V_tcp_do_sack				VNET(shm_tcp->tcp_do_sack)
#define	V_tcp_sack_maxholes			VNET(shm_tcp->tcp_sack_maxholes)
#define	V_tcp_sack_globalmaxholes	VNET(shm_tcp->tcp_sack_globalmaxholes)
#define	V_tcp_sack_globalholes		VNET(shm_tcp->tcp_sack_globalholes)

#define	V_tcp_syncookies		VNET(shm_tcp->tcp_syncookies)
#define	V_tcp_syncookiesonly	VNET(shm_tcp->tcp_syncookiesonly)
#define	V_tcp_sc_rst_sock_fail	VNET(shm_tcp->tcp_sc_rst_sock_fail)

#define	V_tcp_reass_maxseg		VNET(shm_tcp->tcp_reass_maxseg)
#define	V_tcp_reass_qsize		VNET(shm_tcp->tcp_reass_qsize)
#define	V_tcp_reass_overflows	VNET(shm_tcp->tcp_reass_overflows)

#define	V_tcp_maxtcptw	VNET(shm_tcp->maxtcptw)
#define	V_nolocaltimewait	VNET(shm_tcp->nolocaltimewait)

#define	V_tcp_maxprotohdr	VNET(shm_tcp->max_protohdr)
#define	V_tcp_mssdflt		VNET(shm_tcp->tcp_mssdflt)

#ifdef INET6
#define	V_tcp_v6mssdflt		VNET(shm_tcp->tcp_v6mssdflt)
#endif /* INET6 */

#define	V_tcp_minmss		VNET(shm_tcp->tcp_minmss)

#define	V_tcp_do_rfc1323	VNET(shm_tcp->tcp_do_rfc1323)
#define	V_tcp_log_debug		VNET(shm_tcp->tcp_log_debug)
#define	V_tcp_tcbhashsize	VNET(shm_tcp->tcp_tcbhashsize)
#define	V_tcp_do_tcpdrain	VNET(shm_tcp->do_tcpdrain)
#define	V_tcp_icmp_may_rst	VNET(shm_tcp->icmp_may_rst)
#define	V_tcp_isn_reseed_interval	VNET(shm_tcp->tcp_isn_reseed_interval)
#define	V_tcp_soreceive_stream	VNET(shm_tcp->tcp_soreceive_stream)
#define	V_tcp_isn_mtx	VNET(shm_tcp->isn_mtx)

#define	V_tcp_keepinit	VNET(shm_tcp->tcp_keepinit)
#define	V_tcp_keepidle	VNET(shm_tcp->tcp_keepidle)
#define	V_tcp_keepintvl	VNET(shm_tcp->tcp_keepintvl)
#define	V_tcp_delacktime VNET(shm_tcp->tcp_delacktime)
#define	V_tcp_msl VNET(shm_tcp->tcp_msl)
#define	V_tcp_rexmit_min VNET(shm_tcp->tcp_rexmit_min)
#define	V_tcp_rexmit_slop VNET(shm_tcp->tcp_rexmit_slop)
#define	V_tcp_always_keepalive VNET(shm_tcp->always_keepalive)
#define	V_tcp_fast_finwait2_recycle VNET(shm_tcp->tcp_fast_finwait2_recycle)
#define	V_tcp_finwait2_timeout VNET(shm_tcp->tcp_finwait2_timeout)
#define	V_tcp_keepcnt VNET(shm_tcp->tcp_keepcnt)
#define	V_tcp_maxpersistidle VNET(shm_tcp->tcp_maxpersistidle)
#define	V_tcp_timer_race VNET(shm_tcp->tcp_timer_race)

void ofp_tcp_var_init_prepare(void);
int ofp_tcp_var_init_global(void);
int ofp_tcp_var_term_global(void);
int ofp_tcp_var_init_local(void);

#endif /* __OFPI_TCP_SHM_H__ */

