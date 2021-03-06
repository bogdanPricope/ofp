/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_avl.h"
#include "ofpi_rt_lookup.h"
#include "ofpi_stat.h"
#include "ofpi_util.h"

static void print_latency_entry(ofp_print_t *pr,
				struct ofp_packet_stat *st,
				int thread, int entry)
{
	int j;
	uint64_t input_latency = st->per_thr[thread].input_latency[entry];
	int input_latency_log = ilog2(input_latency);

	ofp_print(pr, "\r\n%3d| ", entry);

	if (input_latency == 0)
		return;

	if (input_latency < 100000)
		ofp_print(pr, "[%05d]", input_latency);
	else
		ofp_print(pr, "[99999]");

	for (j = 0; j < input_latency_log + 1; j++)
		ofp_print(pr, "*");
}

static void print_thread_stat(ofp_print_t *pr,
			      struct ofp_packet_stat *st, odp_thrmask_t thrmask)
{
	int next_thr;

	ofp_print(pr, " Thread   Core        ODP_to_FP        FP_to_ODP"
		"     FP_to_SP    SP_to_ODP      Tx_frag   Rx_IP_frag"
		"   Rx_IP_reas    Description\r\n\r\n");
	next_thr = odp_thrmask_first(&thrmask);
	while (next_thr >= 0) {
		ofp_print(pr, "%7u %6d %16llu %16llu %12llu %12llu"
			" %12llu %12llu %12llu %14s\r\n",
			next_thr,
			V_global_thread_info[next_thr].cpu_id,
			st->per_thr[next_thr].rx_fp,
			st->per_thr[next_thr].tx_fp,
			st->per_thr[next_thr].rx_sp,
			st->per_thr[next_thr].tx_sp,
			st->per_thr[next_thr].tx_eth_frag,
			st->per_thr[next_thr].rx_ip_frag,
			st->per_thr[next_thr].rx_ip_reass,
			V_global_thread_info[next_thr].description);
		next_thr = odp_thrmask_next(&thrmask, next_thr);
	}
	ofp_print(pr, "\r\n");
}

void f_stat_show(ofp_print_t *pr, const char *s)
{
	struct ofp_packet_stat *st = ofp_get_packet_statistics();
	int i, j;
	int next_thr;
	odp_thrmask_t thrmask;
	int last_entry;

	unsigned long int stat_flags = ofp_get_stat_flags();

	(void)s;

	if (!st)
		return;

	ofp_print(pr, "Settings: \r\n"
		"  compute latency - %s\r\n"
		"  compute performance - %s\r\n\r\n",
		stat_flags & OFP_STAT_COMPUTE_LATENCY ? "yes" : "no",
		stat_flags & OFP_STAT_COMPUTE_PERF ? "yes" : "no");

	odp_thrmask_control(&thrmask);
	ofp_print(pr, "Packet counters of control threads:\r\n\r\n");
	print_thread_stat(pr, st, thrmask);

	odp_thrmask_worker(&thrmask);
	ofp_print(pr, "Packet counters of worker threads:\r\n\r\n");
	print_thread_stat(pr, st, thrmask);

/*TODO: print interface related stats colected from ODP or linux IP stack*/

	ofp_print(pr, "Allocated memory:\r\n");
	ofp_print_avl_stat(pr);
	ofp_print_rt_stat(pr);

	if (stat_flags & OFP_STAT_COMPUTE_LATENCY) {
		ofp_print(pr, "\r\n  Latency graph | log/log scale | "
			"X = occurrences, Y = cycles");

		next_thr = odp_thrmask_first(&thrmask);
		while (next_thr >= 0) {
			ofp_print(pr, "\r\nWorker thread %d:\r\n", next_thr);

			/* Skip to the first entry where there's data */
			for (i = 0; i < OFP_LATENCY_SLICES; i++)
				if (st->per_thr[next_thr].input_latency[i] != 0)
					break;

			if (i < OFP_LATENCY_SLICES) {
				/* Check what's the last entry with data */
				last_entry = i;
				for (j = i; j < OFP_LATENCY_SLICES; j++)
					if (st->per_thr[next_thr].input_latency[j])
						last_entry = j;

				/* Now we have cut the ends with zeros */
				for (; i < last_entry + 1; i++)
					print_latency_entry(pr, st,
							    next_thr, i);
				ofp_print(pr, "\r\n");
			}
			next_thr = odp_thrmask_next(&thrmask, next_thr);
		}
	}
	if (stat_flags & OFP_STAT_COMPUTE_PERF) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();

		ofp_print(pr, "\r\n");
		ofp_print(pr, "Throughput: %4.3f Mpps\r\n",
			  ((float)ps->rx_fp_pps) / 1000000);
	}
}

void f_stat_set(ofp_print_t *pr, const char *s)
{
	(void)s;
	(void)pr;

	ofp_set_stat_flags(strtol(s, NULL, 0));
}

void f_stat_perf(ofp_print_t *pr, const char *s)
{
	(void)s;

	if (ofp_get_stat_flags() & OFP_STAT_COMPUTE_PERF) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();

		ofp_print(pr, "%4.3f Mpps - Throughput\r\n",
			  ((float)ps->rx_fp_pps) / 1000000);
	} else
		ofp_print(pr, "N/A\r\n");
}

void f_stat_clear(ofp_print_t *pr, const char *s)
{
	struct ofp_packet_stat *st = NULL;

	(void)s;
	(void)pr;

	st = ofp_get_packet_statistics();

	memset(st, 0, sizeof(struct ofp_packet_stat));
}

void f_help_stat(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Show statistics:\r\n"
		  "  stat [show]\r\n\r\n");

	ofp_print(pr, "Set options for statistics:\r\n"
		  "  stat set <bit mask of options>\r\n"
		  "    bit 0: compute packets latency\r\n"
		  "    bit 1: compute throughput (mpps)\r\n"
		  "  Example:\r\n"
		  "    stat set 0x1\r\n\r\n");

	ofp_print(pr, "Get performance statistics:\r\n"
		  "  stat perf\r\n\r\n");

	ofp_print(pr, "Clear statistics:\r\n"
		  "  stat clear\r\n\r\n");

	ofp_print(pr, "Show (this) help:\r\n"
		  "  stat help\r\n\r\n");
}
