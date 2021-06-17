/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <inttypes.h>

#include "ofp.h"
#include "linux_sigaction.h"
#include "cli_arg_parse.h"

#define MAX_WORKERS		64
#define PKT_BURST_SIZE 16

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int core_start;
	appl_arg_ifs_t itf_param;
	char *cli_file;
} appl_args_t;

struct worker_arg {
	int num_pktin;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
	odp_bool_t process_timers;
};

struct interface_id {
	int port;
	uint16_t subport;
};

/* helper funcs */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void parse_args_cleanup(appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int validate_cores_settings(int req_core_start, int req_core_count,
	int *core_start, int *core_count);

/** pkt_io_recv() Custom event dispatcher
 *
 * @param _arg void*  Worker argument
 * @return int Never returns
 *
 */
static int pkt_io_recv(void *_arg)
{
	odp_packet_t pkt, pkt_tbl[PKT_BURST_SIZE];
	odp_event_t events[PKT_BURST_SIZE], ev;
	int pkt_idx, pkt_cnt, event_cnt;
	struct worker_arg *arg;
	int num_pktin, i;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
	uint8_t *ptr;
	odp_bool_t process_timers;
	odp_bool_t *is_running = NULL;

	arg = (struct worker_arg *)_arg;
	process_timers = arg->process_timers;
	num_pktin = arg->num_pktin;

	for (i = 0; i < num_pktin; i++)
		pktin[i] = arg->pktin[i];

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		return -1;
	}

	ptr = (uint8_t *)&pktin[0];

	printf("PKT-IO receive starting on cpu: %i, %i, %x:%x\n", odp_cpu_id(),
	       num_pktin, ptr[0], ptr[8]);

	while (*is_running) {
		if (process_timers) {
			event_cnt = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
				events, PKT_BURST_SIZE);
			for (i = 0; i < event_cnt; i++) {
				ev = events[i];

				if (ev == ODP_EVENT_INVALID)
					continue;

				if (odp_event_type(ev) == ODP_EVENT_TIMEOUT)
					ofp_timer_handle(ev);
				else
					odp_buffer_free(
						odp_buffer_from_event(ev));
			}
		}
		for (i = 0; i < num_pktin; i++) {
			pkt_cnt = odp_pktin_recv(pktin[i], pkt_tbl,
						 PKT_BURST_SIZE);

			for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
				pkt = pkt_tbl[pkt_idx];

				ofp_packet_input(pkt, ODP_QUEUE_INVALID,
						 ofp_eth_vlan_processing);
			}
		}
		ofp_send_pending_pkt();
	}

	/* Never reached */
	return 0;
}

/** configure_interfaces() Create OFP interfaces with
 * pktios open in direct mode, thread unsafe.
 *
 * @param itf_param appl_arg_ifs_t Interfaces to configure
 * @param tx_queue int Number of requested transmision queues
 *    per interface
 * @param rx_queue int Number of requested reciver queues per
 *    interface
 * @param itf_id struct interface_id IDs (port and subport) of
 *    the configured interfaces
 * @return int 0 on success, -1 on error
 *
 */
static int configure_interfaces(appl_arg_ifs_t *itf_param,
				int tx_queues, int rx_queues,
				struct interface_id *itf_id)
{
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	int i;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktin_param.hash_enable = 0;
	pktin_param.num_queues = rx_queues;

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.op_mode    = ODP_PKTIO_OP_MT_UNSAFE;
	pktout_param.num_queues = tx_queues;

	for (i = 0; i < itf_param->if_count; i++)
		if (ofp_ifport_net_create(itf_param->if_array[i].if_name,
					  &pktio_param, &pktin_param,
					  &pktout_param, 1,
					  &itf_id[i].port,
					  &itf_id[i].subport) < 0) {
			OFP_ERR("Failed to init interface %s",
				itf_param->if_array[i].if_name);
			return -1;
		}

	return 0;
}

/** configure_interface_addresses() Configure IPv4 addresses
 *
 * @param itf_param appl_arg_ifs_t Interfaces to configure
 * @param itf_id struct interface_id IDs (port and subport) of
 *     the configured interfaces
 * @return int 0 on success, -1 on error
 *
 */
static int configure_interface_addresses(appl_arg_ifs_t *itf_param,
					 struct interface_id *itf_id)
{
	struct appl_arg_if *ifarg = NULL;
	uint32_t addr = 0;
	int i, ret = 0;
	const char *res = NULL;

	for (i = 0; i < itf_param->if_count && i < OFP_FP_INTERFACE_MAX; i++) {
		ifarg = &itf_param->if_array[i];

		if (!ifarg->if_name) {
			OFP_ERR("Error: Invalid interface name: null");
			ret = -1;
			break;
		}

		if (!ifarg->if_address)
			continue; /* Not set through application parameters*/

		OFP_DBG("Setting %s/%d on %s", ifarg->if_address,
			ifarg->if_address_masklen, ifarg->if_name);

		if (!ofp_parse_ip_addr(ifarg->if_address, &addr)) {
			OFP_ERR("Error: Failed to parse IPv4 address: %s",
				ifarg->if_address);
			ret = -1;
			break;
		}

		res = ofp_ifport_net_ipv4_up(itf_id[i].port, itf_id[i].subport,
					     0,
					     addr, ifarg->if_address_masklen,
					     1);
		if (res != NULL) {
			OFP_ERR("Error: Failed to set IPv4 address %s "
				"on interface %s: %s",
				ifarg->if_address, ifarg->if_name, res);
			ret = -1;
			break;
		}
	}

	return ret;
}

/** configure_workers_arg() Configure workers
 *  argument
 *
 * @param num_workers int  Number of workers
 * @param workers_arg struct worker_arg* Array of workers
 *    argument
 * @param if_count int  Interface count
 * @param if_names char** Interface names
 * @return int 0 on success, -1 on error
 *
 */
static int configure_workers_arg(appl_arg_ifs_t *itf_param,
				 int num_workers,
				 struct worker_arg *workers_arg)
{
	odp_pktio_t pktio;
	odp_pktin_queue_t pktin[MAX_WORKERS];
	int i, j;

	for (i = 0; i < num_workers; i++) {
		workers_arg[i].num_pktin = itf_param->if_count;
		workers_arg[i].process_timers = 0;
	}
	/*enable timer processing on first core*/
	workers_arg[0].process_timers = 1;

	for (i = 0; i < itf_param->if_count; i++) {
		pktio = odp_pktio_lookup(itf_param->if_array[i].if_name);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed locate pktio %s",
				itf_param->if_array[i].if_name);
			return -1;
		}

		if (odp_pktin_queue(pktio, pktin, num_workers) != num_workers) {
			OFP_ERR("Too few pktin queues for %s",
				itf_param->if_array[i].if_name);
			exit(EXIT_FAILURE);
		}

		for (j = 0; j < num_workers; j++)
			workers_arg[j].pktin[i] = pktin[j];
	}

	return 0;
}

/** main() Application entry point
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	appl_args_t params;
	ofp_initialize_param_t app_init_params;
	ofp_thread_t thread_tbl[MAX_WORKERS];
	ofp_thread_param_t thread_param;
	struct worker_arg workers_arg[MAX_WORKERS];
	struct interface_id itf_id[OFP_FP_INTERFACE_MAX];
	int num_workers, first_worker, linux_sp_core, i, ret_val;
	odp_cpumask_t cpu_mask;

	/* add handler for Ctr+C */
	if (ofpexpl_sigaction_set(ofpexpl_sigfunction_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, &params) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	/*
	 * This example creates a custom workers to cores distribution:
	 * Core #0 runs Slow Path background tasks.
	 * Cores #core_start and beyond run packet processing tasks.
	 * It is recommanded to start mapping threads from core 1. Else,
	 * Slow Path processing will be affected by workers processing.
	 * However, if Slow Path is disabled, core 0 may be used as well.
	 */
	linux_sp_core = 0;

	/* Initialize OFP*/
	ofp_initialize_param(&app_init_params);
	app_init_params.linux_core_id = linux_sp_core;
	app_init_params.cli.os_thread.start_on_init = 1;

	if (ofp_initialize(&app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	/* Validate workers distribution settings. */
	if (validate_cores_settings(params.core_start, params.core_count,
				    &first_worker, &num_workers) < 0) {
		ofp_terminate();
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	OFP_INFO("SP core: %d\nWorkers core start: %d\n"
		"Workers core count: %d\n",
		linux_sp_core, first_worker, num_workers);

	odp_memset(itf_id, 0, sizeof(itf_id));
	if (configure_interfaces(&params.itf_param,
				 num_workers, num_workers, itf_id)) {
		OFP_ERR("Error: Failed to configure interfaces.\n");
		ofp_terminate();
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	if (configure_workers_arg(&params.itf_param,
				  num_workers, workers_arg)) {
		OFP_ERR("Failed to initialize workers arguments.");
		ofp_terminate();
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	/* Create worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {
		ofp_thread_param_init(&thread_param);
		thread_param.start = pkt_io_recv;
		thread_param.arg = &workers_arg[i];
		thread_param.thr_type = ODP_THREAD_WORKER;

		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, first_worker + i);

		ret_val = ofp_thread_create(&thread_tbl[i], 1, &cpu_mask,
					    &thread_param);
		if (ret_val != 1) {
			OFP_ERR("Error: Failed to create worker threads, "
				"expected %d, got %d",
				num_workers, i);
			ofp_stop_processing();
			ofp_thread_join(thread_tbl, i);
			ofp_terminate();
			parse_args_cleanup(&params);
			return EXIT_FAILURE;
		}
	}

	/* Configure IP addresses */
	if (configure_interface_addresses(&params.itf_param, itf_id)) {
		OFP_ERR("Error: Failed to configure addresses");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	/*
	 * Process the CLI commands file (if defined).
	 * This is an alternative way to set the IP addresses and other
	 * parameters.
	 */
	if (ofp_cli_process_file(params.cli_file)) {
		OFP_ERR("Error: Failed to process CLI file.");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	ofp_thread_join(thread_tbl, num_workers);

	if (ofp_terminate() < 0)
		printf("Error: ofp_terminate failed.\n");

	parse_args_cleanup(&params);
	printf("End Main()\n");
	return 0;
}

/**
 * validate_cores_settings() Validate requested core settings
 * and computed actual values
 *
 *
 * @param req_core_start int Requested worker core start
 * @param req_core_count int Requested worker core count
 * @param core_start int* Computed worker core start
 * @param core_count int* Computed worker core count
 * @return int 0 on success, -1 on error
 *
 */
static int validate_cores_settings(int req_core_start, int req_core_count,
	 int *core_start, int *core_count)
{
	int total_core_count = odp_cpu_count();

	if (req_core_start >= total_core_count) {
		OFP_ERR("ERROR: Invalid 'core start' parameter: %d. Max = %d\n",
			req_core_start, total_core_count - 1);
		return -1;
	}
	*core_start = req_core_start;

	if (req_core_count) {
		if (*core_start + req_core_count > total_core_count) {
			OFP_ERR("ERROR: Invalid 'core start' 'core count' "
				"configuration: %d,%d\n"
				"Exeeds number of avilable cores: %d",
				*core_start, req_core_count, total_core_count);
			return -1;
		}
		*core_count = req_core_count;
	} else
		*core_count = total_core_count - *core_start;

	if (*core_count < 0) {
		OFP_ERR("ERROR: At least 1 core is required.\n");
		return -1;
	}
	if (*core_count > MAX_WORKERS)  {
		OFP_ERR("ERROR: Number of processing cores %d"
			" exeeds maximum number for this test %d.\n",
			*core_count, MAX_WORKERS);
		return -1;
	}
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on error
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt, res = 0;
	int long_index;
	size_t len;
	static struct option longopts[] = {
		{"core_count", required_argument, NULL, 'c'},
		{"core_start", required_argument, NULL, 's'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));
	appl_args->core_start = 1;
	appl_args->core_count = 0; /* all above core start */

	while (res == 0) {
		opt = getopt_long(argc, argv, "+c:s:i:hf:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
		case 's':
			appl_args->core_start = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			res = ofpexpl_parse_interfaces(optarg,
						       &appl_args->itf_param);
			if (res == EXIT_FAILURE) {
				usage(argv[0]);
				res = -1;
			}
			break;

		case 'h':
			usage(argv[0]);
			parse_args_cleanup(appl_args);
			exit(EXIT_SUCCESS);
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				res = -1;
				break;
			}
			len += 1;	/* add room for '\0' */

			appl_args->cli_file = malloc(len);
			if (appl_args->cli_file == NULL) {
				usage(argv[0]);
				res = -1;
				break;
			}

			strcpy(appl_args->cli_file, optarg);
			break;

		default:
			break;
		}
	}

	if (res == -1) {
		parse_args_cleanup(appl_args);
		return EXIT_FAILURE;
	}

	if (appl_args->itf_param.if_count == 0) {
		usage(argv[0]);
		parse_args_cleanup(appl_args);
		return EXIT_FAILURE;
	}

	if (appl_args->itf_param.if_count > OFP_FP_INTERFACE_MAX) {
		printf("Error: Invalid number of interfaces: maximum %d\n",
		       OFP_FP_INTERFACE_MAX);
		parse_args_cleanup(appl_args);
		return EXIT_FAILURE;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
	return EXIT_SUCCESS;
}

/**
 * Cleanup the stored command line arguments
 *
 * @param appl_args  application arguments
 */
static void parse_args_cleanup(appl_args_t *appl_args)
{
	ofpexpl_parse_interfaces_param_cleanup(&appl_args->itf_param);
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
		   "ODP system info\n"
		   "---------------\n"
		   "ODP API version: %s\n"
		   "CPU model:       %s\n"
		   "CPU freq (hz):   %"PRIu64"\n"
		   "Cache line size: %i\n"
		   "Core count:      %i\n"
		   "\n",
		   odp_version_api_str(), odp_cpu_model_str(),
		   odp_cpu_hz(), odp_sys_cache_line_size(),
		   odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
		   "-----------------\n"
		   "IF-count:        %i\n"
		   "Using IFs:      ",
		   progname, appl_args->itf_param.if_count);
	for (i = 0; i < appl_args->itf_param.if_count; ++i)
		printf(" %s", appl_args->itf_param.if_array[i].if_name);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -i eth1,eth2,eth3\n"
		   "\n"
		   "ODPFastpath application.\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface <interfaces> Ethernet interface list"
		   " (comma-separated, no spaces)\n"
		   "  Example:\n"
		   "    eth1,eth2\n"
		   "    eth1@192.168.100.10/24,eth2@172.24.200.10/16\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -s, --core_start <number> Core start. Default 1.\n"
		   "  -c, --core_count <number> Core count. Default 0: all above core start\n"
		   "  -f, --cli-file <file> OFP CLI file.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
