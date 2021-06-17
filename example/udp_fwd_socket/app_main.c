/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <inttypes.h>

#include "ofp.h"
#include "udp_fwd_socket.h"
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
	appl_arg_ifs_t itf_param;
	int sock_count;		/**< Number of sockets to use */
	char *cli_file;
	char *laddr;
	char *raddr;
} appl_args_t;

struct pktio_thr_arg {
	int num_pktin;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
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

static int pkt_io_recv(void *arg)
{
	odp_packet_t pkt, pkt_tbl[PKT_BURST_SIZE];
	int pkt_idx, pkt_cnt;
	struct pktio_thr_arg *thr_args;
	int num_pktin, i;
	odp_pktin_queue_t pktin[OFP_FP_INTERFACE_MAX];
	uint8_t *ptr;
	odp_bool_t *is_running = NULL;

	thr_args = arg;
	num_pktin = thr_args->num_pktin;

	for (i = 0; i < num_pktin; i++)
		pktin[i] = thr_args->pktin[i];

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		return -1;
	}

	ptr = (uint8_t *)&pktin[0];
	printf("PKT-IO receive starting on cpu: %i, %i, %x:%x\n", odp_cpu_id(),
	       num_pktin, ptr[0], ptr[8]);

	while (*is_running) {
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

	return 0;
}

/*
 * Should receive timeouts only
 */
static int event_dispatcher(void *arg)
{
	odp_event_t ev;
	odp_bool_t *is_running = NULL;

	(void)arg;

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		return -1;
	}

	while (*is_running) {
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(ev);
			continue;
		}

		OFP_ERR("Error: unexpected event type: %u\n",
			  odp_event_type(ev));

		odp_buffer_free(odp_buffer_from_event(ev));
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
	ofp_thread_t thread_tbl[MAX_WORKERS], dispatcher_thread;
	ofp_thread_param_t thread_param;
	int num_workers, tx_queues, first_worker, i;
	odp_cpumask_t cpu_mask;
	struct pktio_thr_arg pktio_thr_args[MAX_WORKERS];
	struct interface_id itf_id[OFP_FP_INTERFACE_MAX];
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_t pktio;

	/* add handler for Ctr+C */
	if (ofpexpl_sigaction_set(ofpexpl_sigfunction_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, &params) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	/* Initialize OFP */
	ofp_initialize_param(&app_init_params);
	app_init_params.cli.os_thread.start_on_init = 1;

	if (ofp_initialize(&app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	/*
	 * By default core #0 runs Linux kernel background tasks. Start mapping
	 * worker threads from core #1. Core #0 requires its own TX queue.
	 */
	first_worker = 1;
	num_workers = odp_cpu_count() - 1;

	if (params.core_count && params.core_count < num_workers)
		num_workers = params.core_count;
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;
	tx_queues = num_workers;

	if (num_workers < 1) {
		OFP_ERR("ERROR: At least 2 cores required.\n");
		ofp_terminate();
		parse_args_cleanup(&params);
		exit(EXIT_FAILURE);
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("First worker CPU:   %i\n\n", first_worker);

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.op_mode = ODP_PKTIO_OP_MT;
	pktin_param.hash_enable = 0;
	pktin_param.hash_proto.proto.ipv4_udp = 0;
	pktin_param.num_queues = num_workers;

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.op_mode = ODP_PKTIO_OP_MT;
	pktout_param.num_queues = tx_queues;

	memset(pktio_thr_args, 0, sizeof(pktio_thr_args));

	for (i = 0; i < params.itf_param.if_count; i++) {
		int j;
		odp_pktin_queue_t pktin[num_workers];
		struct appl_arg_if *if_arg = &params.itf_param.if_array[i];

		if (ofp_ifport_net_create(if_arg->if_name, &pktio_param,
					  &pktin_param, &pktout_param,
					  1, &itf_id[i].port,
					  &itf_id[i].subport) < 0) {
			OFP_ERR("Failed to init interface %s", if_arg->if_name);
			ofp_terminate();
			parse_args_cleanup(&params);
			exit(EXIT_FAILURE);
		}

		pktio = odp_pktio_lookup(if_arg->if_name);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed locate pktio %s", if_arg->if_name);
			ofp_terminate();
			parse_args_cleanup(&params);
			exit(EXIT_FAILURE);
		}

		if (odp_pktin_queue(pktio, pktin, num_workers) != num_workers) {
			OFP_ERR("Too few pktin queues for %s", if_arg->if_name);
			parse_args_cleanup(&params);
			exit(EXIT_FAILURE);
		}

		if (odp_pktout_queue(pktio, NULL, 0) != tx_queues) {
			OFP_ERR("Too few pktout queues for %s",
				if_arg->if_name);
			ofp_terminate();
			parse_args_cleanup(&params);
			exit(EXIT_FAILURE);
		}

		for (j = 0; j < num_workers; j++)
			pktio_thr_args[j].pktin[i] = pktin[j];
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));

	for (i = 0; i < num_workers; ++i) {

		pktio_thr_args[i].num_pktin = params.itf_param.if_count;

		ofp_thread_param_init(&thread_param);
		thread_param.start = pkt_io_recv;
		thread_param.arg = &pktio_thr_args[i];
		thread_param.thr_type = ODP_THREAD_WORKER;

		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, first_worker + i);

		if (ofp_thread_create(&thread_tbl[i], 1,
				      &cpu_mask, &thread_param) != 1)
			break;
	}

	if (i < num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d", num_workers, i);
		ofp_stop_processing();
		if (i > 0)
			ofp_thread_join(thread_tbl, i);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	odp_cpumask_zero(&cpu_mask);
	odp_cpumask_set(&cpu_mask, app_init_params.linux_core_id);
	ofp_thread_param_init(&thread_param);
	thread_param.start = event_dispatcher;
	thread_param.arg = NULL;
	thread_param.thr_type = ODP_THREAD_WORKER;
	if (ofp_thread_create(&dispatcher_thread, 1,
			      &cpu_mask, &thread_param) != 1) {
		OFP_ERR("Error: Failed to create dispatcherthreads");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	/* Configure IP addresses */
	if (configure_interface_addresses(&params.itf_param, itf_id)) {
		OFP_ERR("Error: Failed to configure addresses");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		ofp_thread_join(&dispatcher_thread, 1);
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
		ofp_thread_join(&dispatcher_thread, 1);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}
	sleep(1);

	if (udp_fwd_cfg(params.sock_count, params.laddr, params.raddr)) {
		OFP_ERR("Error: udp_fwd_cleanup failed.");
		ofp_stop_processing();
	}

	ofp_thread_join(thread_tbl, num_workers);
	ofp_thread_join(&dispatcher_thread, 1);

	if (udp_fwd_cleanup())
		printf("Error: udp_fwd_cleanup failed.\n");

	if (ofp_terminate() < 0)
		printf("Error: ofp_terminate failed.\n");

	parse_args_cleanup(&params);
	printf("End Main()\n");
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
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{"local-address", required_argument,
			NULL, 'l'},/* return 'l' */
		{"remote-address", required_argument,
			NULL, 'r'},/* return 'r' */
		{"socket-count", required_argument,
			NULL, 's'},/* return 's' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	appl_args->sock_count = 1;

	while (res == 0) {
		opt = getopt_long(argc, argv, "+c:i:hf:l:r:s:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
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
		case 'l':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				res = -1;
				break;
			}
			len += 1;	/* add room for '\0' */
			appl_args->laddr = malloc(len);
			if (appl_args->laddr == NULL) {
				usage(argv[0]);
				res = -1;
				break;
			}

			strcpy(appl_args->laddr, optarg);
			break;
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				res = -1;
				break;
			}
			len += 1;	/* add room for '\0' */
			appl_args->raddr = malloc(len);
			if (appl_args->raddr == NULL) {
				usage(argv[0]);
				res = -1;
				break;
			}

			strcpy(appl_args->raddr, optarg);
			break;
		case 's':
			len = strlen(optarg);
			if (len == 0 || atoi(optarg) < 1) {
				usage(argv[0]);
				res = -1;
				break;
			}
			appl_args->sock_count = atoi(optarg);
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

	if (appl_args->laddr == NULL) {
		printf("Error: Invalid local address (null)\n");
		usage(argv[0]);
		parse_args_cleanup(appl_args);
		return EXIT_FAILURE;
	}

	if (appl_args->raddr == NULL) {
		printf("Error: Invalid remote address (null)\n");
		usage(argv[0]);
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
		   "Forward UDP packet to remote address. See Note.\n\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -i eth1,eth2,eth3\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface <interfaces> Ethernet interface list"
		   " (comma-separated, no spaces)\n"
		   "  Example:\n"
		   "    eth1,eth2\n"
		   "    eth1@192.168.100.10/24,eth2@172.24.200.10/16\n"
		   "  -l, --local-address   Local address. See Note.\n"
		   "  -r, --remote-address  Remote address\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -f, --cli-file <file>       OFP CLI file.\n"
		   "  -c, --count <number>        Core count.\n"
		   "  -s, --socket-count <number> Number of local sockets to use."
		   " Default: 1. See Note.\n"
		   "  -h, --help                  Display help and exit.\n"
		   "Note: Each UDP socket is bound on <local-address, local-port>, "
		   "where:\n"
		   "    - local-address is specified with '-l' option\n"
		   "    - local-port is calculated as %d + socket_index\n"
		   "Packets are forwarded to <remote-address, remote-port>, "
		   "where:\n"
		   "    - remote-address is specified with '-r' option\n"
		   "    - remote-port is %d\n"
		   "\n", NO_PATH(progname), NO_PATH(progname),
		   TEST_LPORT, TEST_RPORT);
}


