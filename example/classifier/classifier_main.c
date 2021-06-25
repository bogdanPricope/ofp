/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "ofp.h"
#include "linux_sigaction.h"
#include "cli_arg_parse.h"

#if ODP_VERSION_API_GENERATION <= 1 && ODP_VERSION_API_MAJOR < 20
	#define ODP_PMR_INVALID ODP_PMR_INVAL
#endif

#define MAX_WORKERS		32
#define TEST_PORT 54321

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	appl_arg_ifs_t itf_param;
	char *cli_file;
} appl_args_t;

/* helper funcs */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void parse_args_cleanup(appl_args_t *appl_args);
static int configure_interface_addresses(appl_arg_ifs_t *itf_param);
static void print_info(char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask);
static void usage(char *progname);
static int build_classifier(int if_count, char if_names[][OFP_IFNAMSIZ]);
static odp_cos_t build_cos_w_queue(const char *name);
static odp_cos_t build_cos_set_queue(const char *name, odp_queue_t queue_cos);
static odp_pmr_t build_udp_prm(odp_cos_t cos_src, odp_cos_t cos_dst);
static void app_processing(void);

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
	int num_workers, ret_val, i;
	odp_cpumask_t cpumask_workers;

	/* add handler for Ctr+C */
	if (ofpexpl_sigaction_set(ofpexpl_sigfunction_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, &params) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	/*
	 * This example assumes that core #0 and #1 runs Linux kernel
	 * background tasks and control threads.
	 * By default, cores #2 and beyond will be populated with a OFP
	 * processing thread each.
	 */
	ofp_initialize_param(&app_init_params);
	app_init_params.cli.os_thread.start_on_init = 1;
	app_init_params.if_count = params.itf_param.if_count;
	for (i = 0; i < params.itf_param.if_count &&
	     i < OFP_FP_INTERFACE_MAX; i++) {
		strncpy(app_init_params.if_names[i],
			params.itf_param.if_array[i].if_name,
			OFP_IFNAMSIZ);
		app_init_params.if_names[i][OFP_IFNAMSIZ - 1] = '\0';
	}

	if (ofp_initialize(&app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	/*
	 * Get the default workers to cores distribution: one
	 * run-to-completion worker thread or process can be created per core.
	 */
	if (ofp_get_default_worker_cpumask(params.core_count, MAX_WORKERS,
					   &cpumask_workers)) {
		OFP_ERR("Error: Failed to get the default workers to cores "
			"distribution\n");
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}
	num_workers = odp_cpumask_count(&cpumask_workers);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params, &cpumask_workers);

	/* Build classifier */
	if (build_classifier(app_init_params.if_count,
			     app_init_params.if_names)) {
		OFP_ERR("Error: Failed to build the classifier.\n");
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	/* Start dataplane dispatcher worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	ofp_thread_param_init(&thread_param);
	thread_param.start = default_event_dispatcher;
	thread_param.arg = ofp_udp4_processing;
	thread_param.thr_type = ODP_THREAD_WORKER;

	ret_val = ofp_thread_create(thread_tbl,
				    num_workers,
				    &cpumask_workers,
				    &thread_param);
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_stop_processing();
		if (ret_val != -1)
			ofp_thread_join(thread_tbl, ret_val);
		ofp_terminate();
		parse_args_cleanup(&params);
		return EXIT_FAILURE;
	}

	/* Configure IP addresses */
	if (configure_interface_addresses(&params.itf_param)) {
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
	sleep(1);

	/* Start processing */
	app_processing();

	ofp_thread_join(thread_tbl, num_workers);

	/* Cleanup */
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
 * @return int EXIT_SUCCESS on success, EXIT_FAILURE on error
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
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (res == 0) {
		opt = getopt_long(argc, argv, "+c:i:hf:",
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
 * Cleanup cli parameters
 */
static void parse_args_cleanup(appl_args_t *appl_args)
{
	ofpexpl_parse_interfaces_param_cleanup(&appl_args->itf_param);
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask)
{
	int i;
	char cpumaskstr[64];

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

	/* Print worker to core distribution */
	if (odp_cpumask_to_str(cpumask, cpumaskstr, sizeof(cpumaskstr)) < 0) {
		printf("Error: Too small buffer provided to "
			"odp_cpumask_to_str\n");
		strcpy(cpumaskstr, "Unknown");
	}

	printf("Num worker threads: %i\n", odp_cpumask_count(cpumask));
	printf("first CPU:          %i\n", odp_cpumask_first(cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		   "Classifies traffic to process only certain UDP packets. See Note.\n\n"
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
		   "  -c, --count <number> Core count.\n"
		   "  -f, --cli-file <file> OFP CLI file.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\nNote: A single UDP socket is bound on "
		   "<local-address, local-port>, where:\n"
		   "    - local-address is the IPv4 address from first "
		   "interface (fp0)\n"
		   "    - local-port is %d\n"
		   "Received packets are classified and only expected UDP packets are processed.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname), TEST_PORT);
}

int build_classifier(int if_count, char if_names[][OFP_IFNAMSIZ])
{
	odp_pktio_t pktio;
	odp_cos_t cos_def;
	odp_cos_t cos_udp;
	odp_pmr_t pmr_udp;
	char name[80];
	int i, port;
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;
	odp_queue_t spq = ODP_QUEUE_INVALID;

	cos_udp = build_cos_w_queue("cos_udp");
	if (cos_udp == ODP_COS_INVALID) {
		OFP_ERR("Failed to create UDP COS");
		return -1;
	}

	for (i = 0; i < if_count; i++) {
		ifnet = ofp_ifport_net_ifnet_get_by_name(if_names[i]);
		if (ifnet == OFP_IFNET_INVALID) {
			OFP_ERR("Failed to get OFP interface %s\n",
				if_names[i]);
			return -1;
		}

		if (ofp_ifnet_port_get(ifnet, &port, NULL)) {
			OFP_ERR("Failed to get OFP interface port ID%s\n",
				if_names[i]);
			return -1;
		}

		pktio  = ofp_ifport_net_pktio_get(port);
		if (pktio == ODP_PKTIO_INVALID) {
			OFP_ERR("Failed to get pktio for interface %s\n",
				if_names[i]);
			return -1;
		}

		spq = ofp_ifport_net_spq_get(port);
		if (spq == ODP_QUEUE_INVALID) {
			OFP_ERR("Failed to get slow path queue %s\n",
				if_names[i]);
			return -1;
		}
		sprintf(name, "cos_default_%s", if_names[i]);
		cos_def = build_cos_set_queue(name, spq);
		if (cos_def == ODP_COS_INVALID) {
			OFP_ERR("Failed to create default COS "
				"for interface %s\n", if_names[i]);
			return -1;
		}

		if (odp_pktio_default_cos_set(pktio, cos_def) < 0) {
			OFP_ERR("Failed to set default COS on interface %s\n",
				if_names[i]);
			return -1;
		}

		if (odp_pktio_error_cos_set(pktio, cos_def) < 0) {
			OFP_ERR("Failed to set error COS on interface %s\n",
				if_names[i]);
			return -1;
		}

		pmr_udp = build_udp_prm(cos_def, cos_udp);
		if (pmr_udp == ODP_PMR_INVALID) {
			OFP_ERR("Failed to create UDP PRM");
			return -1;
		}
	}

	return 0;
}

static odp_cos_t build_cos_w_queue(const char *name)
{
	odp_cos_t cos;
	odp_queue_t queue_cos;
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cos_param;

	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	queue_cos = odp_queue_create(name, &qparam);
	if (queue_cos == ODP_QUEUE_INVALID) {
		OFP_ERR("Failed to create queue\n");
		return ODP_COS_INVALID;
	}

	odp_cls_cos_param_init(&cos_param);
	cos_param.queue = queue_cos;
	cos_param.pool = odp_pool_lookup(SHM_PKT_POOL_NAME);
	cos = odp_cls_cos_create(name, &cos_param);
	if (cos == ODP_COS_INVALID) {
		OFP_ERR("Failed to create COS");
		odp_cos_destroy(cos);
		odp_queue_destroy(queue_cos);
		return ODP_COS_INVALID;
	}

	return cos;
}

static odp_cos_t build_cos_set_queue(const char *name, odp_queue_t queue_cos)
{
	odp_cos_t cos;
	odp_cls_cos_param_t cos_param;

	odp_cls_cos_param_init(&cos_param);
	cos_param.queue = queue_cos;
	cos_param.pool = odp_pool_lookup(SHM_PKT_POOL_NAME);
	cos = odp_cls_cos_create(name, &cos_param);
	if (cos == ODP_COS_INVALID) {
		OFP_ERR("Failed to create COS");
		return ODP_COS_INVALID;
	}

	return cos;
}

static odp_pmr_t build_udp_prm(odp_cos_t cos_src, odp_cos_t cos_dst)
{
	odp_pmr_param_t pmr_param;
	uint16_t pmr_udp_val = TEST_PORT;
	uint16_t pmr_udp_mask = 0xffff;

	odp_cls_pmr_param_init(&pmr_param);

	pmr_param.term = ODP_PMR_UDP_DPORT;
	pmr_param.match.value = &pmr_udp_val;
	pmr_param.match.mask = &pmr_udp_mask;
	pmr_param.val_sz = sizeof (pmr_udp_val);

	return odp_cls_pmr_create(&pmr_param, 1, cos_src, cos_dst);
}

static void app_processing(void)
{
	int fd_rcv = -1;
	char buf[1500];
	int len = sizeof(buf);
	struct ofp_sockaddr_in addr = {0};
	uint32_t ip_addr = 0;
	odp_bool_t *is_running = NULL;
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;

	fd_rcv = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				OFP_IPPROTO_UDP);
	if (fd_rcv == -1) {
		OFP_ERR("Faild to create RCV socket (errno = %d)\n",
			ofp_errno);
		return;
	}

	/* Bind it to the address from first interface */
	ifnet = ofp_ifport_ifnet_get(0, OFP_IFPORT_NET_SUBPORT_ITF);
	if (ifnet == OFP_IFNET_INVALID) {
		OFP_ERR("Interface not found.");
		return;
	}

	if (ofp_ifnet_ipv4_addr_get(ifnet, OFP_IFNET_IP_TYPE_IP_ADDR,
				    &ip_addr)) {
		OFP_ERR("Failed to get IP address.");
		return;
	}

	addr.sin_len = sizeof(struct ofp_sockaddr_in);
	addr.sin_family = OFP_AF_INET;
	addr.sin_port = odp_cpu_to_be_16(TEST_PORT);
	addr.sin_addr.s_addr = ip_addr;

	if (ofp_bind(fd_rcv, (const struct ofp_sockaddr *)&addr,
		sizeof(struct ofp_sockaddr_in)) == -1) {
		OFP_ERR("Faild to bind socket (errno = %d)\n", ofp_errno);
		return;
	}

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		return;
	}

	while (*is_running) {
		len = ofp_recv(fd_rcv, buf, len, OFP_MSG_DONTWAIT);
		if (len == -1) {
			if (ofp_errno == OFP_EWOULDBLOCK)
				continue;

			OFP_ERR("Faild to receive data (errno = %d)\n",
				ofp_errno);
			break;
		}
		OFP_INFO("Data received: length = %d.\n", len);
	}

	if (fd_rcv != -1) {
		ofp_close(fd_rcv);
		fd_rcv = -1;
	}
	OFP_INFO("Test ended.\n");
}

/** Configure IPv4 addresses
 *
 * @param itf_param appl_arg_ifs_t Interfaces to configure
 * @return int 0 on success, -1 on error
 *
 */
static int configure_interface_addresses(appl_arg_ifs_t *itf_param)
{
	struct appl_arg_if *ifarg = NULL;
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;
	uint32_t addr = 0;
	int port = 0;
	uint16_t subport = 0;
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

		ifnet = ofp_ifport_net_ifnet_get_by_name(ifarg->if_name);
		if (ifnet == OFP_IFNET_INVALID) {
			OFP_ERR("Error: interface not found: %s",
				ifarg->if_name);
			ret = -1;
			break;
		}

		if (ofp_ifnet_port_get(ifnet, &port, &subport)) {
			OFP_ERR("Error: Failed to get <port, sub-port>: %s",
				ifarg->if_name);
			ret = -1;
			break;
		}

		if (!ofp_parse_ip_addr(ifarg->if_address, &addr)) {
			OFP_ERR("Error: Failed to parse IPv4 address: %s",
				ifarg->if_address);
			ret = -1;
			break;
		}

		res = ofp_ifport_net_ipv4_up(port, subport, 0, addr,
					     ifarg->if_address_masklen, 1);
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
