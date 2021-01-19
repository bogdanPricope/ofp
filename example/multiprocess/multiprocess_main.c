/* Copyright (c) 2020, Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ofp.h"
#include "odp/helper/linux.h"

#define MAX_WORKERS		64
#define LINUX_CONTROL_CPU 0
#define LPORT_DEFAULT 20000
#define RETRY_MAX 10
#define CNT_UDP 10
#define CNT_TCP 100

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

typedef enum {
	APP_MODE_UDP = 0,
	APP_MODE_TCP
} app_mode;

	/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to use */
	char **if_names;	/**< Array of pointers to interface names */
	char *cli_file;
	char *laddr;
	int lport;
	app_mode mode;
	uint64_t recv_count;
} appl_args_t;

static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

int udp_test(appl_args_t *arg);
int tcp_test(appl_args_t *arg);

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
	ofp_process_t proc_tbl[MAX_WORKERS];
	ofp_process_param_t proc_param = {0};
	int num_workers, i, ret = 0;
	odp_cpumask_t cpumask_workers;
	char cpumaskstr[64];

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	/*
	 * This example assumes that core LINUX_CONTROL_CPU runs Linux kernel
	 * background tasks, ODP/OFP management threads and the control process.
	 * By default, cores LINUX_CONTROL_CPU + 1 and beyond will be populated
	 * with a OFP processing workers.
	 */

	ofp_initialize_param(&app_init_params);
	app_init_params.linux_core_id = LINUX_CONTROL_CPU;
	app_init_params.if_count = params.if_count;
	for (i = 0; i < params.if_count && i < OFP_FP_INTERFACE_MAX; i++) {
		strncpy(app_init_params.if_names[i], params.if_names[i],
			OFP_IFNAMSIZ);
		app_init_params.if_names[i][OFP_IFNAMSIZ - 1] = '\0';
	}

	/*
	 * Initialize OFP. This will open a pktio instance for each interface
	 * supplied as argument by the user.
	 */

	if (ofp_initialize(&app_init_params) != 0) {
		printf("Error: OFP global init failed.\n");
		return EXIT_FAILURE;
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	num_workers = odp_cpu_count() - 1;
	if (params.core_count) {
		num_workers = params.core_count;
		if (num_workers > odp_cpu_count() - 1)
			num_workers = odp_cpu_count() - 1;
	}

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	odp_cpumask_zero(&cpumask_workers);
	for (i = 0; i < num_workers; i++)
		odp_cpumask_set(&cpumask_workers, LINUX_CONTROL_CPU + 1 + i);
	if (odp_cpumask_to_str(&cpumask_workers, cpumaskstr,
			       sizeof(cpumaskstr)) < 0) {
		printf("Error: Too small buffer provided to "
		       "odp_cpumask_to_str\n");
		ofp_terminate();
		return EXIT_FAILURE;
	}

	printf("Control CPU:    %i\n", LINUX_CONTROL_CPU);
	printf("First workers:  %i\n", odp_cpumask_first(&cpumask_workers));
	printf("Num workers:    %i\n", num_workers);
	printf("Workers CPU mask:       %s\n", cpumaskstr);

	/* Start worker processes */
	memset(proc_tbl, 0, sizeof(proc_tbl));
	proc_param.thr_type = ODP_THREAD_WORKER;

	ret = ofp_process_fork_n(proc_tbl, &cpumask_workers, &proc_param);
	if (ret == -1) {
		printf("Error: Failed to start children processes.\n");
		ofp_stop_processing();
		ofp_terminate();
		return EXIT_FAILURE;
	}

	if (ret == 0) {
		default_event_dispatcher(ofp_eth_vlan_processing);
		exit(0);
	}

	if (ofp_start_cli_thread(app_init_params.linux_core_id,
				 params.cli_file) < 0) {
		OFP_ERR("Error: Failed to init CLI thread");
	}

	if (params.mode == APP_MODE_UDP)
		udp_test(&params);
	else
		tcp_test(&params);

	ofp_stop_processing();

	ofp_process_wait_n(proc_tbl, num_workers);

	if (ofp_terminate() < 0)
		printf("Error: ofp_terminate failed\n");

	printf("End Main().\n");
	return 0;
}

static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{"laddr", required_argument,
			NULL, 'l'},/* return 'l' */
		{"lport", required_argument,
			NULL, 'p'}, /*return 'p' */
		{"rcv_count", required_argument,
			NULL, 'n'}, /*return 'n' */
		{"mode", required_argument,	NULL, 'm'}, /* return 'm'*/
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));
	appl_args->mode = APP_MODE_UDP;
	appl_args->lport = LPORT_DEFAULT;
	appl_args->recv_count = 0;

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hf:l:p:m:n:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->cli_file = malloc(len);
			if (appl_args->cli_file == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->cli_file, optarg);
			break;
		case 'l':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */
			appl_args->laddr = malloc(len);
			if (appl_args->laddr == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->laddr, optarg);
			break;
		case 'p':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->lport = atoi(optarg);
			break;
		case 'n':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->recv_count = (uint64_t)atoll(optarg);
			break;
		case 'm':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			if (!strcmp("u", optarg)) {
				appl_args->mode = APP_MODE_UDP;
			} else if (!strcmp("t", optarg)) {
				appl_args->mode = APP_MODE_TCP;
			} else {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (appl_args->if_count > OFP_FP_INTERFACE_MAX) {
		OFP_ERR("Error: Invalid number of interfaces: maximum %d\n",
			OFP_FP_INTERFACE_MAX);
		exit(EXIT_FAILURE);
	}

	if (!appl_args->recv_count) {
		if (appl_args->mode == APP_MODE_UDP)
			appl_args->recv_count = CNT_UDP;
		else
			appl_args->recv_count = CNT_TCP;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
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
		   "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -f, --cli-file <file name> CLI commands file\n"
		   "    CLI commands can be used to configure IP addresses, etc.\n"
		   "  -l, --laddr Local address where sockets are bound\n"
		   "    Default: address of the first interface\n"
		   "  -p, --lport <port> Local port where sockets are bound\n"
		   "    Default: %d\n"
		   "  -m, --mode <u|t> Application mode. Default: UDP test\n"
		   "    Modes:\n"
		   "      u - UDP test\n"
		   "      t - TCP test\n"
		   "  -c, --count <number> Core count.\n"
		   "  -n, --rcv_count <number> Received data before exit.\n"
		   "    Argument represents:\n"
		   "      number of datagrams - UDP test. Default %d\n"
		   "      number of bytes - TCP test\n. Default: %d"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname), LPORT_DEFAULT,
		   CNT_UDP, CNT_TCP);
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
		   "CPU freq (hz):   %" PRIu64 "\n"
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
		   progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n\n");
	fflush(NULL);
}

#define BUFF_SIZE 1500
int udp_test(appl_args_t *arg)
{
	int sd;
	struct ofp_sockaddr_in laddr = {0};
	uint32_t my_ip_addr = 0;
	int ret, retry = 0;
	uint64_t i, cnt = arg->recv_count;
	char buff[BUFF_SIZE];
	ofp_ssize_t dgram_size;

	sd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP);
	if (sd == -1) {
		OFP_ERR("Error: Failed to create socket: errno = %s!\n",
			ofp_strerror(ofp_errno));
		return -1;
	}

	laddr.sin_family = OFP_AF_INET;
	laddr.sin_port = odp_cpu_to_be_16((uint16_t)arg->lport);
	if (arg->laddr)
		my_ip_addr = inet_addr(arg->laddr);
	else
		my_ip_addr =
			ofp_port_get_ipv4_addr(0, 0,
					       OFP_PORTCONF_IP_TYPE_IP_ADDR);
	laddr.sin_addr.s_addr = my_ip_addr;
	laddr.sin_len = sizeof(laddr);

	/* Bind to local address*/
	retry = 0;
	do {
		ret = ofp_bind(sd, (struct ofp_sockaddr *)&laddr,
			       sizeof(struct ofp_sockaddr));
		if (ret < 0) {
			retry++;
			if (retry >= RETRY_MAX)
				break;
			sleep(1);
		}
	} while (ret < 0);

	if (ret < 0) {
		OFP_ERR("Error: Failed to bind: addr=0x%x, port=%d: errno=%s\n",
			my_ip_addr, arg->lport, ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	for (i = 0; i < cnt; i++) {
		dgram_size = ofp_recv(sd, (void *)buff, BUFF_SIZE, 0);
		if (dgram_size == -1) {
			OFP_ERR("Error: ofp_recv() failed: errno=%s.",
				ofp_strerror(ofp_errno));
			break;
		}
		OFP_INFO("%ld bytes received", dgram_size);
	}

	ofp_close(sd);
	return 0;
}

int tcp_test(appl_args_t *arg)
{
	int sd, cd;
	struct ofp_sockaddr_in laddr = {0};
	uint32_t my_ip_addr = 0;
	int ret, retry = 0;
	ofp_ssize_t recv_size, total_recv_size = 0;
	char buff[BUFF_SIZE];

	sd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (sd == -1) {
		OFP_ERR("Error: Failed to create socket: errno = %s!\n",
			ofp_strerror(ofp_errno));
		return -1;
	}

	laddr.sin_family = OFP_AF_INET;
	laddr.sin_port = odp_cpu_to_be_16((uint16_t)arg->lport);
	if (arg->laddr)
		my_ip_addr = inet_addr(arg->laddr);
	else
		my_ip_addr =
			ofp_port_get_ipv4_addr(0, 0,
					       OFP_PORTCONF_IP_TYPE_IP_ADDR);
	laddr.sin_addr.s_addr = my_ip_addr;
	laddr.sin_len = sizeof(laddr);

	/* Bind to local address*/
	retry = 0;
	do {
		ret = ofp_bind(sd, (struct ofp_sockaddr *)&laddr,
			       sizeof(struct ofp_sockaddr));
		if (ret < 0) {
			retry++;
			if (retry >= RETRY_MAX)
				break;
			sleep(1);
		}
	} while (ret < 0);

	if (ret < 0) {
		OFP_ERR("Error: Failed to bind: addr=0x%x, port=%d: errno=%s\n",
			my_ip_addr, arg->lport, ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	if (ofp_listen(sd, 1)) {
		OFP_ERR("Error: Failed to listen: errno=%s\n",
			ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	cd = ofp_accept(sd, NULL, NULL);
	if (cd == -1) {
		OFP_ERR("Error: Failed to accept connection: errno=%s\n",
			ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	do {
		recv_size = ofp_recv(cd, (void *)buff, BUFF_SIZE, 0);
		if (recv_size == -1) {
			OFP_ERR("Error: ofp_recv() failed: errno=%s.",
				ofp_strerror(ofp_errno));
			break;
		} else if (recv_size == 0) {
			break;
		}

		total_recv_size += recv_size;
		OFP_INFO("%ld/%ld bytes received",
			 total_recv_size, arg->recv_count);
	} while ((uint64_t)total_recv_size < arg->recv_count);

	ofp_close(cd);
	ofp_close(sd);
	return 0;
}

