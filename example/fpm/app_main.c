/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "ofp.h"
#include "linux_sigaction.h"

#define MAX_WORKERS		32



/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *cli_file;
	int perf_stat;
} appl_args_t;

/**
 * helper funcs
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int start_performance(odp_instance_t instance, int core_id);

 /**
  * global OFP init parms
  */
ofp_global_param_t app_init_params;

/**
 * Get rid of path in filename - only for unix-type paths using '/'
 */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))


/**
 * local hook
 *
 * @param pkt odp_packet_t
 * @param protocol int
 * @return int
 *
 */
static enum ofp_return_code fastpath_local_hook(odp_packet_t pkt, void *arg)
{
	int protocol = *(int *)arg;
	(void) pkt;
	(void) protocol;
	return OFP_PKT_CONTINUE;
}

/**
 * Signal handler function
 *
 * @param signum int
 * @return void
 *
 */
static void ofp_sig_func_stop(int signum)
{
	printf("Signal handler (signum = %d) ... exiting.\n", signum);

	ofp_stop_processing();
}


/**
 * main() Application entry point
 *
 * This is the main function of the FPM application, it's a minimalistic
 * example, see 'usage' function for available arguments and usage.
 *
 * Using the number of available cores as input, this example sets up
 * ODP dispatcher threads executing OFP VLAN processesing and starts
 * a CLI function on a managment core.
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	appl_args_t params;
	int core_count, num_workers, ret_val;
	odp_cpumask_t cpumask;
	char cpumaskstr[64];
	odph_odpthread_params_t thr_params;
	odp_instance_t instance;

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, &params) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	if (ofp_sigactions_set(ofp_sig_func_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/*
	 * This example assumes that core #0 runs Linux kernel background tasks.
	 * By default, cores #1 and beyond will be populated with a OFP
	 * processing thread each.
	 */
	ofp_init_global_param(&app_init_params);

	app_init_params.if_count = params.if_count;
	app_init_params.if_names = params.if_names;

	if (app_init_params.pktin_mode != ODP_PKTIN_MODE_SCHED) {
		printf("Warning: Forcing scheduled pktin mode.\n");
		/* Receive packets through the ODP scheduler. */
		app_init_params.pktin_mode = ODP_PKTIN_MODE_SCHED;
	}
	switch (app_init_params.sched_sync) {
	case ODP_SCHED_SYNC_PARALLEL:
		printf("Warning: Packet order is not preserved with "
		       "parallel RX queues\n");
		break;
	case ODP_SCHED_SYNC_ATOMIC:
		/*
		 * Packet order is preserved since we have only one output
		 * queue per interface.
		 */
		break;
	case ODP_SCHED_SYNC_ORDERED:
		/*
		 * Ordered pktin queues allow processing one packet
		 * flow in many threads in parallel. Queued output
		 * must be used to get forwarded packets ordered back
		 * to the reception order at output.
		 */
		if (app_init_params.pktout_mode != ODP_PKTOUT_MODE_QUEUE)
			printf("Warning: Packet order is not preserved with "
			       "ordered RX queues and direct TX queues.\n");
		break;
	default:
		printf("Warning: Unknown scheduling synchronization mode. "
		       "Forcing atomic mode.\n");
		app_init_params.sched_sync = ODP_SCHED_SYNC_ATOMIC;
		break;
	}

	/* Exemplification of creating packet processing hooks */
	app_init_params.pkt_hook[OFP_HOOK_LOCAL] = fastpath_local_hook;

	/*
	 * Initialize OFP. This will also initialize ODP and open a pktio
	 * instance for each interface supplied as argument.
	 *
	 */
	if (ofp_init_global(&app_init_params) != 0) {
		printf("Error: OFP global init failed.\n");
		return EXIT_FAILURE;
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params);

	/*
	 * Get the number of available cores: one run-to-completion thread
	 * will be created per core.
	 */
	core_count = odp_cpu_count();

	if (params.core_count) {
		num_workers = params.core_count;
	} else {
		num_workers = core_count;
		if (core_count > 1)
			num_workers--;
	}
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/*
	 * Initializes cpumask with CPUs available for worker threads.
	 * Sets up to 'num' CPUs and returns the count actually set.
	 * Use zero for all available CPUs.
	 */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	if (odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr)) < 0) {
		printf("Error: Too small buffer provided to "
			"odp_cpumask_to_str\n");
		ofp_term_global();
		return EXIT_FAILURE;
	}

	printf("Num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/*
	 * Create and launch dataplane dispatcher worker threads to be placed
	 * according to the cpumask, thread_tbl will be populated with the
	 * created pthread IDs.
	 *
	 * In this case, all threads will run the default_event_dispatcher
	 * function with ofp_eth_vlan_processing as argument.
	 *
	 * If different dispatchers should run, or the same be run with differnt
	 * input arguments, the cpumask is used to control this.
	 */
	instance = ofp_get_odp_instance();
	memset(thread_tbl, 0, sizeof(thread_tbl));
	thr_params.start = default_event_dispatcher;
	thr_params.arg = ofp_eth_vlan_processing;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	ret_val = odph_odpthreads_create(thread_tbl,
					 &cpumask,
					 &thr_params);
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_stop_processing();
		odph_odpthreads_join(thread_tbl);
		ofp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * Now when the ODP dispatcher threads are running, further applications
	 * can be launched, in this case, we will start the OFP CLI thread on
	 * the management core, i.e. not competing for cpu cycles with the
	 * worker threads
	 */
	if (ofp_start_cli_thread(instance, app_init_params.linux_core_id,
		params.cli_file) < 0) {
		OFP_ERR("Error: Failed to init CLI thread");
		ofp_stop_processing();
		odph_odpthreads_join(thread_tbl);
		ofp_term_global();
		return EXIT_FAILURE;
	}

	/*
	 * If we choose to check performance, a performance monitoring client
	 * will be started on the management core. Once every second it will
	 * read the statistics from the workers from a shared memory region.
	 * Using this has negligible performance impact (<<0.01%).
	 */
	if (params.perf_stat) {
		if (start_performance(instance,
			app_init_params.linux_core_id) <= 0) {
			OFP_ERR("Error: Failed to init performance monitor");
			ofp_stop_processing();
			odph_odpthreads_join(thread_tbl);
			ofp_term_global();
			return EXIT_FAILURE;
		}
	}

	/*
	 * Wait here until all worker threads have terminated, then free up all
	 * resources allocated by odp_init_global().
	 */
	odph_odpthreads_join(thread_tbl);

	if (ofp_term_global() < 0)
		printf("Error: ofp_term_global failed\n");

	printf("FPM End Main()\n");

	return EXIT_SUCCESS;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"performance", no_argument, NULL, 'p'},	/* return 'p' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hpf:",
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
				return EXIT_FAILURE;
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				return EXIT_FAILURE;
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
				return EXIT_FAILURE;
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
			return EXIT_FAILURE;

		case 'p':
			appl_args->perf_stat = 1;
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
			len += 1;	/* add room for '\0' */

			appl_args->cli_file = malloc(len);
			if (appl_args->cli_file == NULL) {
				usage(argv[0]);
				return EXIT_FAILURE;
			}

			strcpy(appl_args->cli_file, optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */

	return EXIT_SUCCESS;
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
		   progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
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
		   "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -p, --performance    Performance Statistics\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}

static int perf_client(void *arg)
{
	(void) arg;

	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return -1;
	}

	ofp_set_stat_flags(OFP_STAT_COMPUTE_PERF);

	while (1) {
		struct ofp_perf_stat *ps = ofp_get_perf_statistics();
		printf ("Mpps:%4.3f\n", ((float)ps->rx_fp_pps)/1000000);
		usleep(1000000UL);
	}

	return 0;
}

static int start_performance(odp_instance_t instance, int core_id)
{
	odph_odpthread_t cli_linux_pthread;
	odp_cpumask_t cpumask;
	odph_odpthread_params_t thr_params;

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	thr_params.start = perf_client;
	thr_params.arg = NULL;
	thr_params.thr_type = ODP_THREAD_CONTROL;
	thr_params.instance = instance;
	return odph_odpthreads_create(&cli_linux_pthread,
				      &cpumask, &thr_params);

}
