/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <string.h>
#include <odp_api.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"
#include "ofpi_cli_shm.h"

#define OFP_SERVER_PORT 2345

/** CLI server thread
 *
 * @param arg void*
 * @return void*
 *
 */
static int cli_server(void *arg)
{
	int cli_serv_fd = -1, cli_conn_fd = -1;
	int alen;
	struct sockaddr_in my_addr, caller;
	int reuse = 1;
	fd_set read_fd, fds;
	char *file_name;
	int select_nfds;
	struct cli_conn *conn = NULL;
	odp_bool_t *is_running = NULL;

	file_name = (char *)arg;

	OFP_INFO("CLI server started on core %i\n", odp_cpu_id());

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("Error: Failed to get processing state.");
		return -1;
	}

	cli_process_file(file_name);

	cli_serv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (cli_serv_fd < 0) {
		OFP_ERR("Error: fail to create socket.\n");
		return -1;
	}

	if (setsockopt(cli_serv_fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&reuse, sizeof(reuse)) < 0)
		OFP_ERR("cli setsockopt (SO_REUSEADDR)\n");

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(OFP_SERVER_PORT);
	my_addr.sin_addr.s_addr = odp_cpu_to_be_32(INADDR_ANY);

	if (bind(cli_serv_fd, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr)) < 0) {
		OFP_ERR("serv bind\n");
		return -1;
	}

	listen(cli_serv_fd, 1);

	FD_ZERO(&read_fd);
	FD_SET(cli_serv_fd, &read_fd);

	while (*is_running) {
		struct timeval timeout;
		int r;

		fds = read_fd;
		select_nfds = cli_serv_fd + 1;

		if (cli_conn_fd > 0) {
			FD_SET(cli_conn_fd, &fds);
			if (cli_conn_fd > select_nfds - 1)
				select_nfds = cli_conn_fd + 1;
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		r = select(select_nfds, &fds, NULL, NULL, &timeout);

		if (conn && conn->close_cli) {
			if (cli_conn_fd > 0)
				close(cli_conn_fd);
			cli_conn_fd = -1;
			conn = NULL;
			OFP_DBG("CLI connection closed\r\n");
		}

		if (r < 0)
			continue;

		if (FD_ISSET(cli_serv_fd, &fds)) {
			if (cli_conn_fd > 0) {
				close(cli_conn_fd);
				conn = NULL;
			}

			alen = sizeof(caller);
			cli_conn_fd = accept(cli_serv_fd,
					     (struct sockaddr *)&caller,
					     (socklen_t *)&alen);
			if (cli_conn_fd < 0) {
				OFP_ERR("cli serv accept");
				continue;
			}
			conn = cli_conn_accept(cli_conn_fd,
					       OFPCLI_CONN_TYPE_SOCKET_OS);
			if (conn == NULL) {
				close(cli_conn_fd);
				continue;
			}

			OFP_DBG("CLI connection established (%d)\r\n",
				cli_conn_fd);
		}

		if (cli_conn_fd > 0 && FD_ISSET(cli_conn_fd, &fds)) {
			unsigned char c;

			//receive data from client
			if (recv(cli_conn_fd, &c, 1, 0) <= 0) {
				close(cli_conn_fd);
				cli_conn_fd = -1;
				conn = NULL;
				OFP_ERR("Failed to recive data on socket: %s",
					strerror(errno));
				OFP_DBG("CLI connection closed\r\n");
				continue;
			}

			if (cli_conn_recv(conn, c)) {
				close(cli_conn_fd);
				cli_conn_fd = -1;
				conn = NULL;
				OFP_DBG("CLI connection closed\r\n");
			}
		}
	} /* while () */

	if (cli_conn_fd > 0)
		close(cli_conn_fd);
	cli_conn_fd = -1;
	conn = NULL;

	close(cli_serv_fd);
	cli_serv_fd = -1;

	OFP_DBG("CLI server exiting");
	return 0;
}

int ofp_start_cli_thread_imp(int core_id, char *cli_file)
{
	ofp_thread_param_t thread_param;
	odp_cpumask_t cpumask;

	if (V_cli_os_thread_is_running) {
		OFP_ERR("Error: CLI thread is running.");
		return -1;
	}

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_thread_param_init(&thread_param);
	thread_param.start = cli_server;
	thread_param.arg = cli_file;
	thread_param.thr_type = ODP_THREAD_CONTROL;
	thread_param.description = "cli";

	if (ofp_thread_create(&V_cli_os_thread,
			      1,
			      &cpumask,
			      &thread_param) != 1) {
		OFP_ERR("Failed to start CLI thread.");
		V_cli_os_thread_is_running = 0;
		return -1;
	}

	V_cli_os_thread_is_running = 1;
	return 0;
}

int ofp_stop_cli_thread_imp(void)
{
	if (V_cli_os_thread_is_running) {
		close_connections();
		ofp_thread_join(&V_cli_os_thread, 1);
		V_cli_os_thread_is_running = 0;
	}

	return 0;
}
