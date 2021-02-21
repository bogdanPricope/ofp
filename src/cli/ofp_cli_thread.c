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
#include "ofpi_util.h"

static int cli_bind(int fd, char *addr, uint16_t port)
{
	struct sockaddr_in my_addr;

	odp_memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(port);
	if (!ofp_parse_ip_addr(addr, &my_addr.sin_addr.s_addr)) {
		OFP_ERR("Error: Invalid address (%s).\n", addr);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr_in)) < 0)
		return 1;

	return 0;
}

/** CLI server thread
 *
 * @param arg void*
 * @return void*
 *
 */
static int cli_server(void *arg)
{
	int cli_serv_fd = -1;
	int reuse = 1;
	int tmp = 0;
	fd_set read_fd, fds;
	int select_nfds;
	struct cli_conn *conn = NULL;
	odp_bool_t *is_running = NULL;

	(void)arg;

	OFP_INFO("CLI server started on core %i\n", odp_cpu_id());

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("Error: Failed to get processing state.");
		return -1;
	}

	/* Create server socket */
	cli_serv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (cli_serv_fd < 0) {
		OFP_ERR("Error: fail to create socket.\n");
		return -1;
	}

	if (setsockopt(cli_serv_fd, SOL_SOCKET, SO_REUSEADDR,
		       (void *)&reuse, sizeof(reuse)) < 0)
		OFP_ERR("cli setsockopt (SO_REUSEADDR)\n");

	/* Bind to address */
	while (*is_running && !V_cli_os_thread_is_stopping) {
		tmp = cli_bind(cli_serv_fd,
			       V_global_param.cli.os_thread.addr,
			       V_global_param.cli.os_thread.port);

		if (tmp == 0) {
			break;	/* bind OK*/
		} else if (tmp < 0) {
			OFP_ERR("Error: Fatal error while binding.\n");
			return -1;
		}

		/* retry */
		sleep(1);
	}

	/* Listen for connections */
	listen(cli_serv_fd, 1);

	/* Process connections */
	FD_ZERO(&read_fd);
	FD_SET(cli_serv_fd, &read_fd);

	while (*is_running && !V_cli_os_thread_is_stopping) {
		struct timeval timeout;
		int r;

		/* Requested to close the connection? */
		if (conn && conn->close_cli) {
			if (conn->fd > 0)
				close(conn->fd);
			conn = NULL;
			OFP_DBG("CLI connection closed\r\n");
		}

		/* Prepare select read set*/
		fds = read_fd;
		select_nfds = cli_serv_fd + 1;

		if (conn && conn->fd > 0) {
			FD_SET(conn->fd, &fds);
			if (conn->fd + 1 > select_nfds)
				select_nfds = conn->fd + 1;
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		r = select(select_nfds, &fds, NULL, NULL, &timeout);

		if (r < 0)
			continue;

		if (FD_ISSET(cli_serv_fd, &fds)) {
			int fda = -1;

			/* connection already opened -> close it*/
			if (conn && conn->fd > 0) {
				close(conn->fd);
				conn = NULL;
			}

			fda = accept(cli_serv_fd, NULL, NULL);
			if (fda < 0) {
				OFP_ERR("Error: cli serv accept");
				continue;
			}
			conn = cli_conn_accept(fda, OFPCLI_CONN_TYPE_SOCKET_OS);
			if (conn == NULL) {
				close(fda);
				continue;
			}

			OFP_DBG("CLI connection established (%d)\r\n", fda);
		} else if (conn && conn->fd > 0 && FD_ISSET(conn->fd, &fds)) {
			unsigned char c;

			/*receive data one char at a time */
			if (recv(conn->fd, &c, 1, 0) <= 0) {
				close(conn->fd);
				conn = NULL;
				OFP_ERR("Failed to recive data on socket: %s",
					strerror(errno));
				OFP_DBG("CLI connection closed\r\n");
				continue;
			}

			if (cli_conn_process(conn, c)) {
				close(conn->fd);
				conn = NULL;
				OFP_DBG("CLI connection closed\r\n");
			}
		}
	} /* while () */

	if (conn && conn->fd > 0)
		close(conn->fd);
	conn = NULL;

	close(cli_serv_fd);
	cli_serv_fd = -1;

	OFP_DBG("CLI server exiting");
	return 0;
}

int ofp_cli_start_os_thread_imp(int core_id)
{
	ofp_thread_param_t thread_param;
	odp_cpumask_t cpumask;

	if (V_cli_os_thread_is_running) {
		OFP_ERR("Error: CLI thread is running.");
		return -1;
	}

	if (core_id == OFP_CONTROL_CORE)
		core_id = V_global_param.linux_core_id;
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_thread_param_init(&thread_param);
	thread_param.start = cli_server;
	thread_param.arg = NULL;
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

int ofp_cli_stop_os_thread_imp(void)
{
	if (V_cli_os_thread_is_running) {
		V_cli_os_thread_is_stopping = 1;
		ofp_thread_join(&V_cli_os_thread, 1);
		V_cli_os_thread_is_running = 0;
		V_cli_os_thread_is_stopping = 0;
	}

	return 0;
}
