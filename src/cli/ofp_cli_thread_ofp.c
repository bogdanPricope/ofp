/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <unistd.h>
#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"
#include "ofpi_cli_shm.h"
#include "ofpi_socket.h"
#include "ofpi_in.h"
#include "ofpi_errno.h"
#include "ofpi_util.h"

static int cli_bind(int fd, char *addr, uint16_t port)
{
	struct ofp_sockaddr_in my_addr;

	odp_memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_len = sizeof(struct ofp_sockaddr_in);
	my_addr.sin_family = OFP_AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(port);
	if (!ofp_parse_ip_addr(addr, &my_addr.sin_addr.s_addr)) {
		OFP_ERR("Error: Invalid address (%s).\n", addr);
		return -1;
	}

	if (ofp_bind(fd, (const struct ofp_sockaddr *)&my_addr,
		     sizeof(my_addr)) < 0)
		return 1;

	return 0;
}

/** CLI server thread
 *
 * @param arg void*
 * @return 0 on success, !0 on error
 *
 */
static int cli_server(void *arg)
{
	int cli_serv_fd = -1;
	int reuse = 1;
	int tmp = 0;
	ofp_fd_set read_fd, fds;
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
	cli_serv_fd = ofp_socket(OFP_AF_INET, OFP_SOCK_STREAM, OFP_IPPROTO_TCP);
	if (cli_serv_fd < 0) {
		OFP_ERR("Error: fail to create socket.\n");
		return -1;
	}

	if (ofp_setsockopt(cli_serv_fd, OFP_SOL_SOCKET, OFP_SO_REUSEADDR,
			   (void *)&reuse, sizeof(reuse)) < 0)
		OFP_ERR("cli setsockopt (SO_REUSEADDR)\n");

	/* Bind to address */
	while (*is_running && !V_cli_ofp_thread_is_stopping) {
		tmp = cli_bind(cli_serv_fd,
			       V_global_param.cli.ofp_thread.addr,
			       V_global_param.cli.ofp_thread.port);

		if (tmp == 0) {
			OFP_DBG("CLI thread bound successfully on %s %d\n",
				V_global_param.cli.ofp_thread.addr,
				V_global_param.cli.ofp_thread.port);
			break;	/* bind OK*/
		} else if (tmp < 0) {
			OFP_ERR("Error: Fatal error while binding.\n");
			ofp_close(cli_serv_fd);
			return -1;
		}

		/* retry */
		sleep(1);
	}

	/* Listen for connections */
	if (ofp_listen(cli_serv_fd, 1)) {
		OFP_ERR("Error: Failed to start listening.\n");
		ofp_close(cli_serv_fd);
		return -1;
	}

	/* Process connections */
	OFP_FD_ZERO(&read_fd);
	OFP_FD_SET(cli_serv_fd, &read_fd);

	while (*is_running && !V_cli_ofp_thread_is_stopping) {
		struct ofp_timeval timeout;
		int r;

		/* Requested to close the connection? */
		if (conn && conn->close_cli) {
			if (conn->fd > 0)
				ofp_close(conn->fd);
			conn = NULL;
			OFP_DBG("CLI connection closed\r\n");
		}

		/* Prepare select read set*/
		fds = read_fd;
		select_nfds = cli_serv_fd + 1;

		if (conn && conn->fd > 0) {
			OFP_FD_SET(conn->fd, &fds);
			if (conn->fd + 1 > select_nfds)
				select_nfds = conn->fd + 1;
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		r = ofp_select(select_nfds, &fds, NULL, NULL, &timeout);

		if (r <= 0)
			continue;

		if (OFP_FD_ISSET(cli_serv_fd, &fds)) {
			int fda = -1;

			/* connection already opened -> close it*/
			if (conn && conn->fd > 0) {
				ofp_close(conn->fd);
				conn = NULL;
			}

			fda = ofp_accept(cli_serv_fd, NULL, NULL);
			if (fda < 0) {
				OFP_ERR("Error: cli serv accept");
				continue;
			}

			conn = cli_conn_accept(fda,
					       OFPCLI_CONN_TYPE_SOCKET_OFP);
			if (conn == NULL) {
				ofp_close(fda);
				continue;
			}

			OFP_DBG("CLI connection established (%d)\r\n", fda);
		} else if (conn && conn->fd > 0 &&
			   OFP_FD_ISSET(conn->fd, &fds)) {
			unsigned char c;

			/*receive data one char at a time */
			if (ofp_recv(conn->fd, &c, 1, 0) <= 0) {
				ofp_close(conn->fd);
				conn = NULL;
				OFP_ERR("Failed to recive data on socket: %d",
					ofp_errno);
				OFP_DBG("CLI connection closed\r\n");
				continue;
			}

			if (cli_conn_process(conn, c)) {
				ofp_close(conn->fd);
				conn = NULL;
				OFP_DBG("CLI connection closed\r\n");
			}
		}
	} /* while() */

	if (conn && conn->fd > 0)
		ofp_close(conn->fd);
	conn = NULL;

	ofp_close(cli_serv_fd);
	cli_serv_fd = -1;

	OFP_DBG("CLI server exiting");
	return 0;
}

int ofp_cli_start_ofp_thread_imp(int core_id)
{
	ofp_thread_param_t thread_param;
	odp_cpumask_t cpumask;

	if (V_cli_ofp_thread_is_running) {
		OFP_ERR("Error: CLI thread is running.");
		return -1;
	}

	if (core_id == OFP_DFLT_CLI_CORE)
		core_id = V_global_param.cli.ofp_thread.core_id;

	if (core_id == OFP_CONTROL_CORE)
		core_id = V_global_param.linux_core_id;

	if (core_id < 0) {
		OFP_ERR("Error: Invalid core ID: %d", core_id);
		return -1;
	}

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_thread_param_init(&thread_param);
	thread_param.start = cli_server;
	thread_param.arg = NULL;
	thread_param.thr_type = ODP_THREAD_CONTROL;
	thread_param.description = "cli_ofp";

	if (ofp_thread_create(&V_cli_ofp_thread,
			      1,
			      &cpumask,
			      &thread_param) != 1) {
		OFP_ERR("Failed to start CLI thread.");
		V_cli_ofp_thread_is_running = 0;
		return -1;
	}

	V_cli_ofp_thread_is_running = 1;
	return 0;
}

int ofp_cli_stop_ofp_thread_imp(void)
{
	if (V_cli_ofp_thread_is_running) {
		V_cli_ofp_thread_is_stopping = 1;
		ofp_thread_join(&V_cli_ofp_thread, 1);
		V_cli_ofp_thread_is_running = 0;
		V_cli_ofp_thread_is_stopping = 0;
	}

	return 0;
}

