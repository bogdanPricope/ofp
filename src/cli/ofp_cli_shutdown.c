/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_debug.h"
#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"
#include "ofpi_util.h"

void f_shutdown(struct cli_conn *conn, const char *s)
{
	(void)s;

	if (V_global_param.cli.enable_shutdown_cmd == 0) {
		ofp_sendf(conn->fd, "Error: shutdown through CLI not "
			"permitted.\r\n\r\n");
		sendcrlf(conn);
		return;
	}

	ofp_stop_processing();
	sendcrlf(conn);
}

void f_help_shutdown(struct cli_conn *conn, const char *s)
{
	(void)s;
	ofp_sendf(conn->fd, "Shutdown OFP:\r\n"
		"  shutdown\r\n\r\n");
	sendcrlf(conn);
}
