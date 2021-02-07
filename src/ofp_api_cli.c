/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_errno.h"
#include "ofpi_api_cli.h"
#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"

int ofp_start_cli_thread(int core_id, char *cli_file)
{
#ifdef CLI
	return ofp_start_cli_thread_imp(core_id, cli_file);
#else
	(void)core_id;
	(void)cli_file;

	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_stop_cli_thread(void)
{
#ifdef CLI
	return ofp_stop_cli_thread_imp();
#else
	return OFP_ENOTSUP;
#endif /* CLI */
}

void ofp_cli_add_command(const char *cmd, const char *help,
			 ofp_cli_cb_func func)
{
#ifdef CLI
	ofp_cli_add_command_imp(cmd, help, func);
#else
	(void)cmd;
	(void)help;
	(void)func;
#endif /* CLI */
}

int ofp_cli_print(void *handle, char *buf, size_t buf_size)
{
	return ofp_print_buffer((ofp_print_t *)handle, buf, buf_size);
}
