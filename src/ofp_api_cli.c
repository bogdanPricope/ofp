/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "ofpi_errno.h"
#include "ofpi_api_cli.h"
#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"

int ofp_cli_start_os_thread(int core_id)
{
#ifdef CLI
	return ofp_cli_start_os_thread_imp(core_id);
#else
	(void)core_id;

	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_cli_stop_os_thread(void)
{
#ifdef CLI
	return ofp_cli_stop_os_thread_imp();
#else
	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_cli_start_ofp_thread(int core_id)
{
#ifdef CLI
	return ofp_cli_start_ofp_thread_imp(core_id);
#else
	(void)core_id;

	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_cli_stop_ofp_thread(void)
{
#ifdef CLI
	return ofp_cli_stop_ofp_thread_imp();
#else
	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_cli_add_command(const char *cmd, const char *help,
			ofp_cli_cb_func func)
{
#ifdef CLI
	return ofp_cli_add_command_imp(cmd, help, func);
#else
	(void)cmd;
	(void)help;
	(void)func;

	return OFP_ENOTSUP;
#endif /* CLI */
}

int ofp_cli_print(void *handle, char *buf, size_t buf_size)
{
	return ofp_print_buffer((ofp_print_t *)handle, buf, buf_size);
}

int ofp_cli_process_file(char *cli_file)
{
#ifdef CLI
	return ofp_cli_process_file_imp(cli_file);
#else
	(void)cli_file;

	return OFP_ENOTSUP;
#endif /* CLI */
}
