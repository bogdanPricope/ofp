/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_log.h"
#include "ofpi_cli.h"
#include "ofpi_cli_shm.h"
#include "ofpi_util.h"

void f_alias_set(ofp_print_t *pr, const char *s)
{
	const char *name;
	int name_len;
	const char *line;
	uint32_t i;
	size_t len_max = 0;

	(void)pr;

	name = s;
	while ((*s != ' ') && (*s != 0))
		s++;
	name_len = s - name;

	line  = NULL;
	if (*s != 0) {
		while (*s == ' ')
			s++;
		if (*s != 0)
			line  = s;
	}

	for (i = 0; i < V_cli_alias_table_size; i++) {
		if (V_cli_alias_table[i].name[0] == 0) {
			/* alias name*/
			len_max = name_len;
			if (name_len > ALIAS_TABLE_NAME_LEN - 1)
				len_max = ALIAS_TABLE_NAME_LEN - 1;
			odp_memcpy(V_cli_alias_table[i].name, name, len_max);
			V_cli_alias_table[i].name[len_max] = 0;

			/* alias cmd*/
			len_max = strlen(line);
			if (len_max > ALIAS_TABLE_CMD_LEN - 1)
				len_max = ALIAS_TABLE_CMD_LEN - 1;
			odp_memcpy(V_cli_alias_table[i].cmd, line, len_max);
			V_cli_alias_table[i].cmd[len_max] = 0;

			/*Add command*/
			if (f_add_alias_command(V_cli_alias_table[i].name)) {
				V_cli_alias_table[i].name[0] = 0;
				V_cli_alias_table[i].cmd[0] = 0;

				ofp_print(pr, "Error: Failed to add alias");
			}
			break;
		} else {
			if (strncmp(V_cli_alias_table[i].name,
				    name, name_len) == 0) {
				len_max = strlen(line);
				if (len_max > ALIAS_TABLE_CMD_LEN - 1)
					len_max = ALIAS_TABLE_CMD_LEN - 1;
				odp_memcpy(V_cli_alias_table[i].cmd,
					   line, len_max);
				V_cli_alias_table[i].cmd[len_max] = 0;
				break;
			}
		}
	}
}

void f_alias_show(ofp_print_t *pr, const char *s)
{
	uint32_t i;

	(void)s;
	ofp_print(pr, "Alias      Command\r\n");
	for (i = 0; i < V_cli_alias_table_size; i++) {
		if (V_cli_alias_table[i].name[0] != 0) {
			ofp_print(pr, "%-10s %s\r\n", V_cli_alias_table[i].name,
				  V_cli_alias_table[i].cmd);
		} else {
			break;
		}
	}
}

void f_help_alias(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr,
		  "Add an alias for a command:\r\n"
		  "  alias set <name> \"<command line>\"\r\n"
		  "  Example:\r\n"
		  "    alias set ll \"loglevel show\"\r\n\r\n");

	ofp_print(pr,
		  "Show alias table:\r\n"
		  "  alias show\r\n\r\n");

	ofp_print(pr,
		  "Show (this) help:\r\n"
		  "  alias help\r\n\r\n");
}
