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
#include "ofpi_util.h"

struct alias_table_s alias_table[ALIAS_TABLE_LEN];

void f_alias_set(ofp_print_t *pr, const char *s)
{
	const char *name;
	int name_len;
	const char *line;
	int i;

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

	for (i = 0; i < ALIAS_TABLE_LEN; i++) {
		if (alias_table[i].name == 0) {

			alias_table[i].name = strndup(name, name_len);
			alias_table[i].cmd = strdup(line);
			f_add_alias_command(alias_table[i].name);
			break;
		} else {
			if (strncmp(alias_table[i].name, name, name_len) == 0) {
				if (alias_table[i].cmd)
					free(alias_table[i].cmd);
				alias_table[i].cmd = strdup(line);
				break;
			}
		}
	}
}

void f_alias_show(ofp_print_t *pr, const char *s)
{
	int i;

	(void)s;
	ofp_print(pr, "Alias      Command\r\n");
	for (i = 0; i < ALIAS_TABLE_LEN; i++) {
		if (alias_table[i].name != 0) {
			ofp_print(pr, "%-10s %s\r\n", alias_table[i].name,
				  alias_table[i].cmd);
		} else
			break;
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
