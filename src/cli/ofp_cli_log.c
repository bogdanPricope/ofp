/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_cli.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

const char *loglevel_descript[] = {
        [OFP_LOG_DISABLED] = "disabled",
        [OFP_LOG_ERROR]    = "error",
        [OFP_LOG_WARNING]  = "warning",
        [OFP_LOG_INFO]     = "info",
        [OFP_LOG_DEBUG]    = "debug"
};

/* loglevel help */
/* help loglevel */
void f_help_loglevel(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Show log level\r\n"
		"  loglevel show\r\n\r\n");
	ofp_print(pr, "Set log level\r\n"
		"  loglevel set <debug|info|warning|error|disabled>\r\n"
                "  Note:\r\n"
                "    Debug level logs require --enable-debug configuration option\r\n"
                "  Example: Set log level to generate warning and error logs:\r\n"
		"    loglevel set warning\r\n\r\n");
	ofp_print(pr, "Show log level help (this help)\r\n"
		"  loglevel help\r\n");
}

/* loglevel */
/* loglevel show */
void f_loglevel_show(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr, "Log level: %s\r\n",
		  loglevel_descript[ofp_loglevel_get()]);
}

/* loglevel set */
void f_loglevel(ofp_print_t *pr, const char *s)
{
	int i;

	for (i = 0; i < OFP_LOG_MAX_LEVEL; i++) {
		if (strncmp(loglevel_descript[i], s,
			strlen(loglevel_descript[i])) == 0) {
			ofp_loglevel_set(i);
			return;
		}
	}

	ofp_print(pr, "Invalid value!\r\nUsage:\r\n");

	f_help_loglevel(pr, NULL);
}
