/* Copyright (c) 2021, Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli_arg_parse.h"

/**
 * Parse command line argument 'list of interface'
 *
 * Example:
 * eth1,eth2,eth3
 * eth1@192.168.100.10/24,eth2@172.24.200.10/16
 *
 * @param argv       Argument to parse
 * @param itf_param  Structure to store the parsed information
 * @retval EXIT_SUCCESS on success
 * @retval EXIT_FAILURE on error
 */
int ofpexpl_parse_interfaces(char *argv, appl_arg_ifs_t *itf_param)
{
	char *tkn = NULL;
	char *tkn_end = NULL;
	char *tkn_addr = NULL;
	char *tkn_addr_mask = NULL;
	char *argv_cpy = NULL;
	int idx = 0;
	int ret = EXIT_SUCCESS;
	struct appl_arg_if *ifarg = NULL;

	if (!argv || !strlen(argv) || !itf_param)
		return EXIT_FAILURE;

	memset(itf_param, 0, sizeof(*itf_param));

	/* Get number of interfaces*/
	tkn = argv;
	while (tkn) {
		tkn_end = strchr(tkn, ',');
		itf_param->if_count++;
		tkn = (tkn_end != NULL) ? tkn_end + 1 : NULL;
	}

	/* Get interfaces */
	do {
		itf_param->if_array = calloc(itf_param->if_count,
					     sizeof(*itf_param->if_array));
		if (!itf_param->if_array) {
			ret = EXIT_FAILURE;
			break;
		}

		argv_cpy = strdup(argv);
		if (!argv_cpy) {
			ret = EXIT_FAILURE;
			break;
		}

		tkn = argv_cpy;
		idx = 0;
		while (tkn) {
			ifarg = &itf_param->if_array[idx];
			tkn_end = strchr(tkn, ',');
			if (tkn_end)
				*tkn_end = '\0';

			tkn_addr = strchr(tkn, '@');
			if (tkn_addr) {
				*tkn_addr = '\0';
				tkn_addr++;
			}

			ifarg->if_name = strdup(tkn);
			if (!ifarg->if_name) {
				ret = EXIT_FAILURE;
				break;
			}

			if (tkn_addr) {
				tkn_addr_mask = strchr(tkn_addr, '/');
				if (!tkn_addr_mask) {
					ret = EXIT_FAILURE;
					break;
				}
				*tkn_addr_mask = '\0';
				tkn_addr_mask++;

				ifarg->if_address = strdup(tkn_addr);
				if (!ifarg->if_address) {
					ret = EXIT_FAILURE;
					break;
				}

				ifarg->if_address_masklen = atoi(tkn_addr_mask);
			}

			idx++;
			tkn = (tkn_end != NULL) ? tkn_end + 1 : NULL;
		}
	} while (0);

	if (argv_cpy) {
		free(argv_cpy);
		argv_cpy = NULL;
	}

	if (ret == EXIT_FAILURE) {
		ofpexpl_parse_interfaces_param_cleanup(itf_param);
		return EXIT_FAILURE;
	}

	return ret;
}

/**
 * Cleanup command line argument 'list of interface'
 *
 * @param itf_param  Interface parameters
 */
void ofpexpl_parse_interfaces_param_cleanup(appl_arg_ifs_t *itf_param)
{
	int i;

	if (!itf_param)
		return;

	for (i = 0; i < itf_param->if_count; i++) {
		if (itf_param->if_array[i].if_name)
			free(itf_param->if_array[i].if_name);
		if (itf_param->if_array[i].if_address)
			free(itf_param->if_array[i].if_address);
	}

	free(itf_param->if_array);
	itf_param->if_count = 0;
}
