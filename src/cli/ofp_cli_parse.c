/*-
 * Copyright (c) 2016 ENEA Software AB
 * Copyright (c) 2016 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include "odp.h"
#include "ofpi_cli.h"

int token_string_to_val(char *token, uint32_t *val,
	const char *array_str[], const uint32_t array_val[])
{
	int i;

	for (i = 0; array_str[i]; i++)
		if (!strcmp(array_str[i], token)) {
			*val = array_val[i];
			return 0;
		}

	return -1;
}

int token_string_to_val_with_size(char *token, uint32_t *val,
	const char *array_str[], const uint32_t array_val[])
{
	int i;

	for (i = 0; array_str[i]; i++)
		if (!strncmp(array_str[i], token, strlen(array_str[i]))) {
			*val = array_val[i];
			return 0;
		}

	return -1;
}

const char* token_val_to_string(uint32_t token,
	const char *array_str[], const uint32_t array_val[])
{
	int i;

	for (i = 0; array_str[i]; i++)
		if (array_val[i] == token)
			return array_str[i];

	return NULL;
}

int token_match_array(char* token, const char *array_str[])
{
	int i;

	for (i = 0; array_str[i]; i++)
		if (!strncmp(array_str[i], token, strlen(array_str[i])))
			return 1;
	return 0;
}

