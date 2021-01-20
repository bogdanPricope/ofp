/* Copyright (c) 2021, Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>

#include "linux_resources.h"

#define MAX_CORE_FILE_SIZE	200000000

int ofpexpl_resources_set(void)
{
	struct rlimit rlp;

	getrlimit(RLIMIT_CORE, &rlp);
	printf("RLIMIT_CORE: %ld/%ld\n", rlp.rlim_cur, rlp.rlim_max);
	rlp.rlim_cur = MAX_CORE_FILE_SIZE;
	printf("Setting to max: %d\n", setrlimit(RLIMIT_CORE, &rlp));

	return 0;
}
