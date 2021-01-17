/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef _IOCTL_TEST_H_
#define _IOCTL_TEST_H_

#include <odp_api.h>

int ofp_start_ioctl_thread(ofp_thread_t *thread_ioctl, int core_id);

#endif
