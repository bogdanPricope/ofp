/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _UDP_SERVER_H_
#define _UDP_SERVER_H_

#include <odp_api.h>

#define UDP_LPORT 2048

int udpecho_config(void *arg);
int udpecho_cleanup(void);

#endif
