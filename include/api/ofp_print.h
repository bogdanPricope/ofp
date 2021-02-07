/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_PRINT_H__
#define __OFP_PRINT_H__

#include <string.h>

typedef struct ofp_print_s {
	int           fd;
	int (*print_cb)(struct ofp_print_s *pr, char *buf, size_t buf_size);
} ofp_print_t;

enum ofp_print_type {
	OFP_PRINT_FILE,
	OFP_PRINT_OFP_SOCK,
	OFP_PRINT_LINUX_SOCK
};

void ofp_print_init(ofp_print_t *pr, int fd, enum ofp_print_type type);

int ofp_print_buffer(ofp_print_t *pr, char *buf, size_t buf_size);
int ofp_print(ofp_print_t *pr, const char *fmt, ...);

#endif /* __OFP_PRINT_H__ */

