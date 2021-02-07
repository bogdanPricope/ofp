/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "ofpi_print.h"
#include "ofpi_socket.h"
#include "odp_api.h"

static int printFileCb(ofp_print_t *pr, char *buf, size_t buf_size)
{
	return write(pr->fd, buf, buf_size);
}

static int printLinuxSocketCb(ofp_print_t *pr, char *buf, size_t buf_size)
{
	return send(pr->fd, buf, buf_size, 0);
}

static int printOFPSocketCb(ofp_print_t *pr, char *buf, size_t buf_size)
{
	return ofp_send(pr->fd, buf, buf_size, 0);
}

void ofp_print_init(ofp_print_t *pr, int fd, enum ofp_print_type type)
{
	odp_memset(pr, 0, sizeof(*pr));

	pr->fd = fd;

	switch (type) {
	case OFP_PRINT_LINUX_SOCK:
		pr->print_cb = printLinuxSocketCb;
		break;
	case OFP_PRINT_OFP_SOCK:
		pr->print_cb = printOFPSocketCb;
		break;
	default:
		pr->print_cb = printFileCb;
	};
}

int ofp_print_buffer(ofp_print_t *pr, char *buf, size_t buf_size)
{
	return pr->print_cb(pr, buf, buf_size);
}

int ofp_print(ofp_print_t *pr, const char *fmt, ...)
{
	char buf[1024];
	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0)
		return -1;

	if (n > (int)sizeof(buf))
		n = (int)sizeof(buf);

	return pr->print_cb(pr, buf, (size_t)n);
}
