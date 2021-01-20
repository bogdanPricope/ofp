/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_EXAMPLE_SIGACTION__
#define __OFP_EXAMPLE_SIGACTION__

int ofpexpl_sigaction_set(void (*sig_func)(int));

void ofpexpl_sigfunction_stop(int signum);

#endif /* __OFP_EXAMPLE_SIGACTION__ */
