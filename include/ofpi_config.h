/* Copyright (c) 2015, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_CONFIG_H_
#define _OFPI_CONFIG_H_

#include "api/ofp_config.h"

/**Maximum number of CPUs.
 * Used to define the size of internal structures. */
#define OFP_MAX_NUM_CPU 64

/**Maximum number of nodes in the CLI parser tree.
 * Contains the number of nodes for regular commands (263 to date)
 * plus nodes for alias and custom commands
*/
#define OFP_CLI_NODE_MAX (263 + 100)

#endif
