/* Copyright (c) 2014, ENEA Software AB
 * Copyrighy (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:    BSD-3-Clause
 */
#include "ofp.h"

// Test for successful compile & link.
int main() {
	static ofp_initialize_param_t oig;

	ofp_initialize_param(&oig);

	if (ofp_initialize(&oig)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	OFP_INFO("Init successful.\n");
	return 0;
}
