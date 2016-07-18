/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_ipsec_alg.h"

struct auth_entry alg_db_auth[] = {
	{		/* OFP_AUTH_ALG_NULL */
		ODP_AUTH_ALG_NULL,
		0,
		0
	},
	{		/* OFP_AUTH_ALG_MD5_96 */
		ODP_AUTH_ALG_MD5_96,
		16,
		12
	},
	{		/* OFP_AUTH_ALG_SHA256_128 */
		ODP_AUTH_ALG_SHA256_128,
		0,
		0
	},
	{		/* OFP_AUTH_ALG_AES128_GMAC */
		ODP_AUTH_ALG_AES128_GCM,
		0,
		0
	}
};

struct cipher_entry alg_db_cipher[] = {
	{		/* OFP_CIPHER_ALG_NULL */
		ODP_CIPHER_ALG_NULL,
		0,
		0,
		0
	},
	{		/* OFP_CIPHER_ALG_DES */
		ODP_CIPHER_ALG_DES,
		0,
		0,
		0
	},
	{		/* OFP_CIPHER_ALG_3DES_CBC */
		ODP_CIPHER_ALG_3DES_CBC,
		24,
		8,
		8
	},
	{		/* OFP_CIPHER_ALG_AES128_CBC */
		ODP_CIPHER_ALG_AES128_CBC,
		0,
		0,
		0
	},
	{		/* OFP_CIPHER_ALG_AES128_GCM */
		ODP_CIPHER_ALG_AES128_GCM,
		0,
		0,
		0
	}
};

int ofp_get_auth_alg(ofp_auth_alg_t alg, struct auth_entry *entry)
{
	if (alg < 0 || alg >= OFP_AUTH_ALG_MAX)
		return -1;

	memcpy(entry, &alg_db_auth[alg], sizeof (struct auth_entry));

	return 0;
}

int ofp_get_cipher_alg(ofp_cipher_alg_t alg, struct cipher_entry *entry)
{
	if (alg < 0 || alg >= OFP_CIPHER_ALG_MAX)
		return -1;

	memcpy(entry, &alg_db_cipher[alg], sizeof (struct cipher_entry));
	return 0;
}
