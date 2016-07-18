/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "odp.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_ipsec.h"
#include "ofpi_ipsec_session.h"


int ofp_ipsec_create_session(struct ofp_ipsec_cache_auth_cipher *algs,
	struct ofp_ipsec_cache_processing *proc,
	enum ofp_ipsec_direction dir,
	odp_crypto_session_t *session)
{
	odp_crypto_session_params_t params;
	odp_crypto_ses_create_err_t status;
	struct ofp_ipsec_conf *conf;

	*session = ODP_CRYPTO_SESSION_INVALID;
	memset(&params, 0, sizeof (params));
	status = ODP_CRYPTO_SES_CREATE_ERR_NONE;

	conf = ofp_ipsec_config_get();
	if (!conf)
		return -1;

	if (dir == OFP_IPSEC_DIRECTION_IN)
		params.op = ODP_CRYPTO_OP_DECODE;
	else
		params.op = ODP_CRYPTO_OP_ENCODE;

	/* Processing settings*/
	params.pref_mode = proc->pref_mode;
	/* async compl. queue */
	if (params.pref_mode == ODP_CRYPTO_ASYNC) {
		int idx = 0;

		if (!conf->param.async_queue_cnt) {
			OFP_ERR("IPsec asynchronous completion queue not found.");
			return -1;
		}
		if (conf->param.async_queue_alloc == OFP_ASYNC_QUEUE_ALLOC_ROUNDROBIN) {
			odp_rwlock_write_lock(&conf->async_queue_rwlock);
			idx = conf->async_queue_idx++;
			odp_rwlock_write_unlock(&conf->async_queue_rwlock);
		} else
			idx = odp_cpu_id();

		idx %= conf->param.async_queue_cnt;
		params.compl_queue = conf->param.async_queues[idx];
	} else
		params.compl_queue = ODP_QUEUE_INVALID;

	/* Algs */
	params.auth_cipher_text = algs->auth_cipher;

	/* auth */
	params.auth_alg = algs->auth_alg_desc.odp_name;
	params.auth_key.length = algs->auth_key.length;
	params.auth_key.data = (uint8_t *)algs->auth_key.data;

	/* cipher */
	params.cipher_alg = algs->cipher_alg_desc.odp_name;
	params.cipher_key.length = algs->cipher_key.length;
	params.cipher_key.data = algs->cipher_key.data;
	params.iv.length = algs->cipher_iv.length;
	params.iv.data = algs->cipher_iv.data;
	if (!algs->cipher_iv.length && algs->cipher_alg_desc.iv_len) {
		/* Generate IV */
		algs->cipher_iv.length = algs->cipher_alg_desc.iv_len;
		params.iv.length = algs->cipher_alg_desc.iv_len;
		if (odp_random_data(params.iv.data,
			(int32_t)params.iv.length, 1) < 0) {
			OFP_ERR("Failed to generate random IV.");
			return -1;
		}
	}

	/* output buffer pool */
	params.output_pool = conf->param.output_pool;

       if (odp_crypto_session_create(&params, session, &status)) {
		OFP_ERR("Failed to create ODP IPsec session (%d).", status);
		return -1;
	}

	return 0;
}

int ofp_ipsec_destroy_session(odp_crypto_session_t session)
{
	if (session == ODP_CRYPTO_SESSION_INVALID)
		return 0;

	if (odp_crypto_session_destroy(session) < 0) {
		OFP_ERR("Failed to destroy ODP IPsec session.");
		return -1;
	}

	return 0;
}

