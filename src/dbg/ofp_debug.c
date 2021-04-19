/*-
 * Copyright (c) 2015 ENEA Software AB
 * Copyright (c) 2015 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <signal.h>
#include "ofpi_debug.h"
#include "ofpi_shared_mem.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_global_param_shm.h"

#define SHM_NAME_DEBUG "OfpDebugShMem"
__thread struct ofp_debug_mem *shm_debug;

static void sigpipe_handler(int s)
{
	(void)s;
	if (V_debug_pcap_fd) {
		fclose(V_debug_pcap_fd);
		V_debug_pcap_fd = NULL;
		V_debug_pcap_first = 1;
	}
}

static int ofp_debug_alloc_shared_memory(void)
{
	shm_debug = ofp_shared_memory_alloc(SHM_NAME_DEBUG, sizeof(*shm_debug));
	if (shm_debug == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_debug_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_DEBUG)) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}

	shm_debug = NULL;
	return rc;
}

int ofp_debug_lookup_shared_memory(void)
{
	shm_debug = ofp_shared_memory_lookup(SHM_NAME_DEBUG);
	if (shm_debug == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	return 0;
}

void ofp_debug_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_DEBUG, sizeof(*shm_debug));
}

static void string_copy(char *dest, size_t destsize,
			const char *src, size_t srcsize)
{
	size_t cpy_len = srcsize;

	if (cpy_len > destsize - 1)
		cpy_len = destsize - 1;

	odp_memcpy(dest, src, cpy_len);
	dest[cpy_len] = '\0';
}

int ofp_debug_init_global(void)
{
	HANDLE_ERROR(ofp_debug_alloc_shared_memory());
	memset(shm_debug, 0, sizeof(*shm_debug));

	odp_rwlock_init(&V_debug_lock_rw);
	V_debug_flags = V_global_param.debug.flags;

	if (!strlen(V_global_param.debug.print_filename))
		string_copy(V_debug_print_file_name,
			    sizeof(V_debug_print_file_name),
			    DEFAULT_DEBUG_TXT_FILE_NAME,
			    strlen(DEFAULT_DEBUG_TXT_FILE_NAME));
	else
		string_copy(V_debug_print_file_name,
			    sizeof(V_debug_print_file_name),
			    V_global_param.debug.print_filename,
			    strlen(V_global_param.debug.print_filename));

	V_debug_print_first = 1;

	V_debug_pcap_ports = V_global_param.debug.capture_ports;

	if ((V_debug_flags & OFP_DEBUG_CAPTURE) &&
	    (V_debug_pcap_ports == 0)) {
		/*enable capture on first port*/
		V_debug_pcap_ports = 0x1;
	}

	if (!strlen(V_global_param.debug.capture_filename))
		string_copy(V_debug_pcap_file_name,
			    sizeof(V_debug_pcap_file_name),
			    DEFAULT_DEBUG_PCAP_FILE_NAME,
			    strlen(DEFAULT_DEBUG_PCAP_FILE_NAME));
	else
		string_copy(V_debug_pcap_file_name,
			    sizeof(V_debug_pcap_file_name),
			    V_global_param.debug.capture_filename,
			    strlen(V_global_param.debug.capture_filename));

	V_debug_pcap_first = 1;
	V_debug_pcap_fd = NULL;

	if (signal(SIGPIPE, sigpipe_handler) == SIG_ERR) {
		OFP_ERR("Failed to set SIGPIPE handler.");
		return -1;
	}

	return 0;
}

int ofp_debug_term_global(void)
{
	int rc = 0;

	if (ofp_debug_lookup_shared_memory())
		return -1;

	if (signal(SIGPIPE, SIG_DFL) == SIG_ERR) {
		OFP_ERR("Failed to reset SIGPIPE handler.");
		rc = -1;
	}

	if (V_debug_pcap_fd) {
		fclose(V_debug_pcap_fd);
		V_debug_pcap_fd = NULL;
		V_debug_pcap_first = 1;
	}

	CHECK_ERROR(ofp_debug_free_shared_memory(), rc);

	return rc;
}

struct ofp_flag_descript_s ofp_flag_descript[] = {
	{OFP_DEBUG_PRINT_RECV_NIC, "ODP to FP"},
	{OFP_DEBUG_PRINT_SEND_NIC, "FP to ODP"},
	{OFP_DEBUG_PRINT_RECV_KNI, "FP to SP"},
	{OFP_DEBUG_PRINT_SEND_KNI, "SP to ODP"}
};

void ofp_set_debug_flags(int flags)
{
	V_debug_flags = flags;
}

int ofp_get_debug_flags(void)
{
	return V_debug_flags;
}

void ofp_set_debug_capture_ports(int ports)
{
	V_debug_pcap_ports = ports;
}

int ofp_get_debug_capture_ports(void)
{
	return V_debug_pcap_ports;
}
