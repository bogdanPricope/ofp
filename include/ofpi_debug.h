/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 * Copyright (c) 2014, Nokia
 * Copyright (c) 2014, Enea Software AB
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ofp debug
 */

#ifndef _OFPI_DEBUG_H_
#define _OFPI_DEBUG_H_

#include <odp_api.h>
#include <stdio.h>
#include <stdlib.h>
#include "api/ofp_debug.h"
#include "ofpi_vnet.h"
#include "ofpi_config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ofp_debug_mem {
	VNET_DEFINE(int, flags);
	VNET_DEFINE(odp_rwlock_t, lock_rw);

	/* print packets*/
	VNET_DEFINE(int, print_first);
	char print_file_name[OFP_FILE_NAME_SIZE_MAX];

	/* capture packets*/
	VNET_DEFINE(int, pcap_ports);
	VNET_DEFINE(FILE *, pcap_fd);
	VNET_DEFINE(int, pcap_first);
	VNET_DEFINE(int, pcap_is_fifo);
	char pcap_file_name[OFP_FILE_NAME_SIZE_MAX];
};

extern __thread struct ofp_debug_mem *shm_debug;

#define OFP_DEBUG_PCAP_KNI       0x40
#define OFP_DEBUG_PCAP_TX        0x80

#define DEFAULT_DEBUG_TXT_FILE_NAME "packets.txt"
#define DEFAULT_DEBUG_PCAP_FILE_NAME "/root/packets.pcap"

void ofp_save_packet_to_pcap_file(uint32_t flag, odp_packet_t pkt, int port);
void ofp_print_packet_buffer(const char *comment, uint8_t *p);

/*
 * Debug LOG interface
 */
struct ofp_flag_descript_s {
	uint32_t flag;
	const char *flag_descript;
};

enum ofp_log_packet {
	OFP_DEBUG_PKT_RECV_NIC = 0,
	OFP_DEBUG_PKT_SEND_NIC,
	OFP_DEBUG_PKT_RECV_KNI,
	OFP_DEBUG_PKT_SEND_KNI
};

extern struct ofp_flag_descript_s ofp_flag_descript[];

#define OFP_DEBUG_PACKET(_type_, pkt, port) do {\
	if (V_debug_flags & ofp_flag_descript[_type_].flag) { \
		ofp_print_packet( \
			ofp_flag_descript[_type_].flag_descript, \
				pkt); \
		if (V_debug_flags & OFP_DEBUG_CAPTURE) { \
			ofp_save_packet_to_pcap_file( \
				ofp_flag_descript[_type_].flag, \
					pkt, port); \
		} \
	} \
} while (0)

#define	V_debug_flags			VNET(shm_debug->flags)
#define	V_debug_lock_rw			VNET(shm_debug->lock_rw)
#define	V_debug_print_first		VNET(shm_debug->print_first)
#define	V_debug_print_file_name	VNET(shm_debug->print_file_name)
#define	V_debug_pcap_ports		VNET(shm_debug->pcap_ports)
#define	V_debug_pcap_fd			VNET(shm_debug->pcap_fd)
#define	V_debug_pcap_first		VNET(shm_debug->pcap_first)
#define	V_debug_pcap_is_fifo	VNET(shm_debug->pcap_is_fifo)
#define	V_debug_pcap_file_name	VNET(shm_debug->pcap_file_name)

int ofp_debug_lookup_shared_memory(void);
void ofp_debug_init_prepare(void);
int ofp_debug_init_global(void);
int ofp_debug_term_global(void);

#ifdef __cplusplus
}
#endif

#endif
