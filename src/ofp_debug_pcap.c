/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ofpi_debug.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define IS_KNI(flag) \
	(flag == OFP_DEBUG_PRINT_RECV_KNI || \
	flag == OFP_DEBUG_PRINT_SEND_KNI)

#define IS_TX(flag) \
	(flag == OFP_DEBUG_PRINT_SEND_NIC || \
	flag == OFP_DEBUG_PRINT_SEND_KNI)

#define GET_PCAP_CONF_ADD_INFO(port, flag) \
	(port | \
	(IS_KNI(flag) ? OFP_DEBUG_PCAP_KNI : 0) | \
	(IS_TX(flag) ? OFP_DEBUG_PCAP_TX : 0))

/* PCAP */
void ofp_save_packet_to_pcap_file(uint32_t flag, odp_packet_t pkt, int port)
{
#define PUT16(x) do {					\
uint16_t val16 = x; fwrite(&val16, 2, 1, V_debug_pcap_fd);	\
} while (0)
#define PUT32(x) do {					\
uint32_t val32 = x; fwrite(&val32, 4, 1, V_debug_pcap_fd);	\
} while (0)
	struct timeval t;

	if ((V_debug_pcap_ports &
	     (1 << (port & OFP_DEBUG_PCAP_PORT_MASK))) == 0)
		return;

	odp_rwlock_write_lock(&V_debug_lock_rw);

	if (V_debug_pcap_first) {
		/*int n = ufp_get_num_ports(), i;*/
		struct stat st;

		V_debug_pcap_is_fifo = 0;
		if (stat(V_debug_pcap_file_name, &st) == 0)
			V_debug_pcap_is_fifo = (st.st_mode & S_IFIFO) != 0;

		V_debug_pcap_fd = fopen(V_debug_pcap_file_name, "w");
		if (!V_debug_pcap_fd)
			goto out;

		/* Global header */
		PUT32(0xa1b2c3d4); /* Byte order magic */
		PUT16(2); PUT16(4); /* Version major & minor */
		PUT32(0); /* Timezone */
		PUT32(0); /* Accuracy */
		PUT32(0xffff); /* Snaplen */
		PUT32(1); /* Ethernet */

		V_debug_pcap_first = 0;
	} else if (V_debug_pcap_fd == NULL) {
		V_debug_pcap_fd = fopen(V_debug_pcap_file_name, "a");
		if (!V_debug_pcap_fd)
			goto out;
	}

	/* Header */
	/* Timestamp */
	gettimeofday(&t, NULL);
	PUT32(t.tv_sec);
	PUT32(t.tv_usec);

	PUT32(odp_packet_len(pkt)); /* Saved packet len -- segment len */
	PUT32(odp_packet_len(pkt)); /* Captured packet len -- packet len */

	/* Data */
	if (V_debug_pcap_ports & OFP_DEBUG_PCAP_CONF_ADD_INFO) {
		fputc(GET_PCAP_CONF_ADD_INFO(port, flag), V_debug_pcap_fd);
		/* Packet data */
		fwrite((uint8_t *) odp_packet_data(pkt) + 1, 1,
		       odp_packet_len(pkt) - 1, V_debug_pcap_fd);
	} else {
		/* Packet data */
		fwrite(odp_packet_data(pkt), 1,
		       odp_packet_len(pkt), V_debug_pcap_fd);
	}

	if (!V_debug_pcap_is_fifo) {
		fclose(V_debug_pcap_fd);
		V_debug_pcap_fd = NULL;
	} else {
		fflush(V_debug_pcap_fd);
	}
out:
	odp_rwlock_write_unlock(&V_debug_lock_rw);
}

void ofp_set_capture_file(const char *filename)
{
	char *p;

	odp_rwlock_write_lock(&V_debug_lock_rw);

	strncpy(V_debug_pcap_file_name, filename,
		sizeof(V_debug_pcap_file_name) - 1);
	V_debug_pcap_file_name[sizeof(V_debug_pcap_file_name) - 1] = 0;

	/* There may be trailing spaces. Remove. */
	for (p = V_debug_pcap_file_name; *p; p++)
		if (*p == ' ') {
			*p = 0;
			break;
		}

	if (V_debug_pcap_fd) {
		fclose(V_debug_pcap_fd);
		V_debug_pcap_fd = NULL;
	}
	V_debug_pcap_first = 1;

	odp_rwlock_write_unlock(&V_debug_lock_rw);
}

void ofp_get_capture_file(char *filename, int max_size)
{
	odp_rwlock_write_lock(&V_debug_lock_rw);

	strncpy(filename, V_debug_pcap_file_name, max_size - 1);
	filename[max_size - 1] = 0;

	odp_rwlock_write_unlock(&V_debug_lock_rw);
}

