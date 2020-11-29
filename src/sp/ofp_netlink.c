/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <errno.h>

#include "ofpi_netlink.h"
#include "ofpi_sp_shm.h"
#include "ofpi_log.h"
#include "ofpi_init.h"
#include "ofpi_sp_shm.h"

#define NETNS_RUN_DIR "/var/run/netns"

#define RETRY_VRF_MAX 100
#define RETRY_VRF_TIME 10000

#define BUFFER_SIZE 4096

static int open_allvrf_nl_sockets(void);
static int netlink_msg_recv(int fd, int vrf);
static int open_nl_socket(int vrf);

static int add_vrf(int vrf, int *idx);
static int wait_vrf(int idx);
static int set_vrf_locked(int idx);

/* Variable that remain with netlink thread (no shm)*/
static char buffer[BUFFER_SIZE];

/* Netlink thread */
int start_netlink_nl_server(void *arg)
{
	int i, r;
	struct timeval timeout;
	struct ofp_global_config_mem *ofp_global_cfg = NULL;
	int last_ns_sock_cnt = 0;
	fd_set read_fd;
	ofp_netlink_sock_t *s = NULL;

	(void)arg;

	/* Lookup shared memories */
	if (ofp_init_local()) {
		OFP_ERR("Error: OFP local init failed.\n");
		return -1;
	}

	ofp_global_cfg = ofp_get_global_config();
	if (!ofp_global_cfg) {
		OFP_ERR("Error: Failed to retrieve global configuration.");
		ofp_term_local();
		return -1;
	}

	FD_ZERO(&read_fd);

	if (add_vrf(0, NULL) != 0)
		return -1;

	if (open_allvrf_nl_sockets() != 0)
		return -1;

	while (ofp_global_cfg->is_running) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		r = select(FD_SETSIZE, &read_fd, NULL, NULL, &timeout);
		if (r < 0)
			continue;

		odp_rwlock_write_lock(&V_sp_nl_rwlock);
		for (i = 0; i < last_ns_sock_cnt; i++) {
			s = &V_sp_nl_sockets[i];
			if (s->fd > 0) {
				if (FD_ISSET(s->fd, &read_fd))
					netlink_msg_recv(s->fd, s->vrf);
				else
					FD_SET(s->fd, &read_fd);
			}
		}

		if (last_ns_sock_cnt != V_sp_nl_sock_cnt) {
			/* new vrf added -> create sockets */
			for (i = last_ns_sock_cnt; i < V_sp_nl_sock_cnt; i++) {

				if (set_vrf_locked(i))
					continue;

				FD_SET(V_sp_nl_sockets[i].fd, &read_fd);
			}

			last_ns_sock_cnt = V_sp_nl_sock_cnt;
		}
		odp_rwlock_write_unlock(&V_sp_nl_rwlock);
	}

	odp_rwlock_write_lock(&V_sp_nl_rwlock);
	for (i = 0; i < V_sp_nl_sock_cnt; i++) {
		if (V_sp_nl_sockets[i].fd > 0) {
			close(V_sp_nl_sockets[i].fd);
			V_sp_nl_sockets[i].fd = -1;
		}
	}
	V_sp_nl_sock_cnt = 0;
	odp_rwlock_write_unlock(&V_sp_nl_rwlock);

	OFP_DBG("Netlink server exiting");
	ofp_term_local();
	return 0;
}

static int open_allvrf_nl_sockets(void)
{
	DIR *dir;
	struct dirent *entry;
	int rc = 0;
	int vrf;

	dir = opendir(NETNS_RUN_DIR);
	if (!dir)	/* folder may not exist: OK*/
		return 0;

	while ((entry = readdir(dir)) != NULL &&
	       V_sp_nl_sock_cnt < NUM_NS_SOCKETS) {
		if (strncmp(entry->d_name, "vrf", 3))
			continue;

		vrf = atoi(entry->d_name + 3);
		rc = add_vrf(vrf, NULL);
		if (rc != 0)
			break;
	}

	closedir(dir);
	if (rc != 0)
		return -1;

	return 0;
}

static int add_vrf(int vrf, int *idx)
{
	odp_rwlock_write_lock(&V_sp_nl_rwlock);
	if (V_sp_nl_sock_cnt >= NUM_NS_SOCKETS) {
		odp_rwlock_write_unlock(&V_sp_nl_rwlock);
		return -1;
	}

	V_sp_nl_sockets[V_sp_nl_sock_cnt].vrf = vrf;
	V_sp_nl_sockets[V_sp_nl_sock_cnt].fd = -1;
	if (idx)
		*idx = V_sp_nl_sock_cnt;
	V_sp_nl_sock_cnt++;
	odp_rwlock_write_unlock(&V_sp_nl_rwlock);

	return 0;
}

static int wait_vrf(int idx)
{
	int retry = 0;
	int done = 0;

	do {
		if (retry)
			usleep(RETRY_VRF_TIME);

		odp_rwlock_write_lock(&V_sp_nl_rwlock);

		if (V_sp_nl_sockets[idx].fd != -1)
			done = 1;
		odp_rwlock_write_unlock(&V_sp_nl_rwlock);

	} while (++retry < RETRY_VRF_MAX && !done);

	if (!done)
		return -1;

	return 0;
}

static int set_vrf_locked(int idx)
{
	int vrf;
	int fd;

	if (idx >= NUM_NS_SOCKETS)
		return -1;

	vrf = V_sp_nl_sockets[idx].vrf;

	fd = open_nl_socket(vrf);
	if (fd < 0)
		return -1;

	V_sp_nl_sockets[idx].fd = fd;

	return 0;
}

int ofp_create_ns_socket(int vrf)
{
	int idx = -1;

	if (add_vrf(vrf, &idx) != 0)
		return -1;

	return wait_vrf(idx);
}

extern int setns (int __fd, int __nstype) __THROW;

static int open_nl_socket(int vrf)
{
	int fd = -1;
	char net_path[PATH_MAX];
	int netns;
	struct sockaddr_nl la;

	if (vrf) {
		snprintf(net_path, sizeof(net_path), "%s/vrf%d", NETNS_RUN_DIR, vrf);
		netns = open(net_path, O_RDONLY | O_CLOEXEC);

		if (netns < 0) {
			OFP_ERR("NS: Cannot open network namespace vrf%d: %s",
				vrf, strerror(errno));
			return -1;
		}

		if (setns(netns, CLONE_NEWNET) < 0) {
			OFP_ERR("NS: setting the network namespace vrf%d failed: %s",
				vrf, strerror(errno));
			close(netns);
			return -1;
		}
		close(netns);
	}

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		OFP_ERR("NS: Socket open failed");
		return -1;
	}

	bzero(&la, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_pid = getpid() | (vrf << 16);
	la.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_NOTIFY |
#ifdef INET6
		RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR |
#endif /* INET6 */
		RTMGRP_LINK;

	if (bind(fd, (struct sockaddr *) &la, sizeof(la)) < 0) {
		OFP_ERR("NS: Socket bind failed");
		close(fd);
		return -1;
	}

	return fd;
}

static int netlink_msg_recv(int fd, int vrf)
{
	int rtn;
	struct iovec iov;
	struct sockaddr_nl sa;
	struct msghdr msg;

	bzero(buffer, sizeof(buffer));
	bzero(&msg, sizeof(msg));
	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rtn = recvmsg(fd, &msg, 0);
	if (rtn > 0)
		netlink_msg_process(rtn, buffer, vrf);

	return rtn;
}

