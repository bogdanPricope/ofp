/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFP_SOCKET_SIGEVENT_H__
#define __OFP_SOCKET_SIGEVENT_H__

#include <odp_api.h>
#include "ofp_socket.h"

/* Sigevent event type*/
#define OFP_EVENT_INVALID	0
#define OFP_EVENT_ACCEPT	1
#define OFP_EVENT_RECV	2
#define OFP_EVENT_SEND	3

union ofp_sigval {          /* Data passed with notification */
	int     sival_int;         /* Integer value */
	void   *sival_ptr;         /* Pointer value */
};

/**
 * struct ofp_sock_sigval is the argument of notification function
 *
 * sigev_value: "ofp_sigevent.sigev_value" argument configured with
 * ofp_socket_sigevent().
 *
 * ofp_sock_sigval.event:  indicates the type of event received. Valid values
 * are OFP_EVENT_ACCEPT, OFP_EVENT_RECV or OFP_EVENT_SEND.
 *
 * sockfd: socket on which event occurred
 *
 * sockfd2: additional socket e.g. (accepted socket on OFP_EVENT_ACCEPT event)
 *
 * pkt: the packet triggering the event (OFP_EVENT_RECV only)
 *
 * Note: On OFP_EVENT_RECV events, the packet is considered
 * processed 'outside the stack' if the 'pkt' is set to ODP_PACKET_INVALID
 * at the return of notification function. One may inspect, process the
 * packet in different ways or even delete it in the notification function.
 */

struct ofp_sock_sigval {
	union ofp_sigval    sigev_value; /* Data passed with notification
					from event configuration api
					(struct ofp_sigevent)*/
	int                 event;	/* Sigevent event type */
	int                 sockfd;	/* socket on which event occurred*/
	int                 sockfd2;	/* additional socket e.g. (accepted
					socket on OFP_EVENT_ACCEPT event */

	odp_packet_t        pkt;	/* The packet triggering the event */
};

/* Sigevent notification method */
#define OFP_SIGEV_NONE 0
#define OFP_SIGEV_HOOK 1
#define OFP_SIGEV_SIGNAL 2
#define OFP_SIGEV_THREAD 3

struct ofp_sigevent {
	int                 sigev_notify; /* Notification method */
	int                 sigev_signo;  /* Notification signal */
	union ofp_sigval    sigev_value;  /* Data passed with notification */
	void                (*sigev_notify_func)(union ofp_sigval *sigev_value);
		/* Function used for notification */
	void                *sigev_notify_attr;
		/* Attributes for notification thread
		(SIGEV_THREAD) */
	ofp_pid_t           sigev_notify_thread_id;
		/* ID of thread to signal (SIGEV_THREAD_ID) */
};

/**
 * Configures the event notification on a socket.
 *
 * Notification mechanism is configured through a "struct ofp_sigevent"
 * argument:
 * ofp_sigevent.sigev_notify specifies the type of notification that is
 * requested. In current version, only OFP_SIGEV_HOOK type is supported.
 *
 * ofp_sigevent.sigev_notify_func is the callback function.
 * The argument of this function has a "union ofp_sigval *" type but
 * the actual type depends on ofp_sigevent.sigev_notify field.
 * In current version, a "struct ofp_sock_sigval *" is returned.
 *
 * In the future, the function's argument may differ depending on
 * "ofp_sock_sigval.event" type (base type + derived type model).
 *
 * ofp_sigevent.sigev_value is a field that will be passed to
 * the callback function as (part of the) function's argument
 * (e.g. ofp_sock_sigval.sigev_value).
 *
 * The rest of "struct ofp_sigevent" fields are not used.
 *
 * Note: On TCP, the event notification configuration will be inherited from
 * listening socket to accepted socket.
 *
 * @param sd            Socket descriptor
 * @param ev            Event notification parameters
 *
 * @return 0 on success
 * @retval !0 on error
 */
int	ofp_socket_sigevent(int sd, struct ofp_sigevent *ev);

#endif /* __OFP_SOCKET_SIGEVENT_H__ */

