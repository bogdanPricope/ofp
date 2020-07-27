#ifndef _HTTPD_H_
#define _HTTPD_H_

#include <odp_api.h>

#define DEFAULT_BIND_PORT 2048
#define DEFAULT_ROOT_DIRECTORY "/var/www"

typedef struct {
	char *root_dir;
	uint16_t lport;
	odp_bool_t use_epoll;
} webserver_arg_t;

void ofp_start_webserver_thread(odp_instance_t instance, int core_id,
				odph_odpthread_t *webserver_pthread,
				webserver_arg_t *arg);

#endif
