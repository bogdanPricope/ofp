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

int ofp_start_webserver_thread(ofp_thread_t *webserver_pthread, int core_id,
			       webserver_arg_t *arg);

#endif
