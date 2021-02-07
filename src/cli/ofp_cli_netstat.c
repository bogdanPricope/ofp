#include "ofpi_cli.h"
#include "ofpi_socketvar.h"
#include "ofpi_tcp_var.h"
#include "ofpi_udp_var.h"

/* "netstat" */
void f_netstat_all(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_tcp_netstat(pr);
	ofp_udp_netstat(pr);
}

/* "netstat -t" */
void f_netstat_tcp(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_tcp_netstat(pr);
}

/* "netstat -u" */
void f_netstat_udp(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_udp_netstat(pr);
}

/* "help netstat" */
void f_help_netstat(ofp_print_t *pr, const char *s)
{
	(void)s;
	ofp_print(pr,
		  "Show all open ports:\r\n"
		  "  netstat\r\n\r\n");

	ofp_print(pr,
		  "Show TCP open ports:\r\n"
		  "  netstat -t\r\n\r\n");

	ofp_print(pr,
		  "Show UDP open ports:\r\n"
		  "  netstat -u\r\n\r\n");

	ofp_print(pr,
		  "Show (this) help:\r\n"
		  "  netstat help\r\n\r\n");
}
