/* Copyright (c) 2020 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "string.h"
#include "ofpi_cli.h"
#include "ofpi_portconf.h"
#include "ofpi_util.h"

/** CLI Commands node
 */
struct cli_node {
	void (*func)(struct cli_conn *conn, const char *s);
	struct cli_node *nextword;
	struct cli_node *nextpossibility;
	const char *word;
	const char *help;
	char type;
};

/**< Special Parameter keywords in commands */
static const char NUMBER[]  = "<number>";
static const char IP4ADDR[] = "<a.b.c.d>";
static const char TOPNAME[] = "<top name>";
static const char STRING[]  = "<string>";
static const char DEV[] = "<dev>";
static const char IP4NET[] = "<a.b.c.d/n>";
static const char IP6ADDR[] = "<a:b:c:d:e:f:g:h>";
static const char IP6NET[] = "<a:b:c:d:e:f:g:h/n>";
static const char MAC[] = "<a:b:c:d:e:f>";

static struct cli_node end = {0, 0, 0, 0, 0, 0};
static struct cli_node *start = &end;

static struct cli_node *find_next_vertical(struct cli_node *s, char *word);
static int is_parameter(struct cli_node *s);
static void addchars(struct cli_conn *conn, const char *s);
static void print_q(struct cli_conn *conn, struct cli_node *s,
		    struct cli_node *ok);

static int int_ok(char *val)
{
	if ((val[0] == '0') &&
	    (val[1] == 'x' || val[1] == 'X')) {
		val += 2;
		while (*val) {
			if (!((*val >= '0' && *val <= '9') ||
			      (*val >= 'a' && *val <= 'f') ||
			      (*val >= 'A' && *val <= 'F')))
				return 0;
			val++;
		}
		return 1;
	}

	while (*val) {
		if (*val < '0' || *val > '9')
			return 0;
		val++;
	}
	return 1;
}

static int ip4addr_ok(char *val)
{
	char b[100], *p, *octet;
	int i;

	strcpy(b, val);

	p = b;
	for (i = 0; i < 4; i++) {
		octet = strsep(&p, ".");
		if (strlen(octet) > 3)
			return 0;
		if (strlen(octet) == 0)
			return 0;
		if (!int_ok(octet))
			return 0;
		if (i < 3 && p == NULL)
			return 0;
	}
	if (p)
		return 0;
	return 1;
}

static int topname_ok(char *val)
{
	if (!strncmp("parse", val, 3))
		return 1;
	if (!strncmp("resolve", val, 3))
		return 1;
	if (!strncmp("modify", val, 3))
		return 1;
	if (!strncmp("search", val, 3))
		return 1;
	if (!strncmp("learn", val, 3))
		return 1;
	return 0;
}

static int dev_ok(char *val)
{
	int port, vlan;

	port = ofp_name_to_port_vlan(val, &vlan);
	return (port >= 0 && port < ofp_get_num_ports());
}

static int ip4net_ok(char *val)
{
	char b[100], *p, *octet;
	int i;

	strcpy(b, val);

	p = b;
	for (i = 0; i < 5; i++) {
		if (i == 3)
			octet = strsep(&p, "/");
		else
			octet = strsep(&p, ".");
		if (strlen(octet) > 3)
			return 0;
		if (strlen(octet) == 0)
			return 0;
		if (!int_ok(octet))
			return 0;
		if (i < 4 && p == NULL)
			return 0;
	}
	return 1;
}

static int mac_ok(char *val)
{
	char *tk_start, *tk_end, *val_end, *pch;
	int tk_cnt;

	val_end = val + strlen(val);
	tk_start = val;
	tk_cnt = 0;

	while (tk_start != val_end) {
		tk_end = strchr(tk_start, ':');
		if (tk_end == NULL)
			tk_end = val_end;

		for (pch = tk_start; pch != tk_end; pch++)
			if (!((*pch >= '0' && *pch <= '9') ||
			      (*pch >= 'a' && *pch <= 'f') ||
			      (*pch >= 'A' && *pch <= 'F')))
				return 0;

		if ((tk_end - tk_start) != 2 &&
		    (tk_end - tk_start) != 1)
			return 0;

		tk_cnt++;

		tk_start = (tk_end == val_end) ? tk_end : tk_end + 1;
	}

	if (tk_cnt != OFP_ETHER_ADDR_LEN)
		return 0;

	return 1;
}

static int ip6addr_check_ok(char *val, int len)
{
	char *it, *last;
	char *last_colon;
	char *group_start;
	int colon_cnt;
	int group_cnt;
	odp_bool_t short_format;

	it = val;
	last = it + len;
	last_colon = NULL;
	colon_cnt = 0;
	group_cnt = 0;
	short_format = 0;

	while (it < last) {
		if ((*it) == ':') {
			if ((last_colon != NULL) && (it - 1 == last_colon))
				short_format = 1;
			last_colon = it;
			it++;
			colon_cnt++;
		} else if (((*it) >= '0' && (*it) <= '9') ||
			   ((*it) >= 'a' && (*it) <= 'f') ||
			   ((*it) >= 'A' && (*it) <= 'F')) {
			group_start = it;
			while ((it < last) &&
			       (((*it) >= '0' && (*it) <= '9') ||
				((*it) >= 'a' && (*it) <= 'f') ||
				((*it) >= 'A' && (*it) <= 'F'))) {
				it++;
			}

			if ((it - group_start > 4) ||
			    (it - group_start == 0))
				return 0;

			group_cnt++;
		} else {
			return 0;
		}
	}

	if (short_format) {
		if (colon_cnt > 7 || group_cnt > 8)
			return 0;
	} else {
		if (colon_cnt != 7 || group_cnt != 8)
			return 0;
	}

	return 1;
}

static int ip6addr_ok(char *val)
{
	return ip6addr_check_ok(val, strlen(val));
}

static int ip6net_ok(char *val)
{
	char *prefix_position;

	prefix_position = strstr(val, "/");
	if (prefix_position == NULL)
		return 0;

	if (ip6addr_check_ok(val, prefix_position - val) == 0)
		return 0;

	prefix_position++;

	if (strlen(prefix_position) > 3)
		return 0;
	if (strlen(prefix_position) == 0)
		return 0;
	if (!int_ok(prefix_position))
		return 0;

	return 1;
}

/** ofp_cli_parser_parse(): parse a Command line
 *
 * @param conn struct cli_conn*
 * @param extra int
 * @return void
 *
 */
void ofp_cli_parser_parse(struct cli_conn *conn, int extra)
{
	char **ap, *argv[50], **token, *msg, *lasttoken = 0;
	char b[sizeof(conn->inbuf)];
	struct cli_node *p = start, *horpos = &end, *lastok = 0;
	int paramlen;
	char paramlist[100];
	char *line = conn->inbuf;
	int linelen = strlen(line);

	if (linelen > 0 && line[linelen - 1] == ' ' && extra)
		extra = '?';
	else if (linelen == 0 && extra)
		extra = '?';
	else if (extra)
		extra = '\t';

	if (linelen == 0) {
		print_q(conn, p, 0);
		return;
	}

	strcpy(b, line);
	msg = b;

	for (ap = argv; (*ap = strsep(&msg, " \r\n")) != NULL;) {
		if (**ap != '\0') {
			if (++ap >= &argv[49])
				break;

			if (msg != NULL && *msg == '\"') {
				msg += 1;
				*ap = strsep(&msg, "\"\r\n");
				if (++ap >= &argv[49])
					break;
			}
		}
	}

	token = argv;

	horpos = p;
	paramlen = 0;
	paramlist[0] = 0;

	while (*token && p != &end) {
		struct cli_node *found;

		found = find_next_vertical(p, *token);
		if (found) {
			lastok = found;
			lasttoken = *token;
			p = found->nextword;
			horpos = p;
			if ((found->word == NUMBER && int_ok(*token)) ||
			    (found->word == IP4ADDR && ip4addr_ok(*token)) ||
			    (found->word == TOPNAME && topname_ok(*token)) ||
			    (found->word == DEV && dev_ok(*token)) ||
			    (found->word == IP4NET && ip4net_ok(*token)) ||
			    (found->word == STRING) ||
			    (found->word == IP6ADDR && ip6addr_ok(*token)) ||
			    (found->word == IP6NET && ip6net_ok(*token)) ||
			    (found->word == MAC && mac_ok(*token))) {
				paramlen += sprintf(paramlist + paramlen,
						"%s ", *token);
			}
			token++;
		} else {
			p = &end;
		}
	}

	if (extra && p == &end && *token == 0) {
		if (is_parameter(lastok) ||
		    strlen(lastok->word) == strlen(lasttoken)) {
			sendstr(conn, "\r\n <cr>");
			sendcrlf(conn);
			sendstr(conn, line);
		} else {
			addchars(conn, lastok->word + strlen(lasttoken));
			addchars(conn, " ");
			sendstr(conn, lastok->word + strlen(lasttoken));
			sendstr(conn, " ");
		}
		return;
	}

	if (lastok && lastok->func && extra == 0) {
		lastok->func(conn, paramlist);
		return;
	}

	if (extra == '?') {
		print_q(conn, horpos, lastok);
		sendstr(conn, line);
		return;
	}

	if (extra == '\t') {
		struct cli_node *found = 0;

		if (*token == NULL) {
			addchars(conn, lastok->word + strlen(lasttoken));
			addchars(conn, " ");
			sendstr(conn, lastok->word + strlen(lasttoken));
			sendstr(conn, " ");
			return;
		}

		found = find_next_vertical(horpos, *token);

		if (found) {
			addchars(conn, found->word + strlen(*token));
			addchars(conn, " ");
			sendstr(conn, found->word + strlen(*token));
			sendstr(conn, " ");
			return;
		}

		print_q(conn, horpos, lastok);
		sendstr(conn, line);
		return;
	}

	sendstr(conn, "syntax error\r\n");
	sendcrlf(conn);
}

static struct cli_node *find_next_vertical(struct cli_node *s, char *word)
{
	int foundcnt = 0;
	size_t len = strlen(word);
	struct cli_node *found = 0;

	while (s != &end) {
		if ((strncmp(s->word, word, len) == 0 &&
		     strlen(s->word) == len) ||
		    (s->word == NUMBER && int_ok(word)) ||
		    (s->word == IP4ADDR && ip4addr_ok(word)) ||
		    (s->word == TOPNAME && topname_ok(word)) ||
		    (s->word == DEV && dev_ok(word)) ||
		    (s->word == IP4NET && ip4net_ok(word)) ||
		    (s->word == STRING) ||
		    (s->word == IP6ADDR && ip6addr_ok(word)) ||
		    (s->word == IP6NET && ip6net_ok(word)) ||
		    (s->word == MAC && mac_ok(word))) {
			foundcnt++;
			if (foundcnt > 1)
				return 0;
			found = s;
		}
		s = s->nextpossibility;
	}
	return found;
}

static int is_parameter(struct cli_node *s)
{
	return ((s->word == NUMBER) ||
		(s->word == IP4ADDR) ||
		(s->word == TOPNAME) ||
		(s->word == DEV) ||
		(s->word == IP4NET) ||
		(s->word == STRING) ||
		(s->word == IP6ADDR) ||
		(s->word == IP6NET) ||
		(s->word == MAC));
}

static void addchars(struct cli_conn *conn, const char *s)
{
	strcat(conn->inbuf, s);
	conn->pos += strlen(s);
}

/** Check if the given word is a built-in "Parameter Keyword",
 *  and if so returns the Parameter string address, used as an identifier
 *  in the parser;
 *
 * @input str const char*: word to be checked
 * @return char*
 * @return NULL: the input word is not a Parameter
 * @return else the Parameter string address
 *
 */
static const char *get_param_string(const char *str)
{
#define IS_PARAM(str, param) (!strncmp(str, #param, strlen(#param)))

	if IS_PARAM(str, NUMBER)
		return NUMBER;
	if IS_PARAM(str, IP4ADDR)
		return IP4ADDR;
	if IS_PARAM(str, TOPNAME)
		return TOPNAME;
	if IS_PARAM(str, STRING)
		return STRING;
	if IS_PARAM(str, DEV)
		return DEV;
	if IS_PARAM(str, IP4NET)
		return IP4NET;
	if IS_PARAM(str, IP6NET)
		return IP6NET;
	if IS_PARAM(str, IP6ADDR)
		return IP6ADDR;
	if IS_PARAM(str, MAC)
		return MAC;

#undef IS_PARAM
	return NULL;
}

static void print_q(struct cli_conn *conn, struct cli_node *s,
		    struct cli_node *ok)
{
	char sendbuf[200];

	if (s == &end || (ok && ok->func)) {
		sendstr(conn, "\r\n <cr>");
		//return;
	}
	while (s != &end) {
		if (s->help)
			sprintf(sendbuf, "\r\n %-20s(%.158s)",
				s->word, s->help);
		else
			sprintf(sendbuf, "\r\n %.178s", s->word);
		sendstr(conn, sendbuf);
		s = s->nextpossibility;
	}
	sendcrlf(conn);
}

static struct cli_node *add_command_in_list(struct cli_node *root,
					    struct cli_command *cc)
{
	struct cli_node *s;
	struct cli_node *cn = root;
	struct cli_node *new_node;
	struct cli_node *n;
	int nextpossibility = 0;
	size_t len;
	char *nw;
	const char *param;
	const char *str;
	const char *w;

	w = cc->command;

	s = cn;
	while (cn != &end) {
		nw = strchr(w, ' ');

		str = get_param_string(w);
		if (!str) {
			str = w;
			if (nw)
				len = nw - w;
			else
				len = strlen(w);
		} else {
			len = strlen(str);
		}

		while (cn != &end && (strncmp(str, cn->word, len) ||
				      len != strlen(cn->word))) {
			s = cn;
			cn = cn->nextpossibility;
		}

		if (cn == &end) {
			nextpossibility = 1;
		} else {
			if (!nw)
				ofp_generate_coredump();
			w = nw + 1;
			s = cn;
			cn = cn->nextword;
		}
	}

	new_node = NULL;
	cn = NULL;
	while (w) {
		n = malloc(sizeof(*cn));
		n->help = NULL;
		n->func = NULL;
		n->nextword = &end;
		n->nextpossibility = &end;

		if (!new_node)
			new_node = n;

		if (cn)
			cn->nextword = n;

		cn = n;
		param = get_param_string(w);
		nw = strchr(w, ' ');
		if (!nw) {
			if (param)
				n->word = param;
			else
				n->word = strdup(w);
			break;
		}
		/* else */
		if (param) {
			n->word = param;
		} else {
			char *tmp = NULL;

			tmp = malloc(nw - w + 1);
			memcpy(tmp, w, nw - w);
			tmp[nw - w] = '\0';

			n->word = tmp;
		}
		w = nw + 1;
	}

	cn->func = cc->func;
	cn->help = cc->help;

	if (root == &end)
		root = new_node;
	else if (nextpossibility)
		s->nextpossibility = new_node;
	else
		s->nextword = new_node;

	return root;
}

void ofp_cli_parser_add_command(struct cli_command *cc)
{
	start = add_command_in_list(start, cc);
}

static void print_nodes(int fd, struct cli_node *node)
{
	struct cli_node *n;
	static int depth;
	int i;
	int ni = 0;
	struct cli_node *stack[100];

	if (node == &end)
		return;

	for (i = 0; i < depth; i++)
		ofp_sendf(fd, " ");
	for (n = node; n != &end; n = n->nextword) {
		depth += strlen(n->word) + 1;
		stack[ni++] = n;
		ofp_sendf(fd, "%s ", n->word);
	}

	ofp_sendf(fd, "\n");
	while (ni > 0) {
		n = stack[--ni];
		depth -= strlen(n->word) + 1;
		print_nodes(fd, n->nextpossibility);
	}
}

void ofp_cli_parser_print_nodes(int fd)
{
	print_nodes(fd, start);
}
