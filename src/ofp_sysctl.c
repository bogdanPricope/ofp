/*-
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015, Nokia Solutions and Networks
 * Copyright (c) 2015, ENEA Software AB
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Quite extensively rewritten by Poul-Henning Kamp of the FreeBSD
 * project, to make these variables more userfriendly.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_sysctl.c	8.4 (Berkeley) 4/14/94
 */

#include <stdlib.h>

#include <odp_api.h>
#include "ofpi.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_errno.h"
#include "ofpi_sysctl.h"

#define SHM_NAME_SYSCTL "OfpSysctlShMem"

#define	V_sysctllock	VNET(shm_sysctl->sysctllock)

#define	SYSCTL_XLOCK()		odp_spinlock_lock(&V_sysctllock)
#define	SYSCTL_XUNLOCK()	odp_spinlock_unlock(&V_sysctllock)
#define	SYSCTL_ASSERT_XLOCKED()	//sx_assert(&sysctllock, SA_XLOCKED)
#define	SYSCTL_INIT()		odp_spinlock_init(&V_sysctllock)
#define	SYSCTL_SLEEP(ch, wmesg, timo) do {} while (0)

static int
ofp_name2oid(const char *name, struct ofp_sysctl_oid **oidpp);

struct ofp_syctl_mem {
	odp_spinlock_t sysctllock;
};

__thread struct ofp_syctl_mem *shm_sysctl;

__thread struct ofp_sysctl_oid sysctl_root = {0};

__thread int ofp_oid_auto = 1;	/* 0 reserved for root node */

OFP_SYSCTL_PROC_ROOT_CHLD_DEF(vartype);
OFP_SYSCTL_NODE_ROOT_CHLD_DEF(net);


void ofp_sysctl_add_child(struct ofp_sysctl_oid *oidp,
			  struct ofp_sysctl_oid *parent)
{
	struct ofp_sysctl_oid *p;
	struct ofp_sysctl_oid *q;

	if (!oidp || !parent)
		return;

	if (!(parent->oid_kind & OFP_CTLTYPE_NODE))
		return;

	/*
	 * Insert the oid into the parent's list in order.
	 */
	q = NULL;
	OFP_SLIST_FOREACH(p, &(parent->oid_head), oid_link) {
		if (oidp->oid_number < p->oid_number)
			break;
		q = p;
	}
	if (q)
		OFP_SLIST_INSERT_AFTER(q, oidp, oid_link);
	else
		OFP_SLIST_INSERT_HEAD(&(parent->oid_head), oidp, oid_link);
}

static void
ofp_sysctl_debug_dump_node(int fd, struct ofp_sysctl_oid *node, int print_align)
{
	int k;
	struct ofp_sysctl_oid *oidp;

	SYSCTL_ASSERT_XLOCKED();

	if (!node)
		return;

	if (!(node->oid_kind & OFP_CTLTYPE_NODE)) {
		OFP_ERR("OID %s is not of type node.", node->oid_name);
		return;
	}

	OFP_SLIST_FOREACH(oidp, &(node->oid_head), oid_link) {
		for (k = 0; k < print_align; k++)
			ofp_sendf(fd, " ");

		ofp_sendf(fd, "%d %s ", oidp->oid_number, oidp->oid_name);

		ofp_sendf(fd, "%c%c",
			  oidp->oid_kind & OFP_CTLFLAG_RD ? 'R' : ' ',
			  oidp->oid_kind & OFP_CTLFLAG_WR ? 'W' : ' ');

		switch (oidp->oid_kind & OFP_CTLTYPE) {
		case OFP_CTLTYPE_NODE:
			ofp_sendf(fd, " Node  (%s)\r\n", oidp->oid_descr);
			if (!oidp->oid_handler)
				ofp_sysctl_debug_dump_node(fd, oidp,
							   print_align + 2);
			break;
		case OFP_CTLTYPE_INT:
			ofp_sendf(fd, " int  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_UINT:
			ofp_sendf(fd, " u_int  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_LONG:
			ofp_sendf(fd, " long  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_ULONG:
			ofp_sendf(fd, " u_long  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_STRING:
			ofp_sendf(fd, " string  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_U64:
			ofp_sendf(fd, " uint64_t  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_S64:
			ofp_sendf(fd, " int64_t  (%s)\r\n", oidp->oid_descr);
			break;
		case OFP_CTLTYPE_OPAQUE:
			ofp_sendf(fd, " opaque/struct  (%s)\r\n",
				  oidp->oid_descr);
			break;
		case OFP_CTLTYPE_PROC:
			ofp_sendf(fd, " Procedure  (%s)\r\n", oidp->oid_descr);
			break;
		}
	}
}

void
ofp_sysctl_write_tree(int fd)
{
	ofp_sendf(fd, "ID Name Access Type Description\r\n");

	SYSCTL_XLOCK();
	ofp_sysctl_debug_dump_node(fd, &sysctl_root, 0);
	SYSCTL_XUNLOCK();
}

/*
 * Default "handler" functions.
 */

/*
 * Handle an int, signed or unsigned.
 * Two cases:
 *     a variable:  point arg1 at it.
 *     a constant:  pass it in arg2.
 */

int
sysctl_handle_int(OFP_SYSCTL_HANDLER_ARGS)
{
	int tmpout, error = 0;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (arg1)
		tmpout = *(int *)arg1;
	else
		tmpout = arg2;
	error = SYSCTL_OUT(req, &tmpout, sizeof(int));

	if (error || !req->newptr)
		return (error);

	if (!arg1)
		error = OFP_EPERM;
	else
		error = SYSCTL_IN(req, arg1, sizeof(int));
	return error;
}

/*
 * Based on on sysctl_handle_int() convert milliseconds into ticks.
 * Note: this is used by TCP.
 */

int
sysctl_msec_to_ticks(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, s, tt;
	(void)arg2;

	tt = *(int *)arg1;
	s = (int)((int64_t)tt * 1000 / hz);

	error = sysctl_handle_int(oidp, &s, 0, req);
	if (error || !req->newptr)
		return error;

	tt = (int)((int64_t)s * hz / 1000);
	if (tt < 1)
		return OFP_EINVAL;

	*(int *)arg1 = tt;
	return 0;
}

/*
 * Handle a long, signed or unsigned.  arg1 points to it.
 */

int
sysctl_handle_long(OFP_SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	long tmplong;
#ifdef SCTL_MASK32
	int tmpint;
#endif
	(void)arg2;
	(void)oidp;
	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (!arg1)
		return OFP_EINVAL;
	tmplong = *(long *)arg1;
#ifdef SCTL_MASK32
	if (req->flags & SCTL_MASK32) {
		tmpint = tmplong;
		error = SYSCTL_OUT(req, &tmpint, sizeof(int));
	} else
#endif
		error = SYSCTL_OUT(req, &tmplong, sizeof(long));

	if (error || !req->newptr)
		return error;

#ifdef SCTL_MASK32
	if (req->flags & SCTL_MASK32) {
		error = SYSCTL_IN(req, &tmpint, sizeof(int));
		*(long *)arg1 = (long)tmpint;
	} else
#endif
		error = SYSCTL_IN(req, arg1, sizeof(long));
	return error;
}

/*
 * Handle a 64 bit int, signed or unsigned.  arg1 points to it.
 */
int
sysctl_handle_64(OFP_SYSCTL_HANDLER_ARGS)
{
	int error = 0;
	uint64_t tmpout;
	(void)oidp;
	(void)arg2;

	/*
	 * Attempt to get a coherent snapshot by making a copy of the data.
	 */
	if (!arg1)
		return OFP_EINVAL;
	tmpout = *(uint64_t *)arg1;
	error = SYSCTL_OUT(req, &tmpout, sizeof(uint64_t));

	if (error || !req->newptr)
		return error;

	error = SYSCTL_IN(req, arg1, sizeof(uint64_t));
	return error;
}

/*
 * Handle our generic '\0' terminated 'C' string.
 * Two cases:
 * 	a variable string:  point arg1 at it, arg2 is max length.
 * 	a constant string:  point arg1 at it, arg2 is zero.
 */

int
sysctl_handle_string(OFP_SYSCTL_HANDLER_ARGS)
{
	int error=0;
	char *tmparg;
	size_t outlen;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot by copying to a
	 * temporary kernel buffer.
	 */
	outlen = strlen((char *)arg1)+1;
	tmparg = malloc(outlen);
	memcpy(tmparg, (char *)arg1, outlen);
	tmparg[outlen-1] = 0;

	error = SYSCTL_OUT(req, tmparg, outlen);
	free(tmparg);

	if (error || !req->newptr)
		return error;

	if ((int)(req->newlen - req->newidx) >= arg2) {
		error = OFP_EINVAL;
	} else {
		arg2 = (req->newlen - req->newidx);
		error = SYSCTL_IN(req, arg1, arg2);
		((char *)arg1)[arg2] = '\0';
	}

	return error;
}

/*
 * Handle any kind of opaque data.
 * arg1 points to it, arg2 is the size.
 */

int
sysctl_handle_opaque(OFP_SYSCTL_HANDLER_ARGS)
{
	int error, tries;
	int generation;
	struct ofp_sysctl_req req2;
	(void)oidp;

	/*
	 * Attempt to get a coherent snapshot, by using the thread
	 * pre-emption counter updated from within mi_switch() to
	 * determine if we were pre-empted during a bcopy() or
	 * copyout(). Make 3 attempts at doing this before giving up.
	 * If we encounter an error, stop immediately.
	 */
	tries = 0;
	req2 = *req;
retry:
	generation = odp_cpu_id();
	error = SYSCTL_OUT(req, arg1, arg2);
	if (error)
		return error;
	tries++;
	if (generation != odp_cpu_id() && tries < 3) {
		*req = req2;
		goto retry;
	}

	error = SYSCTL_IN(req, arg1, arg2);

	return error;
}

static int
sysctl_handle_vartype(OFP_SYSCTL_HANDLER_ARGS)
{
	struct ofp_sysctl_oid *oid = NULL;
	int error;

	(void)oidp;
	(void)arg1;
	(void)arg2;

	if (!req->oldptr || !req->newptr)
		return OFP_EINVAL;

	error = ofp_name2oid(req->newptr, &oid);
	if (error)
		return error;

	error = SYSCTL_OUT(req, &oid->oid_kind, sizeof(oid->oid_kind));

	return error;
}

static int
sysctl_old_data(struct ofp_sysctl_req *req, const void *p, size_t l)
{
	if (!req->oldptr)
		return 0;

	if (req->oldlen - req->oldidx < l)
		return OFP_ENOMEM;

	odp_memcpy((char *)req->oldptr + req->oldidx, p, l);
	req->oldidx += l;

	return 0;
}

static int
sysctl_new_data(struct ofp_sysctl_req *req, void *p, size_t l)
{
	if (!req->newptr)
		return 0;

	if (req->newlen - req->newidx < l)
		return OFP_EINVAL;

	odp_memcpy(p, (const char *)req->newptr + req->newidx, l);
	req->newidx += l;

	return 0;
}

static struct ofp_sysctl_oid *
ofp_sysctl_find_child(const char *child_name, size_t child_name_len,
		      struct ofp_sysctl_oid *parent)
{
	struct ofp_sysctl_oid *oidp;

	SYSCTL_ASSERT_XLOCKED();

	if (!(parent->oid_kind & OFP_CTLTYPE_NODE))
		return NULL;

	OFP_SLIST_FOREACH(oidp, &(parent->oid_head), oid_link) {
		if (strlen(oidp->oid_name) == child_name_len &&
		    strncmp(oidp->oid_name, child_name, child_name_len) == 0)
			return oidp;
	}
	return NULL;
}

static int
ofp_name2oid(const char *name, struct ofp_sysctl_oid **oidpp)
{
	const char *p, *e, *last;
	struct ofp_sysctl_oid *oidp;

	if (!name || !oidpp)
		return OFP_ENOENT;

	*oidpp = NULL;

	/*remove spaces in front */
	p = name;
	while (*p == ' ')
		p++;

	/*remove spaces at the end */
	last = name + strlen(name) - 1;
	while (last != name && (*last == ' ' || *last == '.'))
		last--;

	if (p == last)
		return OFP_ENOENT;

	last++; /* first char after last valid (likely '\0') */
	oidp = &sysctl_root;

	do {
		e = p;
		while (e != last && *e != '.')
			e++;

		oidp = ofp_sysctl_find_child(p, e - p, oidp);
		if (oidp == NULL)
			return OFP_ENOENT;

		p = e;
		if (p < last && *p == '.')
			p++;
	} while (p < last);

	*oidpp = oidp;

	return 0;
}


static int
sysctl_request(const char *name, struct ofp_sysctl_req *req)
{
	int ret = 0;
	int error = 0;
	struct ofp_sysctl_oid *oidp = NULL;

	ret = ofp_name2oid(name, &oidp);
	if (ret) {
		OFP_ERR("ofp_name2oid() failed: %d", ret);
		return ret;
	}
	if (!oidp)
		return OFP_ENOENT;

	if ((oidp->oid_kind & OFP_CTLTYPE) == OFP_CTLTYPE_NODE) {
		/*
		 * You can't call a sysctl when it's a node, but has
		 * no handler.  Inform the user that it's a node.
		 * The indx may or may not be the same as namelen.
		 */
		if (oidp->oid_handler == NULL)
			return OFP_EISDIR;
	}

	/* Is this sysctl writable? */
	if (req->newptr && !(oidp->oid_kind & OFP_CTLFLAG_WR))
		return OFP_EPERM;

	/* Is this sysctl readable? */
	if (req->oldptr && !(oidp->oid_kind & OFP_CTLFLAG_RD))
		return OFP_EPERM;

	if (!oidp->oid_handler)
		return OFP_EINVAL;

	error = oidp->oid_handler(oidp, oidp->oid_arg1, oidp->oid_arg2, req);

	return error;
}

int
ofp_sysctl(const char *name, void *old, size_t *oldlenp,
	   const void *new, size_t newlen, size_t *retval)
{
	int error = 0;
	struct ofp_sysctl_req req = {0};

	if (oldlenp)
		req.oldlen = *oldlenp;

	req.validlen = req.oldlen;

	if (old)
		req.oldptr = old;

	if (new != NULL) {
		req.newlen = newlen;
		req.newptr = new;
	}

	req.oldfunc = sysctl_old_data;
	req.newfunc = sysctl_new_data;

	SYSCTL_XLOCK();
	error = sysctl_request(name, &req);
	SYSCTL_XUNLOCK();

	if (error && error != OFP_ENOMEM)
		return error;

	if (retval) {
		if (req.oldptr && req.oldidx > req.validlen)
			*retval = req.validlen;
		else
			*retval = req.oldidx;
	}

	return error;
}

static int ofp_sysctl_alloc_shared_memory(void)
{
	shm_sysctl = ofp_shared_memory_alloc(SHM_NAME_SYSCTL,
					     sizeof(struct ofp_syctl_mem));
	if (shm_sysctl == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_sysctl_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_SYSCTL) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_sysctl = NULL;

	return rc;
}

static int ofp_sysctl_lookup_shared_memory(void)
{
	shm_sysctl = ofp_shared_memory_lookup(SHM_NAME_SYSCTL);
	if (shm_sysctl == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}

	return 0;
}

void ofp_sysctl_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_SYSCTL,
				   sizeof(struct ofp_syctl_mem));
}

int ofp_sysctl_init_global(void)
{
	HANDLE_ERROR(ofp_sysctl_alloc_shared_memory());
	memset(shm_sysctl, 0, sizeof(struct ofp_syctl_mem));

	SYSCTL_INIT();

	return 0;
}

int ofp_sysctl_init_local(void)
{
	HANDLE_ERROR(ofp_sysctl_lookup_shared_memory());

	sysctl_root = (struct ofp_sysctl_oid){NULL,
					      OFP_SLIST_HEAD_INITIALIZER(NULL),
					      {NULL}, 0, OFP_CTLTYPE_NODE,
					      NULL, 0, "sysctl", NULL, NULL, 0,
					      'N', __DESCR("sysctl_root")};

	OFP_SYSCTL_PROC_ROOT_CHLD_SET(OFP_OID_AUTO, vartype, OFP_CTLFLAG_RW,
				      NULL, 0, sysctl_handle_vartype, "IU",
				      "Get variable type");
	OFP_SYSCTL_NODE_ROOT_CHLD_SET(OFP_OID_AUTO, net, OFP_CTLFLAG_RW, 0,
				      "Network controls");

	return 0;
}

int ofp_sysctl_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_sysctl_free_shared_memory(), rc);

	return rc;
}
