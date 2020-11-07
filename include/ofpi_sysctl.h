/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2015, Nokia Solutions and Networks
 * Copyright (c) 2015, ENEA Software AB
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
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
 */

#ifndef _SYS_SYSCTL_H_
#define	_SYS_SYSCTL_H_

#include "ofpi_queue.h"
#include "api/ofp_sysctl.h"

/*
 * USE THIS instead of a hardwired number from the categories below
 * to get dynamically assigned sysctl entries. This is the way nearly
 * all new sysctl variables should be implemented.
 * e.g. OFP_SYSCTL_INT_SET(parent, OFP_OID_AUTO, name, OFP_CTLFLAG_RW,
 * &variable, 0, "");
 */
#define OFP_OID_AUTO	(-1)

#define OFP_SYSCTL_HANDLER_ARGS struct ofp_sysctl_oid *oidp, void *arg1, \
	intptr_t arg2, struct ofp_sysctl_req *req

/*
 * This describes the access space for a sysctl request.  This is needed
 * so that we can use the interface from the kernel or from user-space.
 */
struct ofp_sysctl_req {
	struct thread	*td;		/* used for access checking */
	int		lock;		/* wiring state */
	void		*oldptr;
	size_t		oldlen;
	size_t		oldidx;
	int		(*oldfunc)(struct ofp_sysctl_req *_r, const void *_p,
				   size_t _l);
	const void	*newptr;
	size_t		newlen;
	size_t		newidx;
	int		(*newfunc)(struct ofp_sysctl_req *_r, void *_p,
				   size_t _l);
	size_t		validlen;
	int		flags;
};

#define SYSCTL_IN(r, p, l) (r->newfunc)(r, p, l)
#define SYSCTL_OUT(r, p, l) (r->oldfunc)(r, p, l)


/*
 * This describes one "oid" in the MIB tree.  Potentially more nodes can
 * be hidden behind it, expanded by the handler.
 */
struct ofp_sysctl_oid {
	struct ofp_sysctl_oid *oid_parent;

	OFP_SLIST_HEAD(, ofp_sysctl_oid) oid_head;
	OFP_SLIST_ENTRY(ofp_sysctl_oid) oid_link;
	int		oid_number;
	unsigned int	oid_kind;
	void		*oid_arg1;
	intptr_t	oid_arg2;
	const char	*oid_name;
	int		(*oid_handler)(OFP_SYSCTL_HANDLER_ARGS);
	const char	*oid_fmt;
	int		oid_refcnt;
	unsigned int	oid_running;
	const char	*oid_descr;
};

#ifndef NO_SYSCTL_DESCR
#define __DESCR(d) d
#else
#define __DESCR(d) ""
#endif

#define SYSCTL_DECL(name)					\
	extern __thread struct ofp_sysctl_oid sysctl_##name

extern __thread int ofp_oid_auto;

SYSCTL_DECL(root);
SYSCTL_DECL(net);

/* Root's children case */
#define OFP_SYSCTL_OID_ROOT_CHLD_DEF(name) \
	__thread struct ofp_sysctl_oid sysctl_##name = {0}

#define OFP_SYSCTL_OID_ROOT_CHLD_SET(nbr, name, access, a1, a2, handler, fmt, descr) {	\
	sysctl_##name = (struct ofp_sysctl_oid){			    \
		&sysctl_root, OFP_SLIST_HEAD_INITIALIZER(oid_head), {NULL}, \
		nbr == OFP_OID_AUTO ? ofp_oid_auto++ : nbr,		    \
		access, a1, a2, #name, handler, fmt, 0, 0, __DESCR(descr)   \
	};								    \
	ofp_sysctl_add_child(&sysctl_##name, &sysctl_root);		    \
}

#define OFP_SYSCTL_NODE_ROOT_CHLD_DEF(name)	\
	OFP_SYSCTL_OID_ROOT_CHLD_DEF(name)

#define OFP_SYSCTL_NODE_ROOT_CHLD_SET(nbr, name, access, handler, descr)    \
	OFP_SYSCTL_OID_ROOT_CHLD_SET(nbr, name, OFP_CTLTYPE_NODE | (access),\
		0, 0, handler, "N", descr)

#define OFP_SYSCTL_PROC_ROOT_CHLD_DEF(name)	\
	OFP_SYSCTL_OID_ROOT_CHLD_DEF(name)

#define OFP_SYSCTL_PROC_ROOT_CHLD_SET(nbr, name, access, ptr, arg, handler, fmt, descr)	\
	OFP_SYSCTL_OID_ROOT_CHLD_SET(nbr, name, OFP_CTLTYPE_PROC | (access),\
		ptr, arg, handler, fmt, descr)

/* Regular case*/
#define OFP_SYSCTL_OID_DEF(parent, name) \
	__thread struct ofp_sysctl_oid sysctl_##parent##_##name = {0}

#define OFP_SYSCTL_OID_SET(parent, nbr, name, kind, a1, a2, handler, fmt, descr) { \
	sysctl_##parent##_##name = (struct ofp_sysctl_oid){		       \
		&sysctl_##parent, OFP_SLIST_HEAD_INITIALIZER(oid_head), {NULL},\
		nbr == OFP_OID_AUTO ? ofp_oid_auto++ : nbr,		       \
		kind, a1, a2, #name, handler, fmt, 0, 0, __DESCR(descr)	       \
	};								       \
	ofp_sysctl_add_child(&sysctl_##parent##_##name, &sysctl_##parent);     \
}

#define OFP_SYSCTL_NODE_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_NODE_SET(parent, nbr, name, access, handler, descr)	       \
	OFP_SYSCTL_OID_SET(parent, nbr, name, OFP_CTLTYPE_NODE | (access),     \
		NULL, 0, handler, "N", descr)

#define OFP_SYSCTL_INT_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_INT_SET(parent, nbr, name, access, ptr, val, descr)	       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_INT | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_int, "I", descr)

#define OFP_SYSCTL_UINT_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_UINT_SET(parent, nbr, name, access, ptr, val, descr)	       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_UINT | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_int, "IU", descr)

#define OFP_SYSCTL_LONG_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_LONG_SET(parent, nbr, name, access, ptr, val, descr)	       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_LONG | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_long, "L", descr)

#define OFP_SYSCTL_ULONG_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_ULONG_SET(parent, nbr, name, access, ptr, val, descr)       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_ULONG | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_long, "LU", descr)

#define OFP_SYSCTL_QUAD_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_QUAD_SET(parent, nbr, name, access, ptr, val, descr)	       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_S64 | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_64, "Q", descr)

#define OFP_SYSCTL_UQUAD_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

#define OFP_SYSCTL_UQUAD_SET(parent, nbr, name, access, ptr, val, descr)       \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_U64 | OFP_CTLFLAG_MPSAFE | (access),	       \
		ptr, val, sysctl_handle_64, "QU", descr)

#define OFP_SYSCTL_STRING_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

/* Oid for a string.  len can be 0 to indicate '\0' termination. */
#define OFP_SYSCTL_STRING_SET(parent, nbr, name, access, arg, len, descr)      \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_STRING | (access),				       \
		arg, len, sysctl_handle_string, "A", descr)

#define OFP_SYSCTL_OPAQUE_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

/* Oid for an opaque object.  Specified by a pointer and a length. */
#define OFP_SYSCTL_OPAQUE_SET(parent, nbr, name, access, ptr, len, fmt, descr) \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_OPAQUE | (access),				       \
		ptr, len, sysctl_handle_opaque, fmt, descr)

#define OFP_SYSCTL_STRUCT_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

/* Oid for a struct.  Specified by a pointer and a type. */
#define OFP_SYSCTL_STRUCT_SET(parent, nbr, name, access, ptr, type, descr)     \
	OFP_SYSCTL_OID_SET(parent, nbr, name,				       \
		OFP_CTLTYPE_OPAQUE | (access),				       \
		ptr, sizeof(struct type), sysctl_handle_opaque,		       \
		"S," #type, descr)

#define OFP_SYSCTL_PROC_DEF(parent, name)	\
	OFP_SYSCTL_OID_DEF(parent, name)

/* Oid for a procedure.  Specified by a pointer and an arg. */
#define OFP_SYSCTL_PROC_SET(parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
	OFP_SYSCTL_OID_SET(parent, nbr, name, OFP_CTLTYPE_PROC | (access), \
		ptr, arg, handler, fmt, descr)

/* OID handlers */
int sysctl_handle_int(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_msec_to_ticks(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_64(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_string(OFP_SYSCTL_HANDLER_ARGS);
int sysctl_handle_opaque(OFP_SYSCTL_HANDLER_ARGS);

void ofp_sysctl_add_child(struct ofp_sysctl_oid *oidp,
			  struct ofp_sysctl_oid *parent);

void ofp_sysctl_write_tree(int fd);

void ofp_sysctl_init_prepare(void);
int ofp_sysctl_init_global(void);
int ofp_sysctl_term_global(void);
int ofp_sysctl_init_local(void);

#endif	/* !_SYS_SYSCTL_H_ */
