/*
 * Copyright (c) 2013. Intel Corporation. All rights reserved.
 * Copyright (c) 2006-2012. QLogic Corporation. All rights reserved.
 * Copyright (c) 2003-2006, PathScale, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "psm_user.h"
#include "psm_mq_internal.h"

struct psmi_stats_type {
    STAILQ_ENTRY(psmi_stats_type)    next;
    struct psmi_stats_entry	    *entries;

    int	    num_entries;
    void    *heading;
    uint32_t statstype;
    void    *context;
};

static STAILQ_HEAD(, psmi_stats_type) psmi_stats = 
	    STAILQ_HEAD_INITIALIZER(psmi_stats);

psm_error_t
psmi_stats_register_type(const char *heading, 
			 uint32_t statstype,
			 const struct psmi_stats_entry *entries_i,
			 int num_entries,
			 void *context)
{
    struct psmi_stats_entry *entries;
    struct psmi_stats_type *type;
    int i;
    psm_error_t err = PSM_OK;

    entries = psmi_calloc(PSMI_EP_NONE, STATS, num_entries, sizeof(struct psmi_stats_entry));
    type = psmi_calloc(PSMI_EP_NONE, STATS, 1, sizeof(struct psmi_stats_type));
    PSMI_CHECKMEM(err, entries);
    PSMI_CHECKMEM(err, type);

    type->entries = entries;
    type->num_entries = num_entries;
    type->statstype = statstype;
    type->context = context;
    type->heading = (char *) heading;

    for (i = 0; i < num_entries; i++) {
	type->entries[i].desc  = entries_i[i].desc;
	type->entries[i].flags = entries_i[i].flags;
	type->entries[i].getfn = entries_i[i].getfn;
	type->entries[i].u.val = entries_i[i].u.val;
    }

    STAILQ_INSERT_TAIL(&psmi_stats, type, next);
    return err;

fail:
    if (entries) psmi_free(entries);
    if (type) psmi_free(type);
    return err;
}

psm_error_t
psmi_stats_deregister_all(void)
{
    struct psmi_stats_type *type;

    /* Currently our mpi still reads stats after finalize so this isn't safe
     * yet */
    while ((type = STAILQ_FIRST(&psmi_stats)) != NULL) {
	STAILQ_REMOVE_HEAD(&psmi_stats, next);
	psmi_free(type->entries);
	psmi_free(type);
    }

    return PSM_OK;
}

static
uint32_t
typestring_to_type(const char *typestr)
{
    if (strncasecmp(typestr, "all", 4) == 0)
	return PSMI_STATSTYPE_ALL;
    else if (strncasecmp(typestr, "p2p", 4) == 0)
	return PSMI_STATSTYPE_P2P;
    else if (strncasecmp(typestr, "ipath", 6) == 0)
	return PSMI_STATSTYPE_IPATH;
    else if (strncasecmp(typestr, "ips", 4) == 0)
	return PSMI_STATSTYPE_IPSPROTO;
    else if ((strncasecmp(typestr, "intr", 5) == 0) ||
	     (strncasecmp(typestr, "thread", 7) == 0) ||
	     (strncasecmp(typestr, "rcvthread", 10) == 0))
	return PSMI_STATSTYPE_RCVTHREAD;
    else if ((strncasecmp(typestr, "mq", 3) == 0) ||
	     (strncasecmp(typestr, "mpi", 4) == 0))
	return PSMI_STATSTYPE_MQ;
    else if ((strncasecmp(typestr, "tid", 4) == 0) ||
	     (strncasecmp(typestr, "tids", 5) == 0))
	return PSMI_STATSTYPE_TIDS;
    else if ((strncasecmp(typestr, "counter", 8) == 0) ||
	     (strncasecmp(typestr, "counters", 9) == 0))
	return PSMI_STATSTYPE_DEVCOUNTERS;
    else if (strncasecmp(typestr, "devstats", 9) == 0)
	return PSMI_STATSTYPE_DEVSTATS;
    else if ((strncasecmp(typestr, "memory", 7) == 0) ||
	     (strncasecmp(typestr, "alloc", 6) == 0) ||
	     (strncasecmp(typestr, "malloc", 7) == 0))
	return PSMI_STATSTYPE_MEMORY;
    else
	return 0;
}

static
uint32_t
stats_parse_enabled_mask(const char *stats_string) 
{
    char *b = (char *) stats_string;
    char *e = b;
    char buf[128];

    uint32_t stats_enabled_mask = 0;

    while (*e) {
	b = e;
	while (*e && *e != ',' && *e != '+' && *e != '.' && 
	       *e != '|' && *e != ':')
	    e++;
	if (e > b) { /* something new to parse */
	    int len = ((e - b) > (sizeof buf - 1)) ?
			(sizeof buf - 1) : (e - b);
	    strncpy(buf, b, len);
	    buf[len] = '\0';
	    stats_enabled_mask |= typestring_to_type(buf);
	}
	if (*e)
	    e++; /* skip delimiter */
    }
    return stats_enabled_mask;
}

static
void
psmi_stats_mpspawn_callback(struct mpspawn_stats_req_args *args)
{
    const struct psmi_stats_entry *entry;
    struct psmi_stats_type *type =
	    (struct psmi_stats_type *) args->context;
    int i, num = args->num;
    uint64_t *stats = args->stats;
    uint64_t *c = NULL;
    uint64_t *s = NULL;

    psmi_assert(num == type->num_entries);

    if (type->statstype == PSMI_STATSTYPE_DEVCOUNTERS ||
	type->statstype == PSMI_STATSTYPE_DEVSTATS) 
    {
	int unit_id = ((psm_ep_t) type->context)->unit_id;
	int portno = ((psm_ep_t) type->context)->portnum;
	uintptr_t off;
	uint8_t *p = NULL;
	int nc, npc, ns;
	int nstats = infinipath_get_stats_names_count();
	int nctrs = infinipath_get_ctrs_unit_names_count(unit_id);
	int npctrs = infinipath_get_ctrs_port_names_count(unit_id);

	if (nctrs != -1 && npctrs != -1)
		c = psmi_calloc(PSMI_EP_NONE, STATS, nctrs+npctrs,
				sizeof(uint64_t));
	if (nstats != -1)
		s = psmi_calloc(PSMI_EP_NONE, STATS, nstats, sizeof(uint64_t));

	/*
	 * If ipathfs is not loaded, we set NAN everywhere.  We don't want
	 * stats to break just because 1 node didn't have ipath-stats
	 */
	if (type->statstype == PSMI_STATSTYPE_DEVCOUNTERS && c != NULL) {
	    nc = infinipath_get_ctrs_unit(unit_id, c, nctrs);
	    if (nc != -1 && nc == nctrs)
		p = (uint8_t *)c;
	    if (nc == -1)
	    	nc = 0;
	    npc = infinipath_get_ctrs_port(unit_id, portno, c+nc, npctrs);
	    if (!p && npc > 0 && npc == npctrs)
		p = (uint8_t *)c;
	}
	else if (s != NULL) {
            ns = infinipath_get_stats(s, nstats);
	    if (ns != -1)
		p = (uint8_t *)s;
	}
	for (i = 0; i < num; i++) {
	    entry = &type->entries[i];
	    if (p) {
		off = (uintptr_t) entry->u.off;
		stats[i] = *((uint64_t *)(p + off));
	    }
	    else
		stats[i] = MPSPAWN_NAN_U64;
	}
    }
    else if (type->statstype == PSMI_STATSTYPE_MEMORY) {
	for (i = 0; i < num; i++)  {
	    entry = &type->entries[i];
	    stats[i] = *(uint64_t *) ((uintptr_t) &psmi_stats_memory 
				      + (uintptr_t) entry->u.off);
	}
    }
    else {
	for (i = 0; i < num; i++) {
	    entry = &type->entries[i];
	    if (entry->getfn != NULL)
		stats[i] = entry->getfn(type->context);
	    else
		stats[i] = *entry->u.val;
	}
    }

    if (c != NULL)
    	psmi_free(c);
    if (s != NULL)
    	psmi_free(s);
}

static
void
stats_register_mpspawn_single(mpspawn_stats_add_fn add_fn,
			      char *heading,
			      int num_entries, 
			      struct psmi_stats_entry *entries,
			      mpspawn_stats_req_fn req_fn,
			      void *context)
{
    int i;
    struct mpspawn_stats_add_args mp_add;

    mp_add.version = MPSPAWN_STATS_VERSION;
    mp_add.num = num_entries;
    mp_add.header = heading;
    mp_add.req_fn = req_fn;
    mp_add.context = context;

    mp_add.desc = (char **) alloca(sizeof(char *) * num_entries);
    psmi_assert_always(mp_add.desc != NULL);

    mp_add.flags = (uint16_t *) alloca(sizeof(uint16_t *) * num_entries);
    psmi_assert_always(mp_add.flags != NULL);

    for (i = 0; i < num_entries; i++) {
	mp_add.desc[i] = (char *) entries[i].desc;
	mp_add.flags[i] = entries[i].flags;
    }

    /* Ignore return code, doesn't matter to *us* if register failed */
    add_fn(&mp_add);

    return;
}

static void stats_register_ipath_counters(psm_ep_t ep);
static void stats_register_ipath_stats(psm_ep_t ep);
static void stats_register_mem_stats(psm_ep_t ep);
static psm_error_t psmi_stats_epaddr_register(struct mpspawn_stats_init_args *args);

/*
 * Downcall from QLogic MPI into PSM, so we can register stats
 */
void *psmi_stats_register(struct mpspawn_stats_init_args *args)
{
    struct psmi_stats_type *type;
    uint32_t statsmask;
    
    /* 
     * Args has a version string in it, but we can ignore it since mpspawn
     * will decide if it supports *our* version
     */

    /* 
     * Eventually, parse the stats_types to add various "flavours" of stats
     */
    if (args->stats_types == NULL)
	return NULL;

    statsmask = stats_parse_enabled_mask(args->stats_types);

    /* MQ (MPI-level) statistics */
    if (statsmask & PSMI_STATSTYPE_MQ)
	psmi_mq_stats_register(args->mq, args->add_fn);

    /* PSM and ipath level statistics */
    if (statsmask & PSMI_STATSTYPE_DEVCOUNTERS)
	stats_register_ipath_counters(args->mq->ep);

    if (statsmask & PSMI_STATSTYPE_DEVSTATS)
	stats_register_ipath_stats(args->mq->ep);

    if (statsmask & PSMI_STATSTYPE_MEMORY)
	stats_register_mem_stats(args->mq->ep);

    /* 
     * At this point all PSM and ipath-level components have registered stats
     * with the PSM stats interface.  We register with the mpspawn stats
     * interface with an upcall in add_fn 
     */
    STAILQ_FOREACH(type, &psmi_stats, next) 
    {
	if (type->statstype & statsmask) 
	    stats_register_mpspawn_single(args->add_fn,
					  type->heading,
					  type->num_entries,
					  type->entries,
					  psmi_stats_mpspawn_callback,
					  type);
    }

    /*
     * Special handling for per-endpoint statistics
     * Only MPI knows what the endpoint-addresses are in the running program,
     * PSM has no sense of MPI worlds.  In stats register, MPI tells PSM how
     * many endpoints it anticipates having and PSM simply reserves that amount
     * of stats entries X the amount of per-endpoint stats.
     */
    if (statsmask & PSMI_STATSTYPE_P2P) 
	psmi_stats_epaddr_register(args);

    return NULL;
}

struct stats_epaddr {
    psm_ep_t		  ep;
    mpspawn_map_epaddr_fn epaddr_map_fn;
    int			  num_ep;
    int			  num_ep_stats;
};

static
void
psmi_stats_epaddr_callback(struct mpspawn_stats_req_args *args)
{
    int i, num, off;
    uint64_t *statsp;
    struct stats_epaddr *stats_ctx = (struct stats_epaddr *) args->context;
    psm_ep_t ep = stats_ctx->ep;
    psm_epaddr_t epaddr;

    num = stats_ctx->num_ep * stats_ctx->num_ep_stats;

    /* First always NAN the entire stats request */
    for (i = 0; i < num; i++) {
	if (args->flags[i] & MPSPAWN_STATS_TYPE_DOUBLE)
	    args->stats[i] = MPSPAWN_NAN;
	else
	    args->stats[i] = MPSPAWN_NAN_U64;
    }

    for (i = 0; i < stats_ctx->num_ep; i++) {
	statsp = args->stats + i*stats_ctx->num_ep_stats;
	off = 0;
	epaddr = stats_ctx->epaddr_map_fn(i);
	if (epaddr == NULL)
	    continue;

	/* Self */
	if (&ep->ptl_self == epaddr->ptlctl) {
	    if (ep->ptl_self.epaddr_stats_get != NULL) 
		off += ep->ptl_self.epaddr_stats_get(epaddr, statsp + off);
	}
	else {
	    if (ep->ptl_self.epaddr_stats_num != NULL) 
		off += ep->ptl_self.epaddr_stats_num();
	}

	/* Shm */
	if (&ep->ptl_amsh == epaddr->ptlctl) {
	    if (ep->ptl_amsh.epaddr_stats_get != NULL) 
		off += ep->ptl_amsh.epaddr_stats_get(epaddr, statsp + off);
	}
	else {
	    if (ep->ptl_amsh.epaddr_stats_num != NULL) 
		off += ep->ptl_amsh.epaddr_stats_num();
	}

	/* ips */
	if (&ep->ptl_ips == epaddr->ptlctl) {
	    if (ep->ptl_ips.epaddr_stats_get != NULL) 
		off += ep->ptl_ips.epaddr_stats_get(epaddr, statsp + off);
	}
	else {
	    if (ep->ptl_ips.epaddr_stats_num != NULL) 
		off += ep->ptl_ips.epaddr_stats_num();
	}
    }
    return;
}

static
psm_error_t
psmi_stats_epaddr_register(struct mpspawn_stats_init_args *args)
{
    int i = 0, j;
    int num_ep = args->num_epaddr;
    int num_ep_stats = 0;
    int nz;
    char **desc, **desc_i;
    uint16_t *flags, *flags_i;
    char *p;
    char buf[128];
    psm_ep_t ep;
    struct mpspawn_stats_add_args mp_add;
    struct stats_epaddr *stats_ctx;
    psm_error_t err = PSM_OK;

    if (args->mq == NULL)
	return PSM_OK;
    ep = args->mq->ep;

    /* Figure out how many stats there are in an endpoint from all devices */
    if (ep->ptl_self.epaddr_stats_num != NULL)
	num_ep_stats += ep->ptl_self.epaddr_stats_num();
    if (ep->ptl_amsh.epaddr_stats_num != NULL)
	num_ep_stats += ep->ptl_amsh.epaddr_stats_num();
    if (ep->ptl_ips.epaddr_stats_num != NULL)
	num_ep_stats += ep->ptl_ips.epaddr_stats_num();

    /* Allocate desc and flags and let each device initialize their
     * descriptions and flags */
    desc = psmi_malloc(ep, STATS, sizeof(char *) * num_ep_stats * (num_ep+1));
    if (desc == NULL)
	return PSM_NO_MEMORY;
    flags = psmi_malloc(ep, STATS, sizeof(uint16_t) * num_ep_stats * (num_ep+1));
    if (flags == NULL) {
	psmi_free(desc);
	return PSM_NO_MEMORY;
    }

    /* Get the descriptions/flags from each device */ 
    i = 0;
    i += ep->ptl_self.epaddr_stats_num != NULL ?
	    ep->ptl_self.epaddr_stats_init(desc + i, flags + i) : 0;
    i += ep->ptl_amsh.epaddr_stats_num != NULL ?
	    ep->ptl_amsh.epaddr_stats_init(desc + i, flags + i) : 0;
    i += ep->ptl_ips.epaddr_stats_num != NULL ?
	    ep->ptl_ips.epaddr_stats_init(desc + i, flags + i) : 0;
    psmi_assert_always(i == num_ep_stats);

    /* 
     * Clone the descriptions for each endpoint but append "rank %d" to it
     * beforehand.
     */
    nz = (num_ep < 10 ? 1 : (num_ep < 100 ? 2 : /* cheap log */
		(num_ep < 1000 ? 3 : (num_ep < 1000 ? 4 :
			(num_ep < 10000 ? 5 : 6)))));
			    
    desc_i  = desc + num_ep_stats;
    flags_i = flags + num_ep_stats;
    memset(desc_i, 0, sizeof(char*)*num_ep*num_ep_stats);

    for (i = 0; i < num_ep; i++) {
	for (j = 0; j < num_ep_stats; j++) {
	    snprintf(buf, sizeof buf - 1, "<%*d> %s", nz, i, desc[j]);
	    buf[sizeof buf - 1] = '\0';
	    p = psmi_strdup(ep, buf);
	    if (p == NULL) {
		err = PSM_NO_MEMORY;
		goto clean;
	    }
	    desc_i [i * num_ep_stats + j] = p;
	    flags_i[i * num_ep_stats + j] = flags[j];
	}
    }

    mp_add.version = MPSPAWN_STATS_VERSION;
    mp_add.num = num_ep_stats * num_ep;
    mp_add.header = "Endpoint-to-Endpoint Stats (by <rank>)";
    mp_add.req_fn = psmi_stats_epaddr_callback;
    mp_add.desc = desc_i;
    mp_add.flags = flags_i;
    stats_ctx = psmi_malloc(ep, STATS, sizeof(struct stats_epaddr));
    if (stats_ctx == NULL) {
	err = PSM_NO_MEMORY;
	goto clean;
    }
    stats_ctx->ep = ep;
    stats_ctx->epaddr_map_fn = args->epaddr_map_fn;
    stats_ctx->num_ep = num_ep;
    stats_ctx->num_ep_stats = num_ep_stats;
    mp_add.context = stats_ctx;

    args->add_fn(&mp_add);

clean:
    /* Now we can free all the descriptions */
    for (i = 0; i < num_ep; i++) {
	for (j = 0; j < num_ep_stats; j++)
	    if (desc_i[i * num_ep_stats + j]) psmi_free(desc_i[i * num_ep_stats + j]);
    }

    psmi_free(desc);
    psmi_free(flags);

    return err;
}

static 
void
stats_register_ipath_counters(psm_ep_t ep)
{
    int i, nc, npc;
    char *cnames = NULL, *pcnames = NULL;
    struct psmi_stats_entry *entries = NULL;

    nc = infinipath_get_ctrs_unit_names(ep->unit_id, &cnames);
    if (nc == -1 || cnames == NULL)
	    goto bail;
    npc = infinipath_get_ctrs_port_names(ep->unit_id, &pcnames);
    if (npc == -1 || pcnames == NULL)
	    goto bail;
    entries = psmi_calloc(ep, STATS, nc+npc, sizeof(struct psmi_stats_entry));
    if (entries == NULL)
	    goto bail;

    for (i = 0; i < nc; i++) {
	    entries[i].desc = infinipath_get_next_name(&cnames);
	    entries[i].flags = MPSPAWN_STATS_REDUCTION_ALL |
			       MPSPAWN_STATS_SKIP_IF_ZERO;
	    entries[i].getfn = NULL;
	    entries[i].u.off = i*sizeof(uint64_t);
    }
    for (i = nc; i < nc+npc; i++) {
	    entries[i].desc = infinipath_get_next_name(&pcnames);
	    entries[i].flags = MPSPAWN_STATS_REDUCTION_ALL |
			       MPSPAWN_STATS_SKIP_IF_ZERO;
	    entries[i].getfn = NULL;
	    entries[i].u.off = i*sizeof(uint64_t);
    }
    psmi_stats_register_type("InfiniPath device counters", 
			     PSMI_STATSTYPE_DEVCOUNTERS,
			     entries,
			     nc+npc,
			     ep);

bail:
    if (cnames != NULL)
	    psmi_free(cnames);
    if (pcnames != NULL)
	    psmi_free(pcnames);
    if (entries != NULL)
	    psmi_free(entries);
    return;
}

static 
void
stats_register_ipath_stats(psm_ep_t ep)
{
    int i, ns;
    char *snames = NULL;
    struct psmi_stats_entry *entries = NULL;

    ns = infinipath_get_stats_names(&snames);
    if (ns == -1 || snames == NULL)
	    goto bail;
    entries = psmi_calloc(ep, STATS, ns, sizeof(struct psmi_stats_entry));
    if (entries == NULL)
	    goto bail;

    for (i = 0; i < ns; i++) {
	    entries[i].desc = infinipath_get_next_name(&snames);
	    entries[i].flags = MPSPAWN_STATS_REDUCTION_ALL |
			       MPSPAWN_STATS_SKIP_IF_ZERO;
	    entries[i].getfn = NULL;
	    entries[i].u.off = i*sizeof(uint64_t);
    }
    psmi_stats_register_type("InfiniPath device statistics", 
			     PSMI_STATSTYPE_DEVSTATS,
			     entries,
			     ns,
			     ep);

bail:
    if (snames != NULL)
	    psmi_free(snames);
    if (entries != NULL)
	    psmi_free(entries);
    return;
}

#undef _SDECL
#define _SDECL(_desc, _param) {					\
	    .desc  = _desc,					\
	    .flags = MPSPAWN_STATS_REDUCTION_ALL 		\
		     | MPSPAWN_STATS_SKIP_IF_ZERO,		\
	    .getfn = NULL,					\
	    .u.off = offsetof(struct psmi_stats_malloc, _param)	\
	}

static 
void
stats_register_mem_stats(psm_ep_t ep)
{
    struct psmi_stats_entry entries[] = {
	_SDECL("Total (current)", m_all_total),
	_SDECL("Total (max)", m_all_max),
	_SDECL("All Peers (current)", m_perpeer_total),
	_SDECL("All Peers (max)", m_perpeer_max),
	_SDECL("Network Buffers (current)", m_netbufs_total),
	_SDECL("Network Buffers (max)", m_netbufs_max),
	_SDECL("PSM desctors (current)", m_descriptors_total),
	_SDECL("PSM desctors (max)", m_descriptors_max),
	_SDECL("Unexp. buffers (current)", m_unexpbufs_total),
	_SDECL("Unexp. Buffers (max)", m_unexpbufs_max),
	_SDECL("Other (current)", m_undefined_total),
	_SDECL("Other (max)", m_undefined_max),
    };

    psmi_stats_register_type("PSM memory allocation statistics", 
			     PSMI_STATSTYPE_MEMORY,
			     entries,
			     PSMI_STATS_HOWMANY(entries),
			     ep);
}
