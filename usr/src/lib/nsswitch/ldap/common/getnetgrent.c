/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

/*
 * nss_ldap netgroup support
 *
 * Like other name service switch modules, this code may run in nscd or
 * arbitrary processes that call getnetgrent(3C), getnetgrent_r(3C),
 * setnetgrent(3C), endnetgrent(3C), and innetgr(3C).  For a reason that is not
 * entirely clear ("due to backend knowledge"), libc's nss_pack() instructs
 * callers of all netgroup functions other than innetgr(3C) to NSS_TRYLOCAL
 * rather than allowing the query to be passed to nscd.  This is probably of
 * negligible impact, as modern use of netgroup lookups is almost exclusively
 * through innetgr(3C).
 *
 * Whether being called from libc or nscd, initialization happens via a call to
 * _nss_ldap_netgroup_constr().  There is no destructor - rather the library is
 * closed with dlclose(), which will trigger ngc_fini().  The most likely
 * consumer, nscd, restarts itself when it sees a configuration change.
 *
 *
 * Netgroup Caching
 *
 * Caching of netgroups is done within this module because the type of caching
 * that is most useful for netgroups is a poor fit for nscd.  nscd is focused on
 * caching individual results, with the assumption that one request doesn't
 * perform a high cost operation from which a subsequent operation may benefit.
 * The poster child for this problem is the most common case: innetgr().  The
 * LDAP NIS schema is poorly designed for innetgr because it forces a full
 * object transfer for every innetgr call.  Native NIS avoids this with the
 * revnetgroup map.
 *
 * Netgroups are cached only when running as part of the
 * svc:/system/name-service-cache:default service.  nscd.conf(4) can be used to
 * override defaults with enable-cache, positive-time-to-live, and
 * negative-time-to-live.  While enable-cache defaults to "yes", lookups that
 * bypass nscd still are not cached.
 *
 * The cache is implemented as an AVL tree (ngc_cache), with each node of the
 * tree representing one netgroup.  Nested netgroups are not flattened, implying
 * that if there are two netgroups that each include a common third netgroup,
 * there will be three tree nodes.  Expired netgroups that still have references
 * are migrated from ngc_cache (AVL tree) to ngc_graveyard (list).
 *
 * The following functions are intended to be called by those functions that
 * implement setnetgrent(), endnetgrent(), and innetgr().
 *
 * netgroup_get()	On success, a reference counted pointer to a cached
 *			netgroup is returned.  A call to this function may
 *			trigger the netgroup to be loaded from LDAP.
 *			The context that is passed is used to ensure that
 *			use of memberNisNetgroup does not lead to infinite
 *			loops.
 * netgroup_rele()	Releases the reference returned by netgroup_get.
 *
 *
 * Locking
 *
 * There is one big lock, ngc_lock.  It must be held while accessing ngc_cache,
 * or any of the lists that may reference netgroup_t objects.  It must also be
 * held while accessing the ng_refcnt field of any netgroup_t that is in any of
 * the ngc_* lists or tree.
 *
 * ngc_*() functions operate on netgroup_t objects.  ngc_*_locked() functions
 * must be called with ngc_lock held and the others expect ngc_lock not to be
 * held.
 *
 *
 * Expiry
 *
 * Clearly, it is not OK to cache data forever without checking to ensure that
 * it is current.  When a netgroup is loaded from LDAP, its expiration time is
 * set to ngc_pos_ttl (default NGC_POS_TTL) seconds from the time that it is
 * loaded.  Any queries that start after the expiration time will trigger the
 * netgroup to be loaded from LDAP again.  Negative (NSS_NOTFOUND) results are
 * also cached for ngc_neg_ttl seconds.  As mentioned above, the defaults can be
 * overridden by positive-time-to-live and negative-time-to-live in nscd.conf.
 *
 * To avoid full reloads of netgroups on a regular basis, a netgroup_get() that
 * occurs in the final 25% of a netgroup's expiry period will trigger a worker
 * thread to make an LDAP query to check the modifyTimestamp of the relevant
 * netgroup object.  If the modifyTimestamp has not changed from its value
 * stored in the cache, the netgroup's timeout is reset to ngc_pos_ttl seconds
 * in the future.  If the modifyTimestamp has changed to a later time, the
 * netgroup will be reloaded and replaced in or removed from the cache.  In
 * addition to reducing the load on the LDAP server(s), this approach leads to
 * lower latency for frequent lookups.
 *
 * Each netgroup in the cache is also in the ngc_pos_expire_queue or
 * ngc_neg_expire_queue list_t.  These lists are ordered by expiry time, with
 * each new or renewed netgroup being placed at the end of the appropriate list.
 * Whether triggered by a lookup or a periodic reap (see ngc_reap_locked()),
 * when an expired netgroup is removed from ngc_cache, it is also removed from
 * the expire queue.  See ngc_dispose_locked().
 *
 * When setnetgrent() is called, it calls netgroup_get() and holds the reference
 * in the context that lives until endnetgrent() is called or the netgroup is
 * fully consumed.  To avoid problems with a netgroup reference that is returned
 * in the instant before the netgroup expires, the reference is valid for at
 * least EXPIRE_SECONDS seconds.
 *
 * When nscd sees a configuration change, it restarts itself.  Thus, there is no
 * need for any finalization code to free state.  Applications that call
 * setnetgrent() should call endnetgrent() to free resources held by this module
 * and libslap.
 *
 *
 * Example
 *
 * In this example, the cache has 6 netgroups: admins, bastion, blah, devs, ops,
 * and qa.  In ngc_cache, the solid lines represent the tree structure, the
 * dotted lines represent expiration queues (lists), and the hash lines
 * represent the warm queue.
 *
 *  - Five of them are not expired: admins, bastion, blah, devs, qa
 *    - Three of the non-expired netgroups exist: admins, bastion, devs
 *      - Two of these are active and near their expiration time so a refresh
 *        has been queued: (admins, bastion)
 *    - Two of the recently queried netgroups do not exist: blah, qa
 *  - One netgroup is expired but is still referenced: ops
 *
 *                            ngc_cache                       ngc_graveyard
 *                               |                                  |
 *                               V                                  V
 *                          +----------+                       +---------+
 *                          | @blah    |                       | @ops    |
 *                          | negative |<..............        | expired |
 *                          +----------+              :        +---------+
 *                            /       \               :
 *                  +----------+     +----------+     :
 *             ....>| @bastion |....>| @devs    |     :
 *             :    | positive |     | positive |     :
 *             :    +----------+     +----------+     :
 *             :      /   ^                    \      :
 *          +----------+  #                   +----------+
 *          | @admins  |###                   | @qa      |
 *          | positive |<##########           | negative |
 *          +----------+          #           +----------+
 *          ^                     #                    ^
 *          :                     #                    :
 *   ngc_pos_expire_queue   ngc_warm_queue   ngc_neg_expire_queue
 *
 * When the thread that has a hold on ops releases it, ops will be removed from
 * ngc_graveyard and will be freed.
 *
 * When ngc_warmer wakes up, it will walk far enough into each of
 * ngc_neg_expire_queue and ngc_pos_expire_queue to see the first non-expired
 * netgroup on each list or the end of the list.  Those netgroups that it
 * encounters that are expired will be moved to ngc_graveyard or freed,
 * depending on whether they have references.  Both admins and bastion will have
 * their modifyTimestamp attribute queried, causing each of those netgroups to
 * be renewed or expired and replaced.
 */


#include <assert.h>
#include <errno.h>
#include <libscf.h>
#include <locale.h>
#include <stddef.h>
#include <syslog.h>
#include <sys/avl.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <sys/sdt.h>
#include <sys/sysmacros.h>
#include <thread.h>
#include "ldap_common.h"

/* netgroup attributes filters */
#define	_N_TRIPLE		"nisnetgrouptriple"
#define	_N_MEMBER		"membernisnetgroup"
#define	_N_MODIFYSTAMP		"modifyTimestamp"

#define	PRINT_VAL(a)		((((a).argc == 0) || ((a).argv == NULL) || \
				    ((a).argv[0] == NULL)) ? "*" : (a).argv[0])
#define	ISNULL(a)		(a == NULL ? "<NULL>" : a)
#define	MAX_DOMAIN_LEN		1024
#define	MAX_TRIPLE_LEN		(MAXHOSTNAMELEN + LOGNAME_MAX + \
					MAX_DOMAIN_LEN + 5)

#define	_F_SETMEMBER		"(&(objectClass=nisNetGroup)(cn=%s))"
#define	_F_SETMEMBER_SSD	"(&(%%s)(cn=%s))"

#define	N_HASH		257
#define	COMMA		','

/* These are in seconds.  Be careful: ngc_expire and ng_refresh are in nsec. */
#define	NGC_POS_TTL		3600	/* or nscd.conf positive-time-to-live */
#define	NGC_NEG_TTL		5	/* or nscd.conf negative-time-to-live */

#define	NGC_DATESTR_LEN		24

#define	NSCD_FMRI "svc:/system/name-service-cache:default"
#define	NSCD_CONF "/etc/nscd.conf"

static const char *netgrent_attrs[] = {
	_N_TRIPLE,
	_N_MEMBER,
	_N_MODIFYSTAMP,
	(char *)NULL
};

static const char *netgrent_stamp[] = {
	_N_MODIFYSTAMP,
	(char *)NULL
};

/*
 * Each of these will reference strings in ng_result.  Per split_triple(), NULL
 * is treated as a wild card.
 */
typedef struct {
	const char *ngt_host;
	const char *ngt_user;
	const char *ngt_domain;
} ngc_triple_t;

typedef enum {
	NGC_FLAG_NEGATIVE	= 0x01,
	NGC_FLAG_INCACHE	= 0x02,
	NGC_FLAG_INWARMER	= 0x04,
	NGC_FLAG_INEXPQUEUE	= 0x08,
} ngc_flags_t;

#define	NGC_NEGATIVE(ng)	(!!((ng)->ng_flags & NGC_FLAG_NEGATIVE))
#define	NGC_INCACHE(ng)		(!!((ng)->ng_flags & NGC_FLAG_INCACHE))
#define	NGC_INWARMER(ng)	(!!((ng)->ng_flags & NGC_FLAG_INWARMER))
#define	NGC_INEXPQUEUE(ng)	(!!((ng)->ng_flags & NGC_FLAG_INEXPQUEUE))

#define	NGC_CLEAR(ng, flags)	((ng)->ng_flags &= ~(flags))
#define	NGC_SET(ng, flags)	((ng)->ng_flags |= (flags))

/*
 * A cached netgroup.
 *
 * Each netgroup_t is in ng_cache (with NGC_FLAG_INCACHE) or ng_graveyard
 * (without NGC_FLAG_INCACHE).  Those that are in ng_cache are also in
 * ngc_pos_expire_queue or ngc_neg_expire_queue, roughly sorted by ng_expire
 * (soonest at head).  References in ng_cache, ng_graveyard,
 * ng_pos_expire_queue, and ng_neg_expire_queue do not cause ng_refcnt to
 * increase.  Any other reference while not also holding ng_lock (including
 * those for ng_warm_queue) do increase ng_refcnt.
 *
 * This structure is arranged such that it is as friendly as possible to dtrace
 * scripts that need to work across 32-bit and 64-bit executables.  In
 * particular, pointers come late in the structure and any 64-bit fields are
 * 64-bit aligned to avoid strange offsets.
 */
typedef struct {
	/* Monotonic seconds */
	uint32_t ng_birth;		/* For cache debugging */
	uint32_t ng_expire;		/* Do not use after */
	uint32_t ng_refresh;		/* Time to update ahead of expiry */

	uint32_t ng_refcnt;
	uint64_t ng_lastchange;		/* Tenths of second since epoch */
	ngc_flags_t ng_flags;
	ns_ldap_result_t *ng_result;
	ngc_triple_t *ng_triples;
	uint32_t ng_triplecnt;
	union {
		avl_node_t ng_cache;	/* if NGC_INCACHE(), in ngc_cache */
		list_node_t ng_tombstone; /* !NGC_INCACHE(), in ngc_graveyard */
	} ng_linkage;
	list_node_t ng_warm_linkage;	/* ngc_warm_queue */
	list_node_t ng_expire_linkage;	/* ngc_{pos,neg}_expire_queue */
	const char *ng_name;		/* Will reference space after struct */
} netgroup_t;

/*
 * While iterating a netgroup we must keep track of which memberNisNetgroups
 * have been seen and avoid visiting the same nested netgroup multiple times.
 * This is particularly important for netgroups that form circular references.
 *
 * This is handled with a netgroup_table_t.  Each iterator establishes a
 * netgroup_table_t containing a hash table of netgroup_name_t elements.
 */
typedef struct netgroup_name {
	char *ngn_name;
	struct netgroup_name *ngn_next;
	struct netgroup_name *ngn_next_hash;
} netgroup_name_t;

typedef struct {
	netgroup_name_t *ngt_hash_list[N_HASH];
	netgroup_name_t *ngt_to_do;
	netgroup_name_t *ngt_done;
} netgroup_table_t;

typedef unsigned int hash_t;

/*
 * This cookie is used across setnetgrent()/getnetgrent()/endnetgrent().
 */
typedef struct {
	netgroup_t *gnc_netgroup;	/* cached netgroup */
	ns_ldap_entry_t *gnc_entry;	/* entry in netgroup->ng_result */
	char *gnc_name;			/* netgroup name */
	uint32_t gnc_curtriple;		/* index in netgroup->ng_triples */
	netgroup_table_t gnc_tab;
} getnetgrent_cookie_t;

/* These hold netgroup_t nodes in the cache. */
static avl_tree_t ngc_cache;
static list_t ngc_graveyard;
static list_t ngc_warm_queue;

/*
 * ngc_lock must be held while modifying ngc_cache, ngc_graveyard, or adjusting
 * ng_refcnt in any netgroup in ngc_cache or ngc_graveyard.
 */
static mutex_t ngc_lock = ERRORCHECKMUTEX;
static boolean_t ngc_initialized = B_FALSE;

/*
 * The warmer thread performs asynchronous refreshes of active netgroups that
 * are approaching their expiration.  Activity is defined as having at least one
 * use in the final 25% of ngc_pos_ttl.
 *
 * Don't think the warmer thread is all rainbows and unicorns: it is also the
 * grim reaper for expired netgroups.  It wakes up every ngc_reap_interval
 * seconds and clears the cache of expired netgroups.
 */
static cond_t ngc_warm_cv = DEFAULTCV;
static thread_t ngc_warmer_tid;
static boolean_t ngc_warmer_die = B_FALSE;
static list_t ngc_pos_expire_queue;
static list_t ngc_neg_expire_queue;
static uint32_t ngc_reap_interval = 313;	/* Arbitrary, but not N * 60 */

/*
 * The positive cache size is naturally limited by the size of all the netgroups
 * in the LDAP server.  The negative cache is limited only by imagination,
 * unless we have an explicit limit on the size.
 */
static uint32_t ngc_neg_max = 200;		/* Arbitrary */
static volatile uint32_t ngc_neg_count = 0;

/* Initialized in read_nscd_conf() */
static boolean_t ngc_enable;
static int ngc_pos_ttl;
static int ngc_neg_ttl;

static int split_triple(char *, const char **, const char **, const char **);
static void ngc_dispose_locked(netgroup_t *);

/*
 * We don't really care about high-precision timers for cache expiration, but we
 * do need a monotonic clock.  ngc_first_tick is initialized by ngc_init() to
 * the number of seconds returned by gethrtime().  ngc_last_tick is the number
 * of seconds since ngc_first_tick.
 *
 * ngc_first_tick is a global to allow ngc_init() and ngc_time() to cooperate.
 * ngc_last_tick is a global so it is available during post-mortem analysis.
 */
static uint32_t ngc_first_tick = 0;
static uint32_t ngc_last_tick = 0;

static uint32_t
ngc_time(void)
{
	uint32_t tick;

	tick = NSEC2SEC(gethrtime()) - ngc_first_tick;
	DTRACE_PROBE1(nss_ldap, ngc__tick, tick);

	/*
	 * For post-mortem analysis only; the winner of a race will update all
	 * 32-bits at once.
	 */
	ngc_last_tick = tick;

	return (tick);
}

static netgroup_t *
ngc_alloc(const char *name)
{
	netgroup_t *ng;
	size_t len = strlen(name) + 1;

	/*
	 * Use one allocation for the structure and the variable length name.
	 * Not using flexible array member because we need to be able to assign
	 * a value to ng_name before avl_find() without doing a heap allocation.
	 */
	if ((ng = calloc(1, sizeof (*ng) + len)) == NULL) {
		return (NULL);
	}

	ng->ng_birth = ngc_time();
	ng->ng_name = (const char *)ng + sizeof (*ng);
	(void) strlcpy((char *)ng->ng_name, name, len);

	return (ng);
}

static void
ngc_free(netgroup_t *ng)
{
	DTRACE_PROBE2(nss_ldap, netgroup__cache__free, ng->ng_name, ng);

	VERIFY0(ng->ng_refcnt);
	free(ng->ng_triples);
	(void) __ns_ldap_freeResult(&ng->ng_result);
	free(ng);
}

static void
ngc_hold_locked(netgroup_t *ng)
{
	VERIFY(MUTEX_HELD(&ngc_lock));
	DTRACE_PROBE3(nss_ldap, netgroup__cache__hold, ng->ng_name, ng,
	    ng->ng_refcnt);
	ng->ng_refcnt++;
}

static void
ngc_rele_locked(netgroup_t *ng)
{
	uint32_t now = ngc_time();

	VERIFY(MUTEX_HELD(&ngc_lock));
	VERIFY3S(ng->ng_refcnt, >, 0);

	DTRACE_PROBE3(nss_ldap, netgroup__cache__rele, ng->ng_name, ng,
	    ng->ng_refcnt);

	ng->ng_refcnt--;
	if (ng->ng_expire <= now || !NGC_INCACHE(ng)) {
		ngc_dispose_locked(ng);
	}
}

static void
netgroup_rele(netgroup_t *ng)
{
	mutex_enter(&ngc_lock);

	ngc_rele_locked(ng);

	mutex_exit(&ngc_lock);
}

/*
 * Free or otherwise properly dispose of a netgroup that is evicted from the
 * cache or may be ready to be evicted from the graveyard.  Does not alter the
 * reference count.
 */
static void
ngc_dispose_locked(netgroup_t *ng)
{
	VERIFY(MUTEX_HELD(&ngc_lock));

	DTRACE_PROBE4(nss_ldap, netgroup__cache__dispose, ng->ng_name, ng,
	    ng->ng_refcnt, ng->ng_flags);

	if (NGC_INCACHE(ng)) {
		avl_remove(&ngc_cache, ng);

		/*
		 * If it is in the cache, it is also in an expire queue.
		 */
		if (NGC_NEGATIVE(ng)) {
			list_remove(&ngc_neg_expire_queue, ng);
			ngc_neg_count--;
		} else {
			list_remove(&ngc_pos_expire_queue, ng);
		}

		if (ng->ng_refcnt == 0) {
			ngc_free(ng);
		} else {
			NGC_CLEAR(ng, NGC_FLAG_INEXPQUEUE);
			NGC_CLEAR(ng, NGC_FLAG_INCACHE);
			DTRACE_PROBE2(nss_ldap, netgroup__cache__to__graveyard,
			    ng->ng_name, ng);
			list_insert_tail(&ngc_graveyard, ng);
		}
		return;
	}

	/*
	 * If it's not in the cache, it's in the graveyard but may still have
	 * references.
	 */
	if (ng->ng_refcnt == 0) {
		list_remove(&ngc_graveyard, ng);
		ngc_free(ng);
		return;
	}
}

static void
ngc_set_expire_locked(netgroup_t *ng)
{
	list_t *expire_queue;
	int expire_ttl;
	int refresh_ttl;

	VERIFY(MUTEX_HELD(&ngc_lock));

	if (NGC_NEGATIVE(ng)) {
		expire_queue = &ngc_neg_expire_queue;
		ng->ng_expire = ngc_enable ? (ngc_time() + ngc_neg_ttl) : 0;
		ng->ng_refresh = 0;
	} else {
		expire_queue = &ngc_pos_expire_queue;
		ng->ng_expire = ngc_enable ?
			(ngc_time() + ngc_pos_ttl) : 0;
		/* Refresh when 1/4 or less of ngc_pos_ttl remains */
		ng->ng_refresh = ngc_enable ?
		    (ng->ng_expire - (ngc_pos_ttl / 4)) : 0;
	}

	if (NGC_INEXPQUEUE(ng)) {
		if (list_tail(expire_queue) != ng) {
			list_remove(expire_queue, ng);
			list_insert_tail(expire_queue, ng);
		}
	} else {
		NGC_SET(ng, NGC_FLAG_INEXPQUEUE);
		list_insert_tail(expire_queue, ng);
	}
}

/*
 * This parses the netgroup triples in ng->ng_result, storing them in
 * ng->ng_triples.  The process of parsing them overwrites at least some of the
 * white space, commas, and parentheses in ng_result so they are not usable
 * after this.  ng->ng_result must live as long as ng->ng_triples.
 */
static int
ngc_parse_triples(netgroup_t *ng)
{
	ns_ldap_entry_t *entry;
	char **attr;
	uint32_t i = 0;
	uint32_t entries = 0;

	VERIFY0(ng->ng_triplecnt);

	/* First, we need a count of nisNetgroupTriple attributes */
	for (entry = ng->ng_result->entry; entry != NULL; entry = entry->next) {
		entries++;
		for (attr = __ns_ldap_getAttr(entry, _N_TRIPLE);
		    attr != NULL && *attr != NULL; attr++) {
			i++;
		}
	}
#ifdef DEBUG
	syslog(LOG_DEBUG, "ngc_parse_triples parsing %u triples from "
	    "%u entries", i, entries);
#endif
	if (i == 0) {
		return (0);
	}

	/* Allocate the triples */
	ng->ng_triples = calloc(i, sizeof (*ng->ng_triples));
	if (ng->ng_triples == NULL) {
		ng->ng_triplecnt = 0;
		return (-1);
	}
	ng->ng_triplecnt = i;
	i = 0;

	/*
	 * Parse the triples. Parse errors lead to not all of the allocated
	 * slots being used.
	 */
	for (entry = ng->ng_result->entry; entry != NULL; entry = entry->next) {
		for (attr = __ns_ldap_getAttr(entry, _N_TRIPLE);
		    *attr != NULL; attr++) {
			ngc_triple_t *ngt = &ng->ng_triples[i];

			if (split_triple(*attr, &ngt->ngt_host,
			    &ngt->ngt_user, &ngt->ngt_domain) == 0) {
				i++;
				DTRACE_PROBE5(nss_ldap, netgroup__cache__triple,
				    ng->ng_name, ng, ngt->ngt_host,
				    ngt->ngt_user, ngt->ngt_domain);
			}
		}
	}
	ng->ng_triplecnt = i;

	return (0);
}

/*
 * Get a base10 number that is exactly `digits` long from the string at `*bufp`.
 * Verify it is between `min` and `max`, inclusive.
 *
 * On success `*valp` is updated with the value and `*bufp` is advanced by
 * `digits` characters.
 */
static int
parse_num(const char **bufp, int *valp, uint32_t digits, int min, int max)
{
	uint32_t i;
	int val = 0;
	const char *buf = *bufp;

	VERIFY3U(digits, >, 0);
	for (i = 0; i < digits; i++, buf++) {
		int newval;

		/*
		 * We avoid isdigit() and isdigit_l() because we are constrained
		 * by RFC 4517 to the ASCII digits, we don't have control over
		 * which locale is currently being used, and newlocale() could
		 * fail.
		 */
		if (*buf < '0' || *buf > '9') {
			return (-1);
		}
		newval = val * 10 + *buf - '0';
		if (newval < val) {
			return (-1);
		}
		val = newval;
	}
	if (val < min || val > max) {
		return (-1);
	}
	*valp = val;
	*bufp = buf;
	return (0);
}

#ifdef DEBUG
#define	FAILOFF ((uintptr_t)next - (uintptr_t)gtime + 1)
#define	DBG_PARSE_GENTIME_FAIL() \
	(void) fprintf(stderr, "%s:%d: parse failed at character %lu\n", \
	    __func__, __LINE__, FAILOFF); \
	(void) fprintf(stderr, "   %s\n", gtime); \
	(void) fprintf(stderr, "   %*s\n", FAILOFF, "^");
#else
#define	DBG_PARSE_GENTIME_FAIL()
#endif

/*
 * See RFC 4517 Section 3.3.13
 *
 * Tries to find an RFC 4517 compliant Generalized Time in gtime, returning via
 * *whenp the tenths of seconds since the epoch UTC.
 *
 * Times before the epoch are not supported.
 *
 * At first blush, it would seem that strptime(3C) should be able to handle this
 * task.  Sadly, that is not the case.  In particular, it does not handle
 * fractional seconds, does not document the support it has for offsets (%z),
 * and does not support two digit offsets.  The one-digit fractional part
 * specified by RFC 4517 is unlikely to be useful outside of this use case,
 * so fixing strptime() to be useful here is not reasonable.  Even absent the
 * fractional units issue, the optional components would force many trips
 * through strptime() trying to guess which format may be the right one.
 */
static int
parse_generalized_time(const char *gtime, uint64_t *whenp)
{
	const char *next;
	struct tm tm = { 0 };
	uint32_t frac_tenths = 0;
	int frac = 0;
	time_t secs;
	uint64_t tsecs;		/* tenths of a second */

	for (next = gtime; *next != '\0'; next++) {
		if (!isascii(*next)) {
			DBG_PARSE_GENTIME_FAIL();
			return (-1);
		}
	}
	next = gtime;

	/* Year, month, day, hour are required */
	if (parse_num(&next, &tm.tm_year, 4, 0, 9999) != 0 ||
	    parse_num(&next, &tm.tm_mon, 2, 1, 12) != 0 ||
	    parse_num(&next, &tm.tm_mday, 2, 1, 31) != 0 ||
	    parse_num(&next, &tm.tm_hour, 2, 0, 23) != 0) {
		DBG_PARSE_GENTIME_FAIL();
		return (-1);
	}

	/*
	 * Minutes and seconds are optional.  The meaning of the fractional part
	 * varies with its position: it may be a fraction of an hour, a minute,
	 * or a second.
	 */
	frac_tenths = 60 * 60;
	if (parse_num(&next, &tm.tm_min, 2, 0, 59) == 0) {
		frac_tenths = 60;
		if (parse_num(&next, &tm.tm_sec, 2, 0, 60) == 0) {
			frac_tenths = 1;
		}
	}

	/*
	 * (time_t) -1 is an error per timegm(3C); other negative times are
	 * unsupported because we don't realistically expect this to be used
	 * before 1970.  If time_t is signed 32-bits, it shouldn't pretend to
	 * parse time properly when the offset from the epoch no longer fits in
	 * 31 bits.
	 */
	tm.tm_year -= 1900;
	tm.tm_mon--;
	if ((secs = timegm(&tm)) < 0) {
#ifdef DEBUG
		(void) fprintf(stderr, "%s:%d: timegm failed for <%s>\n",
		    __func__, __LINE__, gtime);
#endif
		return (-1);
	}
	tsecs = 10 * (uint64_t)secs;

	if (*next == '.' || *next == ',') {
		next++;
		if (parse_num(&next, &frac, 1, 0, 9) != 0) {
			DBG_PARSE_GENTIME_FAIL();
			return (-1);
		}
		tsecs += frac_tenths * frac;
	}

	if (*next == '+' || *next == '-') {
		int hrs, mins = 0;
		int sign = *next == '+' ? -1 : 1;

		next++;
		/* Get offset hours */
		if (parse_num(&next, &hrs, 2, 0, 23) != 0) {
			DBG_PARSE_GENTIME_FAIL();
			return (-1);
		}
		/*
		 * Get offset minutes, which are optional in GeneralizedTime.
		 *
		 * There are three scenarios that may happen now:
		 *
		 * - parse_num() may find two digits that form a number in
		 *   [0, 59].  In that case, it will update mins, return
		 *   success, and advance the next pointer.
		 *
		 * - parse_num() may find that the next character is a nul
		 *   character.  This error is rightly ignored because minutes
		 *   are optional.  The next pointer still references a nul
		 *   character.
		 *
		 * - parse_num() may find an invalid value in the next two
		 *   characters.  In this case, it returns an error without
		 *   advancing the next pointer.  The nul character check that
		 *   follows will detect this situation, causing this function
		 *   to return an error.
		 */
		(void) parse_num(&next, &mins, 2, 0, 59);
		if (*next != '\0') {
			DBG_PARSE_GENTIME_FAIL();
			return (-1);
		}
		tsecs += 10 * sign * ((hrs * 60) + mins) * 60;
	} else if (*next != '\0' && strcmp(next, "Z") != 0) {
		DBG_PARSE_GENTIME_FAIL();
		return (-1);
	}

	*whenp = tsecs;

	return (0);
}

/*
 * Get the value of modifyTimestamp and return any valid value in the supplied
 * buffer.
 *
 * RFC 4512 section 3.4.4 defines modifyTimestamp as a GeneralizedTime.  RFC
 * 4517 section 3.3.13 specifies GeneralizedTime as an ISO 8601 time that
 * may or may not have a fractional component and may or may not have timezone
 * information.  The fractional component can be fractions of seconds, minutes,
 * or hours, depending on context.
 */
static uint64_t
get_modify_timestamp(ns_ldap_result_t *result)
{
	ns_ldap_entry_t *entry;
	char **attr;
	uint64_t when;

	for (entry = result->entry; entry != NULL; entry = entry->next) {
		attr = __ns_ldap_getAttr(entry, _N_MODIFYSTAMP);
		if (*attr == NULL) {
			continue;
		}
		if (parse_generalized_time(*attr, &when) == 0) {
			return (when);
		}
	}
	return (0);
}

static nss_status_t
ngc_ldap_search(const char *ngname, const char **attrs,
    ns_ldap_result_t **result)
{
	char			filter[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	ns_ldap_error_t		*error = NULL;
	int			rc;

	/* Escape special characters */
	if (_ldap_filter_name(name, ngname, sizeof (name)) != 0)
		return (NSS_NOTFOUND);
	/* Form "(&(objectClass=nisNetGroup)(cn=<name>))" */
	rc = snprintf(filter, sizeof (filter), _F_SETMEMBER, name);
	if (rc >= sizeof (filter) || rc < 0)
		return (NSS_NOTFOUND);

	/* Form "(&(%s)(cn=<name>))" - including literal %s */
	rc = snprintf(userdata, sizeof (userdata), _F_SETMEMBER_SSD, name);
	if (rc >= sizeof (userdata) || rc < 0) {
		return (NSS_NOTFOUND);
	}

	/* Perform the search */
	rc = __ns_ldap_list(_NETGROUP, filter, _merge_SSD_filter, attrs, NULL,
	    0, result, &error, NULL, userdata);
	if (error != NULL && switch_err(rc, error) == NSS_TRYAGAIN) {
		/*
		 * Return NSS_TRYAGAIN (rather than looping here) so that the
		 * nscd or the name service switch frontend can manage the
		 * retries.
		 */
		(void) __ns_ldap_freeError(&error);
		return (NSS_TRYAGAIN);
	}
	(void) __ns_ldap_freeError(&error);
	if (rc != NS_LDAP_SUCCESS) {
		return (NSS_NOTFOUND);
	}

	return (NSS_SUCCESS);
}

/*
 * Get the specified netgroup from LDAP.  Only to be called by netgroup_get() or
 * ng_refresh();
 *
 * On successful read from ldap, the netgroup is added to the cache and a held
 * reference is returned.  If the cache is enabled, a lookup that returns
 * NSS_NOTFOUND will lead to a negative cache entry.
 */
static nss_status_t
ngc_get_from_ldap(const char *ngname, netgroup_t **ngp)
{
	char			filter[SEARCHFILTERLEN];
	char			name[SEARCHFILTERLEN];
	char			userdata[SEARCHFILTERLEN];
	ns_ldap_result_t	*result = NULL;
	ns_ldap_error_t		*error = NULL;
	int			rc;
	nss_status_t		status;
	netgroup_t		*ng, *ngc;

	VERIFY(!MUTEX_HELD(&ngc_lock));

	status = ngc_ldap_search(ngname, netgrent_attrs, &result);
	if (status == NSS_NOTFOUND && ngc_enable && ngc_neg_ttl > 0) {
		/* Add a negative entry, being careful not to allow too many */
		mutex_enter(&ngc_lock);
		if (ngc_neg_count >= ngc_neg_max) {
			mutex_exit(&ngc_lock);
			return (NSS_NOTFOUND);
		}
		ngc_neg_count++;
		mutex_exit(&ngc_lock);

		if ((ng = ngc_alloc(ngname)) == NULL) {
			return (status);
		}
		NGC_SET(ng, NGC_FLAG_NEGATIVE | NGC_FLAG_INCACHE);
	} else if (status != NSS_SUCCESS) {
		return (status);
	} else {
		/* We got a result, cache it. */
		if ((ng = ngc_alloc(ngname)) == NULL) {
			int err = errno;
			(void) __ns_ldap_freeResult(&result);
			errno = err;
			return (NSS_ERROR);
		}

		ng->ng_result = result;
		if (ngc_parse_triples(ng) != 0) {
			return (NSS_ERROR);
		}

		ng->ng_lastchange = get_modify_timestamp(result);

		NGC_SET(ng, NGC_FLAG_INCACHE);
		*ngp = ng;
	}

	mutex_enter(&ngc_lock);

	if ((ngc = avl_find(&ngc_cache, ng, NULL)) != NULL) {
		/* Someone else just slipped one in. This one is newer? */
		DTRACE_PROBE3(nss_ldap, netgroup__cache__add__collision,
		    ng->ng_name, ng, ngc);
		ngc_rele_locked(ngc);
	}

	ngc_set_expire_locked(ng);
	avl_add(&ngc_cache, ng);

	status = NGC_NEGATIVE(ng) ? NSS_NOTFOUND : NSS_SUCCESS;
	if (status == NSS_SUCCESS) {
		ngc_hold_locked(ng);
		*ngp = ng;
	}

	mutex_exit(&ngc_lock);

	DTRACE_PROBE3(nss_ldap, netgroup__cache__add, ng->ng_name, ng, status);
	return (status);
}

static void
ngc_queue_refresh_locked(netgroup_t *ng)
{
	VERIFY(MUTEX_HELD(&ngc_lock));

	DTRACE_PROBE2(nss_ldap, netgroup__warmer__enqueue, ng->ng_name, ng);

	NGC_SET(ng, NGC_FLAG_INWARMER);
	list_insert_tail(&ngc_warm_queue, ng);

	VERIFY0(cond_signal(&ngc_warm_cv));
}

/*
 * Get the specified netgroup from the cache.
 */
static nss_status_t
netgroup_get(const char *name, netgroup_t **ngp)
{
	netgroup_t *ng;
	netgroup_t find = { .ng_name = name };
	uint32_t now;
	nss_status_t status;

	mutex_enter(&ngc_lock);

	if (!ngc_initialized) {
		/*
		 * A poorly behaved application may be trying lookups while
		 * simultaneously calling dlclose().
		 */
		mutex_exit(&ngc_lock);
		errno = ENOSYS;
		return (NSS_ERROR);
	}

	ng = avl_find(&ngc_cache, &find, NULL);
	if (ng == NULL) {
		/* not in cache, get it from LDAP */
		mutex_exit(&ngc_lock);
		return (ngc_get_from_ldap(name, ngp));
	}
	VERIFY(NGC_INCACHE(ng));

	/*
	 * If the netgroup has expired, get it out of the cache and get it fresh
	 * from LDAP.
	 */
	now = ngc_time();
	if (ng->ng_expire <= now) {
		ngc_dispose_locked(ng);
		mutex_exit(&ngc_lock);
		return (ngc_get_from_ldap(name, ngp));
	}

	/*
	 * If a refresh is needed, grab one ref for the return and another for
	 * the refresh.  Set the refresh time forward so that we don't end up
	 * with concurrent refreshes.
	 */
	if (ngc_enable && ng->ng_refresh < now && !NGC_INWARMER(ng) &&
	    !NGC_NEGATIVE(ng)) {
		ng->ng_refresh = ng->ng_expire;
		ngc_hold_locked(ng);
		ngc_queue_refresh_locked(ng);
	}
	status = NGC_NEGATIVE(ng) ? NSS_NOTFOUND : NSS_SUCCESS;
	if (status == NSS_SUCCESS) {
		ngc_hold_locked(ng);
		*ngp = ng;
	}
	mutex_exit(&ngc_lock);

	DTRACE_PROBE3(nss_ldap, netgroup__get__from__cache, ng->ng_name, ng,
	    status);
	return (status);
}

/*
 * Dispose of all expired netgroups that are in the cache.
 */
static void
ngc_reap_locked(void)
{
	list_t *queues[] = {
	    &ngc_neg_expire_queue,
	    &ngc_pos_expire_queue,
	};
	netgroup_t *ng;
	uint32_t now = ngc_time();
	uint32_t i;

	VERIFY(MUTEX_HELD(&ngc_lock));

	for (i = 0; i < ARRAY_SIZE(queues); i++) {
		for (ng = list_head(queues[i]);
		    ng != NULL && now >= ng->ng_expire;
		    ng = list_head(queues[i])) {
			DTRACE_PROBE3(nss_ldap, netgroup__reap, ng->ng_name, ng,
			    queues[i]);
			VERIFY(NGC_INCACHE(ng));
			ngc_dispose_locked(ng);
			VERIFY3P(list_head(queues[i]), !=, ng);
		}
	}
}

/*
 * This worker thread picks up netgroups that need to be refreshed from
 * ngc_warm_queue.  It also wakes up from time to time (ngc_reap_interval) to
 * clear cruft from the cache.
 *
 * Several things can happen to a netgroup that is in this queue.
 *
 * - There could be a delay in queue processing and the netgroup may have
 *   already been evicted from the cache.  In this case it is not refreshed.
 * - The LDAP server may not provide a modifyTimestamp attr.  In this case, the
 *   netgroup will be fully reloaded on demand.
 * - Most commonly, the current modifyTimestamp value matches the value found in
 *   the cache.  The expire and refresh times are updated as though the entire
 *   netgroup was just loaded.
 * - A newer modifyTimestamp may be seen.  This causes the netgroup to be
 *   expired from the cache.
 *
 * As each netgroup was placed in ngc_warm_queue, a reference was taken.  That
 * reference is released as this thread processes the renewal.
 */
static void *
ngc_warmer(void *data __unused)
{
	netgroup_t		*ng;
	netgroup_t		*newng;
	nss_status_t		status;
	ns_ldap_result_t	*result = NULL;
	avl_index_t		where;
	uint64_t		lastchange;
	timestruc_t		reltime;
	int			err;

	mutex_enter(&ngc_lock);

	reltime.tv_sec = ngc_reap_interval;
	reltime.tv_nsec = 0;

	for (;;) {
		err = cond_reltimedwait(&ngc_warm_cv, &ngc_lock, &reltime);
		VERIFY(err == 0 || err == ETIME || err == EINTR);

		if (ngc_warmer_die) {
			mutex_exit(&ngc_lock);
			break;
		}

		/*
		 * First, do a little housekeeping.
		 */
		ngc_reap_locked();

		ng = list_remove_head(&ngc_warm_queue);
		if (ng != NULL) {
			NGC_CLEAR(ng, NGC_FLAG_INWARMER);
		}

		if (ng == NULL) {
			/* Timeout or interrupted by a signal */
			continue;
		}

		mutex_exit(&ngc_lock);
		status = ngc_ldap_search(ng->ng_name, netgrent_stamp, &result);
		mutex_enter(&ngc_lock);
		if (status != NSS_SUCCESS) {
			/*
			 * Either the server does not support modifyTimestamp or
			 * something worse happened.  Since we aren't certain of
			 * the reason, do not evict it from the cache.
			 */
			DTRACE_PROBE3(nss_ldap, netgroup__warmer__ldap__fail,
			    ng->ng_name, ng, status);
			ngc_rele_locked(ng);
			continue;
		}
		lastchange = get_modify_timestamp(result);
		(void) __ns_ldap_freeResult(&result);
		if (lastchange == 0) {
			DTRACE_PROBE2(nss_ldap, netgroup__warmer__no__stamp,
			    ng->ng_name, ng);
			ngc_rele_locked(ng);
			continue;
		}

		if (lastchange == ng->ng_lastchange && !NGC_INCACHE(ng) &&
		    avl_find(&ngc_cache, ng, &where) == NULL) {
			/*
			 * The netgroup has not changed, but it has been
			 * expired.  Rip it from the jaws of death.
			 */

			DTRACE_PROBE2(nss_ldap, netgroup__warmer__resurrection,
			    ng->ng_name, ng);
			list_remove(&ngc_graveyard, ng);
			avl_insert(&ngc_cache, ng, where);
			NGC_SET(ng, NGC_FLAG_INCACHE);
			ngc_set_expire_locked(ng);

			ngc_rele_locked(ng);
			continue;
		}
		if (lastchange == ng->ng_lastchange) {
			/* Netgroup has not changed, move expiry ahead */

			DTRACE_PROBE2(nss_ldap, netgroup__warmer__renewal,
			    ng->ng_name, ng);
			ngc_set_expire_locked(ng);
			ngc_rele_locked(ng);
			continue;
		}

		/*
		 * The netgroup has been changed. Expire the current netgroup
		 * then fetch a fresh copy.  That order is important so that the
		 * netgroup is not in the cache when ngc_get_from_ldap() tries
		 * to add the fresh copy.  Keep the hold on ng until after
		 * ngc_get_from_ldap() completes to ensure that ng->ng_name does
		 * not get freed while it is still needed.
		 */
		DTRACE_PROBE2(nss_ldap, netgroup__warmer__expire, ng->ng_name,
		    ng);
		ngc_dispose_locked(ng);

		mutex_exit(&ngc_lock);
		status = ngc_get_from_ldap(ng->ng_name, &newng);
		mutex_enter(&ngc_lock);

		if (status == NSS_SUCCESS) {
			DTRACE_PROBE3(nss_ldap,
			    netgroup__warmer__reload__success, newng->ng_name,
			    newng, ng);
			ngc_rele_locked(newng);
		} else {
			DTRACE_PROBE3(nss_ldap, netgroup__warmer__reload__fail,
			    ng->ng_name, ng, status);
		}
		ngc_rele_locked(ng);
	}

	return (NULL);
}

/*
 * Netgroup table management.  This is used during a query to handle nested
 * netgroups while avoiding loops.
 */

static hash_t
get_hash(const char *s)
{
	unsigned int sum = 0;
	unsigned int i;

	for (i = 0; s[i] != '\0'; i++)
		sum += ((unsigned char *)s)[i];

	return ((sum + i) % N_HASH);
}

/*
 * Adds a name to the netgroup table
 *
 * Returns
 *	0 if successfully added or already present
 *	-1 if memory allocation error or NULL netgroup_table_t
 *         from caller.
 */

static int
add_netgroup_name(const char *name, netgroup_table_t *tab)
{
	hash_t		h;
	netgroup_name_t	*ng;
	netgroup_name_t	*ng_new;

	if (tab == NULL) {
		/*
		 * Should never happen. But if it does,
		 * that's an error condition.
		 */
		return (-1);
	}
	if (name == NULL || *name == '\0') {
		/* no name to add means success */
		return (0);
	}

	h = get_hash(name);
	ng = tab->ngt_hash_list[h];

	while (ng != NULL) {
		if (strcmp(name, ng->ngn_name) == 0)
			break;
		ng = ng->ngn_next_hash;
	}

	if (ng == NULL) {
		ng_new = (netgroup_name_t *)
		    calloc(1, sizeof (netgroup_name_t));
		if (ng_new == NULL)
			return (-1);
		ng_new->ngn_name = strdup(name);
		if (ng_new->ngn_name == NULL) {
			free(ng_new);
			return (-1);
		}
		ng_new->ngn_next_hash = tab->ngt_hash_list[h];
		tab->ngt_hash_list[h] = ng_new;
		ng_new->ngn_next = tab->ngt_to_do;
		tab->ngt_to_do = ng_new;
	}
	return (0);
}

static netgroup_name_t *
get_next_netgroup(netgroup_table_t *tab)
{
	netgroup_name_t *ng;

	if (tab == NULL)
		return (NULL);

	ng = tab->ngt_to_do;
	if (ng != NULL) {
		tab->ngt_to_do = ng->ngn_next;
		ng->ngn_next = tab->ngt_done;
		tab->ngt_done = ng;
	}
	return (ng);
}

static void
free_netgroup_table(netgroup_table_t *tab)
{
	netgroup_name_t *ng, *next;

	if (tab == NULL)
		return;

	for (ng = tab->ngt_to_do; ng != NULL; ng = next) {
		if (ng->ngn_name != NULL)
			free(ng->ngn_name);
		next = ng->ngn_next;
		free(ng);
	}

	for (ng = tab->ngt_done; ng != NULL; ng = next) {
		if (ng->ngn_name != NULL)
			free(ng->ngn_name);
		next = ng->ngn_next;
		free(ng);
	}
	(void) memset(tab, 0, sizeof (*tab));
}

/*
 * domain comparing routine
 *	n1: See if n1 is n2 or an ancestor of it
 *	n2: (in string terms, n1 is a suffix of n2)
 * Returns ZERO for success, -1 for failure.
 */
static int
domcmp(const char *n1, const char *n2)
{
#define	PASS	0
#define	FAIL	-1

	size_t		l1, l2;

	if ((n1 == NULL) || (n2 == NULL))
		return (FAIL);

	l1 = strlen(n1);
	l2 = strlen(n2);

	/* Turn a blind eye to the presence or absence of trailing periods */
	if (l1 != 0 && n1[l1 - 1] == '.') {
		--l1;
	}
	if (l2 != 0 && n2[l2 - 1] == '.') {
		--l2;
	}
	if (l1 > l2) {		/* Can't be a suffix */
		return (FAIL);
	} else if (l1 == 0) {	/* Trivially a suffix; */
				/* (do we want this case?) */
		return (PASS);
	}
	/* So 0 < l1 <= l2 */
	if (l1 < l2 && n2[l2 - l1 - 1] != '.') {
		return (FAIL);
	}
	if (strncasecmp(n1, &n2[l2 - l1], l1) == 0) {
		return (PASS);
	} else {
		return (FAIL);
	}
}

static int
split_triple(char *triple, const char **hostname, const char **username,
    const char **domain)
{
	int	i, syntax_err;
	char	*splittriple[3];
	char	*p = triple;

#ifdef	DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: split_triple]\n");
#endif	/* DEBUG */

	if (triple == NULL)
		return (-1);

	p++;
	syntax_err = 0;
	for (i = 0; i < 3; i++) {
		char	*start;
		char	*limit;
		const char	*terminators = ",) \t";

		if (i == 2) {
			/* Don't allow comma */
			terminators++;
		}
		while (isspace(*p)) {
			p++;
		}
		start = p;
		limit = strpbrk(start, terminators);
		if (limit == 0) {
			syntax_err++;
			break;
		}
		p = limit;
		while (isspace(*p)) {
			p++;
		}
		if (*p == terminators[0]) {
			/*
			 * Successfully parsed this name and
			 * the separator after it (comma or
			 * right paren); leave p ready for
			 * next parse.
			 */
			p++;
			if (start == limit) {
				/* Wildcard */
				splittriple[i] = NULL;
			} else {
				*limit = '\0';
				splittriple[i] = start;
			}
		} else {
			syntax_err++;
			break;
		}
	}

	if (syntax_err != 0)
		return (-1);

	*hostname = splittriple[0];
	*username = splittriple[1];
	*domain = splittriple[2];

	return (0);
}

/*
 * Test membership in triple
 *	return 0 = no match
 *	return 1 = match
 */

static int
match_triple(struct nss_innetgr_args *ia, netgroup_t *ng)
{
	int	ndomains;
	char	**pdomains;
	int	nhost;
	char	**phost;
	int	nusers;
	char	**pusers;
	const char *tuser, *thost, *tdomain;
	uint32_t i, trip;
	char	*pusers0 = NULL, *phost0 = NULL;

	nhost = ia->arg[NSS_NETGR_MACHINE].argc;
	phost = (char **)ia->arg[NSS_NETGR_MACHINE].argv;
	if (phost == NULL || *phost == NULL) {
		nhost = 0;
	} else {
		phost0 = phost[0];
#ifdef DEBUG
		syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
		    "entering with host: %s", phost0 ? phost0 : "");
#endif
	}
	nusers = ia->arg[NSS_NETGR_USER].argc;
	pusers = (char **)ia->arg[NSS_NETGR_USER].argv;
	if (pusers == NULL || *pusers == NULL) {
		nusers = 0;
	} else {
		pusers0 = pusers[0];
#ifdef DEBUG
		syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
		    "entering with user: %s", pusers0 ? pusers0 : "");
#endif
	}
	ndomains = ia->arg[NSS_NETGR_DOMAIN].argc;
	pdomains = (char **)ia->arg[NSS_NETGR_DOMAIN].argv;
	if (pdomains == NULL || *pdomains == NULL)
		ndomains = 0;
#ifdef DEBUG
	else
		syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
		    "entering with domain: %s", pdomains[0] ? pdomains[0] : "");
#endif

#ifdef DEBUG
	syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
	    "(nusers: %d, nhost:%d, ndomains: %d)",
	    nusers, nhost, ndomains);
#endif

	/* Special cases for speedup */
	if (nusers == 1 && nhost == 0 && ndomains == 0 && pusers0 != NULL) {
		/* Special case for finding a single user in a netgroup */
		for (trip = 0; trip < ng->ng_triplecnt; trip++) {
			ngc_triple_t *ngt = &ng->ng_triples[trip];

#ifdef DEBUG
			syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
			    "current user is: %s", ngt->ngt_user);
#endif
			/* if user part is null, then treat as wildcard */
			if (ngt->ngt_user == NULL) {
				return (1);
			}

			/* do actual compare */
			if (strcmp(pusers0, ngt->ngt_user) == 0) {
				return (1);
			}
		}
	} else if (nusers == 0 && nhost == 1 && ndomains == 0 &&
	    phost0 != NULL) {
		/* Special case for finding a single host in a netgroup */
		for (trip = 0; trip < ng->ng_triplecnt; trip++) {
			ngc_triple_t *ngt = &ng->ng_triples[trip];


#ifdef DEBUG
			syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
			    "current host is: %s", ngt->ngt_host);
#endif

			/* if host part is null, then treat as wildcard */
			if (ngt->ngt_host == NULL) {
				return (1);
			}

			/* do actual compare */
			if (strcasecmp(phost0, ngt->ngt_host) == 0) {
				return (1);
			}
		}
	} else {
		for (trip = 0; trip < ng->ng_triplecnt; trip++) {
			thost = ng->ng_triples[trip].ngt_host;
			tuser = ng->ng_triples[trip].ngt_user;
			tdomain = ng->ng_triples[trip].ngt_domain;
#ifdef DEBUG
			syslog(LOG_DEBUG, "nss_ldap: match_triple_entry: "
			    "triple is: (%s,%s,%s)", thost, tuser, tdomain);
#endif
			if (thost != NULL && *thost != '\0' && nhost != 0) {
				for (i = 0; i < nhost; i++)
					if (strcasecmp(thost, phost[i]) == 0)
						break;
				if (i == nhost)
					continue;
			}
			if (tuser != NULL && *tuser != '\0' && nusers != 0) {
				for (i = 0; i < nusers; i++)
					if (strcmp(tuser, pusers[i]) == 0)
						break;
				if (i == nusers)
					continue;
			}
			if (tdomain != NULL && *tdomain != '\0' &&
			    ndomains != 0) {
				for (i = 0; i < ndomains; i++)
					if (domcmp(tdomain, pdomains[i]) == 0)
						break;
				if (i == ndomains)
					continue;
			}
			return (1);
		}
	}

	return (0);
}

static int
add_netgroup_member_entry(ns_ldap_entry_t *entry, netgroup_table_t *tab)
{
	char		**attrs;
	char		**a;

	attrs = __ns_ldap_getAttr(entry, _N_MEMBER);
	if (attrs == NULL || *attrs == NULL)
		return (0);

	for (a = attrs; *a != NULL; a++) {}

	do {
		a--;
		if (add_netgroup_name(*a, tab) != 0)
			return (-1);
	} while (a > attrs);
	return (0);
}

static int
add_netgroup_member(ns_ldap_result_t *result, netgroup_table_t *tab)
{
	ns_ldap_entry_t	*entry;
	int		ret = 0;

	for (entry = result->entry; entry != NULL; entry = entry->next) {
		ret = add_netgroup_member_entry(entry, tab);
		if (ret != 0)
			break;
	}
	return (ret);
}

/*
 * top_down_search checks only checks the netgroup specified in netgrname
 */
static nss_status_t
top_down_search(struct nss_innetgr_args *ia, char *netgrname)
{
	netgroup_table_t tab;
	netgroup_name_t *ngn;
	netgroup_t *ng;
	int rc;
	int serrno;

	(void) memset(&tab, 0, sizeof (tab));

	if (add_netgroup_name(netgrname, &tab) != 0)
		return ((nss_status_t)NSS_NOTFOUND);

	while ((ngn = get_next_netgroup(&tab)) != NULL) {
#ifdef DEBUG
		syslog(LOG_DEBUG, "nss_ldap: top_down_search: netgroup  loop "
		    "(ngn->ngn_name: %s)",
		    ngn->ngn_name ? ngn->ngn_name : "null !");
#endif
		switch (netgroup_get(ngn->ngn_name, &ng)) {
		case NSS_SUCCESS:
			break;
		case NSS_TRYAGAIN:
			free_netgroup_table(&tab);
			return (NSS_TRYAGAIN);
		case NSS_ERROR:
			serrno = errno;
			free_netgroup_table(&tab);
			errno = serrno;
			return (NSS_ERROR);
		default:
			continue;
		}

		if (match_triple(ia, ng) == 1) {
			/* We found a match */
			ia->status = NSS_NETGR_FOUND;
			free_netgroup_table(&tab);
			netgroup_rele(ng);
#ifdef DEBUG
			syslog(LOG_DEBUG, "nss_ldap: top_down_search: "
			    "found match\n");
#endif
			return (NSS_SUCCESS);
		}

		rc = add_netgroup_member(ng->ng_result, &tab);
		netgroup_rele(ng);
		if (rc != 0) {
			break;
		}
	}

	free_netgroup_table(&tab);
	return (NSS_NOTFOUND);
}

/*
 * __netgr_in checks only checks the netgroup specified in ngroup
 */
static nss_status_t
__netgr_in(void *a, char *netgrname)
{
	struct nss_innetgr_args	*ia = (struct nss_innetgr_args *)a;
	nss_status_t		status = NSS_NOTFOUND;

#ifdef DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: netgr_in]\n");
	(void) fprintf(stderr, "\tmachine: argc[%d]='%s' user: "
	    "argc[%d]='%s',\n\tdomain:argc[%d]='%s' "
	    "netgroup: argc[%d]='%s'\n",
	    NSS_NETGR_MACHINE,
	    PRINT_VAL(ia->arg[NSS_NETGR_MACHINE]),
	    NSS_NETGR_USER,
	    PRINT_VAL(ia->arg[NSS_NETGR_USER]),
	    NSS_NETGR_DOMAIN,
	    PRINT_VAL(ia->arg[NSS_NETGR_DOMAIN]),
	    NSS_NETGR_N,
	    PRINT_VAL(ia->arg[NSS_NETGR_N]));
	(void) fprintf(stderr, "\tgroups='%s'\n", netgrname);
#endif	/* DEBUG */

	ia->status = NSS_NETGR_NO;

	if (netgrname == NULL)
		return (status);

	status = top_down_search(ia, netgrname);
	DTRACE_PROBE5(nss_ldap, innetgr, netgrname,
	    PRINT_VAL(ia->arg[NSS_NETGR_MACHINE]),
	    PRINT_VAL(ia->arg[NSS_NETGR_USER]),
	    PRINT_VAL(ia->arg[NSS_NETGR_DOMAIN]), status);
	return (status);
}

/*ARGSUSED0*/
static nss_status_t
netgr_in(ldap_backend_ptr be, void *a)
{
	struct nss_innetgr_args	*ia = (struct nss_innetgr_args *)a;
	int	i;
	nss_status_t	rc = (nss_status_t)NSS_NOTFOUND;

	ia->status = NSS_NETGR_NO;

	for (i = 0; i < ia->groups.argc; i++) {
		rc = __netgr_in(a, ia->groups.argv[i]);
		if (ia->status == NSS_NETGR_FOUND)
			return (NSS_SUCCESS);
	}
	return (rc);
}

static void
free_getnetgrent_cookie(getnetgrent_cookie_t **cookie)
{
	getnetgrent_cookie_t *p = *cookie;

#ifdef DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: free_getnetgrent_cookie]\n");
#endif	/* DEBUG */

	if (p == NULL)
		return;

	if (p->gnc_netgroup != NULL) {
		netgroup_rele(p->gnc_netgroup);
	}
	free_netgroup_table(&p->gnc_tab);
	free(p->gnc_name);
	free(p);
	*cookie = NULL;
}

/*ARGSUSED1*/
static nss_status_t
getnetgr_ldap_endent(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: getnetgr_ldap_endent]\n");
#endif	/* DEBUG */

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);

	return ((nss_status_t)NSS_NOTFOUND);
}


/*ARGSUSED1*/
static nss_status_t
getnetgr_ldap_destr(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: getnetgr_ldap_destr]\n");
#endif	/* DEBUG */

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);
	free(be);

	return ((nss_status_t)NSS_NOTFOUND);
}

/*
 * Copies results from a buffer that may be about to be freed into a long-lived
 * general-purpose buffer.
 *
 * val		 IN: The return value that needs to be copied.
 *
 * *bufferp	 IN: On the first call of this function for a particular nss
 *		     call, this should be the address of `buffer` element of a
 *		     nss_getnetgrent_args structure (`args`).  On subsequent
 *		     calls, it should be the value that was returned by
 *		     reference from the previous call.  Do not pass
 *		     `&args->buffer`, rather pass a reference to a copy of
 *		     `&args->buffer`.
 *		OUT: Advanced to the next unused space in args->buffer.
 *
 * *leftp	 IN: The amount of space in `args->buffer` that remains unused
 *		     and available for copying `val` into `args->buffer`.
 *		     The first call should pass a reference to a copy of
 *		     `args->buflen` and subsequent calls should use the value
 *		     returned by the previous call.
 *		OUT: The amount of space that remains after copying `val`.
 *
 * *retbufp	OUT: Will be updated to reference the location in args->buffer
 *		     that contains a copy of val.  Typically will be one of
 *		     args->retp[].
 *
 * After the following calls (plus error checking of function returns)
 *
 *   char *buf = args->result;
 *   size_t left = args->buflen;
 *   set_retbuf("host", &buf, &left, &args->retp[NSS_NETGR_MACHINE]);
 *   set_retbuf("user", &buf, &left, &args->retp[NSS_NETGR_USER]);
 *   set_retbuf("domain", &buf, &left, &args->retp[NSS_NETGR_DOMAIN]);
 *
 * `args` looks like:
 *
 *  buffer = "host\0user\0domain\0"
 *	      ^     ^     ^
 *	      |     |     retp[NSS_NETGR_DOMAIN]
 *	      |     retp[NSS_NETGR_USER]
 *	      retp[NSS_NETGR_HOST]
 */
static int
set_retbuf(const char *val, char **bufferp, size_t *leftp, char **retbufp)
{
	char *buffer = *bufferp;
	size_t left = *leftp;
	size_t len;

	if (val == NULL) {
		*retbufp = NULL;
		return (0);
	}
	len = strlcpy(buffer, val, left);
	if (len >= left) {
		return (-1);
	}
	*retbufp = buffer;
	*bufferp = buffer + len;
	*leftp = left - len;
	return (0);
}

static nss_status_t
getnetgr_ldap_getent(ldap_backend_ptr be, void *a)
{
	struct nss_getnetgrent_args	*args;
	getnetgrent_cookie_t	*p;
	nss_status_t		status = NSS_SUCCESS;
	netgroup_name_t		*ngn;
	int			ret;
	ns_ldap_result_t	*results = NULL;

#ifdef	DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: getnetgr_ldap_getent]\n");
#endif	/* DEBUG */

	args = (struct nss_getnetgrent_args *)a;

	args->status = NSS_NETGR_NO;

	p = (getnetgrent_cookie_t *)be->netgroup_cookie;
	if (p == NULL) {
		return ((nss_status_t)NSS_SUCCESS);
	}

	for (;;) {
		/*
		 * Search through each netgroup consecutively: only search
		 * next netgroup when results from previous netgroup are
		 * processed.
		 * Needed for nested netgroup (memberNisNetgroup attributes).
		 */
		if (p->gnc_netgroup == NULL) {
			if ((ngn = get_next_netgroup(&p->gnc_tab)) == NULL) {
				/* No more netgroups to process */
#ifdef DEBUG
				syslog(LOG_DEBUG, "nss_ldap: "
				    "getnetgr_ldap_getent: no more netgroup "
				    "to process.\n");
#endif
				break;		/* from loop */
			}

			switch (netgroup_get(ngn->ngn_name, &p->gnc_netgroup)) {
			case NSS_SUCCESS:
				break;		/* from switch */
			case NSS_TRYAGAIN:
				return (NSS_TRYAGAIN);
			default:
				/*
				 * Likely a nested netgroup that doesn't exist,
				 * but there may be more to try.
				 */
				continue;
			}

			p->gnc_entry = NULL;
		}

		results = p->gnc_netgroup->ng_result;

		/* Empty or missing netgroup */
		if (results == NULL) {
			continue;
		}

		if (p->gnc_entry == NULL) {
			p->gnc_entry = results->entry;
			if (p->gnc_entry == NULL) {
				continue;
			}
		}

		if (p->gnc_curtriple < p->gnc_netgroup->ng_triplecnt) {
			ngc_triple_t *ngt;
			char *buffer = args->buffer;
			size_t left = args->buflen;

			ngt = &p->gnc_netgroup->ng_triples[p->gnc_curtriple];
			p->gnc_curtriple++;

			/*
			 * The triple (ngt) may be freed before args->retp[] are
			 * consumed.  Copy the components from the cache into
			 * args->buffer.
			 */
			if (set_retbuf(ngt->ngt_host, &buffer, &left,
			    &args->retp[NSS_NETGR_MACHINE]) != 0 ||
			    set_retbuf(ngt->ngt_user, &buffer, &left,
			    &args->retp[NSS_NETGR_USER]) != 0 ||
			    set_retbuf(ngt->ngt_domain, &buffer, &left,
			    &args->retp[NSS_NETGR_DOMAIN]) != 0) {
				status = NSS_STR_PARSE_ERANGE;
				break;
			}
			args->status = NSS_NETGR_FOUND;

#ifdef DEBUG
			syslog(LOG_DEBUG, "nss_ldap: getnetgr_ldap_getent: "
			    "found triple (%s,%s,%s), %d more to process",
			    args->retp[NSS_NETGR_MACHINE] ?
			    args->retp[NSS_NETGR_MACHINE] : "",
			    args->retp[NSS_NETGR_USER] ?
			    args->retp[NSS_NETGR_USER] : "",
			    args->retp[NSS_NETGR_DOMAIN] ?
			    args->retp[NSS_NETGR_DOMAIN] : "",
			    p->gnc_netgroup->ng_triplecnt - p->gnc_curtriple);
#endif
			break;
		}

		/* Despite its name, this adds all members on this entry. */
		if (add_netgroup_member_entry(p->gnc_entry, &p->gnc_tab) != 0) {
			args->status = NSS_NETGR_NO;
			break;
		}

		p->gnc_entry = p->gnc_entry->next;
		if (p->gnc_entry == NULL) {
			netgroup_rele(p->gnc_netgroup);
			p->gnc_netgroup = NULL;
			p->gnc_curtriple = 0;
		}
	}

	return (status);
}

static ldap_backend_op_t getnetgroup_ops[] = {
	getnetgr_ldap_destr,
	getnetgr_ldap_endent,
	NULL,
	getnetgr_ldap_getent,
};

/*
 * setnetgrent() backend, at least for non-nscd case.
 */
static nss_status_t
netgr_set(ldap_backend_ptr be, void *a)
{
	struct nss_setnetgrent_args	*args =
	    (struct nss_setnetgrent_args *)a;
	ldap_backend_ptr		get_be;
	getnetgrent_cookie_t		*p;

#ifdef DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: netgr_set]\n");
	(void) fprintf(stderr,
	    "\targs->netgroup: %s\n", ISNULL(args->netgroup));
#endif /* DEBUG */

	if (args->netgroup == NULL)
		return ((nss_status_t)NSS_NOTFOUND);

	free_getnetgrent_cookie((getnetgrent_cookie_t **)&be->netgroup_cookie);
	p = (getnetgrent_cookie_t *)calloc(1, sizeof (getnetgrent_cookie_t));
	if (p == NULL)
		return ((nss_status_t)NSS_NOTFOUND);
	p->gnc_name = strdup(args->netgroup);
	if (p->gnc_name == NULL) {
		free(p);
		return ((nss_status_t)NSS_NOTFOUND);
	}
	if (add_netgroup_name(args->netgroup, &p->gnc_tab) == -1) {
		free_getnetgrent_cookie(&p);
		return ((nss_status_t)NSS_NOTFOUND);
	}

	/* now allocate and return iteration backend structure */
	if ((get_be = (ldap_backend_ptr)malloc(sizeof (*get_be))) == NULL)
		return (NSS_UNAVAIL);
	get_be->ops = getnetgroup_ops;
	get_be->nops = sizeof (getnetgroup_ops) / sizeof (getnetgroup_ops[0]);
	get_be->tablename = NULL;
	get_be->attrs = netgrent_attrs;
	get_be->result = NULL;
	get_be->ldapobj2str = NULL;
	get_be->setcalled = 1;
	get_be->filter = NULL;
	get_be->toglue = NULL;
	get_be->enumcookie = NULL;
	get_be->netgroup_cookie = p;
	args->iterator = (nss_backend_t *)get_be;

	return (NSS_SUCCESS);
}

/*
 * Initialization and configuration
 */

static int
ngc_compare(const void *l, const void *r)
{
	const netgroup_t *ngl = l, *ngr = r;
	int ret;

	ret = strcmp(ngl->ng_name, ngr->ng_name);
	if (ret < 0)
		return (-1);
	if (ret > 0)
		return (1);
	return (0);
}

static int
yntoi(const char *yorn, int minval __unused, int maxval __unused,
    int *retval, char *errbuf, size_t errbufsz)
{
	if (strcasecmp(yorn, "yes") == 0) {
		*retval = 1;
		return (0);
	}
	if (strcasecmp(yorn, "no") == 0) {
		*retval = 0;
		return (0);
	}
	(void) snprintf(errbuf, errbufsz,
	    "invalid value '%s': expected 'yes' or 'no'", yorn);
	return (-1);
}

static int
safestrtoi(const char *str, int minval, int maxval, int *retval,
    char *errbuf, size_t errbufsz)
{
	long val;
	char *end;

	errno = 0;
	val = strtol(str, &end, 10);
	if (errno != 0 || *end != '\0' || val < minval || val > maxval) {
		(void) snprintf(errbuf, errbufsz,
		    "invalid value '%s': expected integer between %d and %d",
		    str, minval, maxval);
		return (-1);
	}
	*retval = (int)val;
	return (0);
}

/*
 * nscd does not provide us with the config or an easy way to get it.  We'll
 * fetch it ourselves.
 */
static void
read_nscd_conf(void)
{
	const int week = 60 * 60 * 24 * 7;
	struct {
		char *key;
		int *valp;
		int defval;
		int minval;
		int maxval;
		int (*toi)(const char *, int, int, int *, char *, size_t);
	} config[] = {
		{ "enable-cache", (int *)&ngc_enable, 1, 0, 1, yntoi },
		{ "positive-time-to-live", &ngc_pos_ttl, NGC_POS_TTL, 0, week,
		    safestrtoi },
		{ "negative-time-to-live", &ngc_neg_ttl, NGC_NEG_TTL, 0, week,
		    safestrtoi }
	};
	uint32_t i;
	FILE *cfg;
	char buf[1024];
	uint32_t line = 0;

	/*
	 * Set values back to their defaults in case they were removed from
	 * nscd.conf.
	 */
	for (i = 0; i < ARRAY_SIZE(config); i++) {
		*config[i].valp = config[i].defval;
	};

	if ((cfg = fopen(NSCD_CONF, "rF")) == NULL) {
		syslog(LOG_ERR, "nss_ldap: unable to read nscd.conf: %m");
		return;
	}

	while (fgets(buf, sizeof (buf), cfg) != NULL) {
		char *key, *db, *strval, *junk, *last = NULL;
		char errmsg[1024];

		line++;

		if ((key = strchr(buf, '#')) != NULL) {
			*key = '\0';
		}
		if ((key = strtok_r(buf, "\n\t ", &last)) == NULL) {
			continue;
		}
		if ((db = strtok_r(NULL, "\n\t ", &last)) == NULL) {
			continue;
		}
		if (strcmp(db, "netgroup") != 0) {
			continue;
		}

		strval = strtok_r(NULL, "\n\t ", &last);
		junk = strtok_r(NULL, "\n\t ", &last);

		for (i = 0; i < ARRAY_SIZE(config); i++) {
			if (strcmp(config[i].key, key) == 0) {
				break;
			}
		}
		if (i == ARRAY_SIZE(config)) {
			syslog(LOG_ERR, "nss_ldap: %s:%d: "
			    "netgroup attribute '%s' invalid", NSCD_CONF,
			    line, key);
			continue;
		}
		if (strval == NULL) {
			syslog(LOG_ERR, "nss_ldap: %s:%d: "
			    "netgroup attribute '%s' missing value", NSCD_CONF,
			    line, key);
			continue;
		}
		if (junk != NULL) {
			syslog(LOG_ERR, "nss_ldap: %s:%d "
			    "netgroup attribute '%s' has too many values",
			    NSCD_CONF, line, key);
			continue;
		}
		if (config[i].toi(strval, config[i].minval, config[i].maxval,
		    config[i].valp, errmsg, sizeof (errmsg)) != 0) {
			syslog(LOG_ERR, "nss_ldap: %s:%d: %s", NSCD_CONF, line,
			    key, errmsg);
			continue;
		}
	}
	VERIFY0(fclose(cfg));
}

static void
ngc_init(void)
{
	char fmri[sizeof (NSCD_FMRI) + 1];	/* space for extra char */
	scf_handle_t *scf = NULL;

	mutex_enter(&ngc_lock);

	DTRACE_PROBE1(nss_ldap, ngc__init, ngc_initialized);

	VERIFY0(ngc_initialized);

	/* See ngc_time() */
	ngc_first_tick = NSEC2SEC(gethrtime());

	read_nscd_conf();

	/*
	 * Even when not caching, the caching structures are used - netgroups
	 * just expire immediately and are pruned when ng_refcnt drops to zero.
	 */
	avl_create(&ngc_cache, ngc_compare, sizeof (netgroup_t),
	    offsetof(netgroup_t, ng_linkage));
	list_create(&ngc_graveyard, sizeof (netgroup_t),
	    offsetof(netgroup_t, ng_linkage));
	list_create(&ngc_neg_expire_queue, sizeof (netgroup_t),
	    offsetof(netgroup_t, ng_expire_linkage));
	list_create(&ngc_pos_expire_queue, sizeof (netgroup_t),
	    offsetof(netgroup_t, ng_expire_linkage));

	/*
	 * Name service backends may run under nscd or as part of some other
	 * process that is making a request.  Keep things as light as possible
	 * while not running under nscd.
	 */
	if (ngc_enable && (scf = scf_handle_create(SCF_VERSION)) != NULL &&
	    scf_handle_bind(scf) == 0 &&
	    scf_myname(scf, fmri, sizeof (fmri)) == (sizeof (NSCD_FMRI) - 1) &&
	    strcmp(fmri, NSCD_FMRI) == 0) {
		char *env;

		/* For testing */
		if ((env = getenv("NSS_LDAP_REAP_INTERVAL")) != NULL) {
			ngc_reap_interval = atoi(env);
			VERIFY3S(ngc_reap_interval, >, 0);
		}

		ngc_warmer_die = B_FALSE;
		list_create(&ngc_warm_queue, sizeof (netgroup_t),
		    offsetof(netgroup_t, ng_warm_linkage));
		VERIFY0(cond_init(&ngc_warm_cv, USYNC_THREAD, NULL));
		if (thr_create(NULL, 0, ngc_warmer, NULL, 0,
		    &ngc_warmer_tid) != 0) {
			ngc_warmer_tid = 0;
		}
	} else {
		ngc_enable = B_FALSE;
		ngc_warmer_tid = 0;
	}
	if (scf != NULL) {
		scf_handle_destroy(scf);
	}

	ngc_initialized = B_TRUE;
	mutex_exit(&ngc_lock);
}

/*
 * This performs an orderly cleanup when the nss_ldap is unloaded.  The name
 * service switch (with nscd or arbitrary libc consumer) doesn't intend for
 * backends to keep state, so we rely on a little help from the dynamic linker
 * on unload.
 */
#pragma fini(ngc_fini)
void
ngc_fini(void)
{
	netgroup_t *ng, *next;

	mutex_enter(&ngc_lock);

	DTRACE_PROBE1(nss_ldap, ngc__fini, ngc_initialized);

	if (!ngc_initialized || !ngc_enable) {
		mutex_exit(&ngc_lock);
		return;
	}

	ngc_initialized = B_FALSE;

	if (ngc_warmer_tid != 0) {
		ngc_warmer_die = B_TRUE;
		cond_signal(&ngc_warm_cv);

		mutex_exit(&ngc_lock);
		(void) thr_join(ngc_warmer_tid, NULL, NULL);
		mutex_enter(&ngc_lock);
	}

	for (ng = avl_first(&ngc_cache); ng != NULL; ng = next) {
		next = AVL_NEXT(&ngc_cache, ng);
		ng->ng_refcnt = 0;
		ngc_dispose_locked(ng);
	}
	avl_destroy(&ngc_cache);
	list_destroy(&ngc_neg_expire_queue);
	list_destroy(&ngc_pos_expire_queue);

	for (ng = list_head(&ngc_graveyard); ng != NULL; ng = next) {
		next = list_next(&ngc_graveyard, ng);
		ng->ng_refcnt = 0;
		ngc_dispose_locked(ng);
	}
	list_destroy(&ngc_graveyard);

	mutex_exit(&ngc_lock);
}

/*ARGSUSED1*/
static nss_status_t
netgr_ldap_destr(ldap_backend_ptr be, void *a)
{

#ifdef	DEBUG
	(void) fprintf(stderr, "\n[getnetgrent.c: netgr_ldap_destr]\n");
#endif	/* DEBUG */

	(void) _clean_ldap_backend(be);

	return ((nss_status_t)NSS_NOTFOUND);
}


static ldap_backend_op_t netgroup_ops[] = {
	netgr_ldap_destr,
	0,
	0,
	0,
	netgr_in,		/*	innetgr()	*/
	netgr_set		/*	setnetgrent()	*/
};


/*
 * _nss_ldap_netgroup_constr is where life begins. This function calls the
 * generic ldap constructor function to define and build the abstract data
 * types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_netgroup_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

#ifdef	DEBUG
	(void) fprintf(stderr,
	    "\n[getnetgrent.c: _nss_ldap_netgroup_constr]\n");
#endif	/* DEBUG */

	/* Initialize the cache. */
	ngc_init();

	return ((nss_backend_t *)_nss_ldap_constr(netgroup_ops,
	    sizeof (netgroup_ops)/sizeof (netgroup_ops[0]), _NETGROUP,
	    netgrent_attrs, NULL));
}
