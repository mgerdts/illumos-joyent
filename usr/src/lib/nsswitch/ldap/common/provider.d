/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

provider nss_ldap {
	/* netgroup-* probes all start with string, netgroup_t */
	probe netgroup__cache__add__collision(string, uintptr_t, uintptr_t);
	probe netgroup__cache__add(string, uintptr_t, int);
	probe netgroup__cache__dispose(string, uintptr_t, int, int);
	probe netgroup__cache__hold(string, uintptr_t, int);
	probe netgroup__cache__free(string, uintptr_t);
	probe netgroup__cache__rele(string, uintptr_t, int);
	probe netgroup__cache__to__graveyard(string, uintptr_t);
	probe netgroup__cache__triple(string, uintptr_t, string, string,
	    string);
	probe netgroup__get__from__cache(string, uintptr_t, int);
	probe netgroup__reap(string, uintptr_t, uintptr_t);
	probe netgroup__warmer__backwards(string, uintptr_t);
	probe netgroup__warmer__enqueue(string, uintptr_t);
	probe netgroup__warmer__expire(string, uintptr_t);
	probe netgroup__warmer__ldap__fail(string, uintptr_t);
	probe netgroup__warmer__no__stamp(string, uintptr_t);
	probe netgroup__warmer__reload__fail(string, uintptr_t, int);
	probe netgroup__warmer__reload__success(string, uintptr_t, uintptr_t);
	probe netgroup__warmer__renewal(string, uintptr_t);
	probe netgroup__warmer__resurrection(string, uintptr_t);

	/* probes not starting with netgroup-* can be more diverse */
	probe innetgr(string, string, string, string, int);
	probe ngc__fini(int);
	probe ngc__init(int);
	probe ngc__tick(uint32_t);
};

#pragma D attributes Evolving/Evolving/Common provider nss_ldap provider
#pragma D attributes Private/Private/Unknown provider nss_ldap module
#pragma D attributes Private/Private/Unknown provider nss_ldap function
#pragma D attributes Evolving/Evolving/Common provider nss_ldap name
#pragma D attributes Evolving/Evolving/Common provider nss_ldap args
