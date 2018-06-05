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
 * Copyright 2018 Joyent, Inc.
 */

#define	_SOL_LOCK_C
#include "sol_lock.h"

int
_check_mutex_init(pthread_mutex_t *mtx, pthread_mutexattr_t *nattr)
{
	pthread_mutexattr_t attr;

	ASSERT3S((nattr), ==, NULL);
	VERIFY3S(pthread_mutexattr_init(&attr), ==, 0);
	VERIFY3S(pthread_mutexattr_settype(&attr,
	    PTHREAD_MUTEX_ERRORCHECK), ==, 0);
	VERIFY3S(pthread_mutex_init((mtx), &attr), ==, 0);
	VERIFY3S(pthread_mutexattr_destroy(&attr), ==, 0);

	return (0);
}

int
_check_mutex_destroy(pthread_mutex_t *mtx)
{
	VERIFY3S(pthread_mutex_destroy(mtx), ==, 0);
	return (0);
}

int
_check_mutex_lock(pthread_mutex_t *mtx)
{
	VERIFY3S(pthread_mutex_lock(mtx), ==, 0);
	return (0);
}

int
_check_mutex_unlock(pthread_mutex_t *mtx)
{
	VERIFY3S(pthread_mutex_unlock(mtx), ==, 0);
	return (0);
}
