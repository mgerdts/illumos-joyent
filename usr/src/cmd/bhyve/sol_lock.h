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

#ifndef SOL_LOCK_H
#define	SOL_LOCK_H

#include <pthread.h>
#include <sys/debug.h>

extern int _check_mutex_init(pthread_mutex_t *, pthread_mutexattr_t *);
extern int _check_mutex_destroy(pthread_mutex_t *);
extern int _check_mutex_lock(pthread_mutex_t *);
extern int _check_mutex_unlock(pthread_mutex_t *);

#ifndef _SOL_LOCK_C
#define	pthread_mutex_init(mtx, a)	_check_mutex_init((mtx), (a))
#define	pthread_mutex_destroy(mtx)	_check_mutex_destroy(mtx)
#define	pthread_mutex_lock(mtx)		_check_mutex_lock(mtx)
#define	pthread_mutex_unlock(mtx)	_check_mutex_unlock(mtx)
#endif

#define	PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP				\
	{{0, 0, 0, PTHREAD_MUTEX_ERRORCHECK, _MUTEX_MAGIC}, {{{0}}}, 0}

#endif
