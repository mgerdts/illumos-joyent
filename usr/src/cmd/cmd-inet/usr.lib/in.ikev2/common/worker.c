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
 * Copyright 2017 Joyent, Inc.
 */

#include <bunyan.h>
#include <err.h>
#include <errno.h>
#include <libperiodic.h>
#include <port.h>
#include <string.h>
#include <synch.h>
#include <sys/debug.h>
#include <sys/list.h>
#include <thread.h>
#include <time.h>
#include <umem.h>
#include "defs.h"
#include "ikev2_proto.h"
#include "ikev2_sa.h"
#include "pkcs11.h"
#include "pkt.h"
#include "worker.h"

/*
 * Workers handle all the heavy lifting (including crypto) in in.ikev2d.
 * An event port (port) waits for packets from our UDP sockets (IPv4, IPv6,
 * and IPv4 NAT) as well as for pfkey messages.  For UDP messages, some
 * minimal sanity checks (such as verifying payload lengths) occur, an IKEv2
 * SA is located for the message (or if appropriate, a larval IKEv2 SA is
 * created), and then the packet is handed off to a worker thread to do the
 * rest of the work.  Currently dispatching works by merely taking the local
 * IKEv2 SA SPI modulo the number of worker threads.  Since we control
 * the local IKEv2 SA SPI value (and is randomly chosen), this should prevent
 * a single connection from saturating the process by making all IKEv2
 * processing for a given IKEv2 SA occur all within the same thread (it also
 * simplifies some of the synchronization requirements for manipulating
 * IKEv2 SAs).  Obviously this does not address a DOS with spoofed source
 * addresses.  Cookies are used to mitigate such threats (to the extent it
 * can by dropping inbound packets without valid cookie values when enabled).
 */

typedef enum worker_state {
	WS_NORMAL = 0,
	WS_SUSPENDING,
	WS_SUSPENDED,
	WS_RESUMING,
	WS_QUITTING,
} worker_state_t;

typedef enum worker_alert {
	WA_NONE,
	WA_SUSPEND,
} worker_alert_t;

__thread worker_t *worker = NULL;

int wk_evport = -1;
size_t wk_nworkers = 0;
periodic_handle_t *wk_periodic = NULL;

/*
 * worker_lock protects access to workers, worker_state- and wk_nsuspended.
 *
 * NOTE: workers itself is largely a diagnostic construct to make it easier to
 * see the per-worker values of things in worker_t.  Once a worker_t has been
 * assigned to a worker thread, no other threads should access the values of
 * another thread's worker_t.
 */
static mutex_t worker_lock = ERRORCHECKMUTEX;
static cond_t worker_cv = DEFAULTCV; /* used to coordinate suspend/resume */
static list_t workers;
/* Global state of all workers */
static worker_state_t worker_state;
static volatile uint_t wk_nsuspended;

static worker_t *worker_new(void);
static void worker_free(worker_t *);
static void *worker_main(void *);
static const char *worker_cmd_str(worker_cmd_t);
static void worker_pkt_inbound(pkt_t *);

static void do_alert(int, void *);
static void do_user(int, void *);

/*
 * Create a pool of worker threads with the given queue depth.
 * Workers are left suspended under the assumption they will be
 * resumed once main_loop() starts.
 */
void
worker_init(size_t n)
{
	if ((wk_evport = port_create()) == -1)
		err(EXIT_FAILURE, "port_create() failed");

	/* CLOCK_READTIME should be good enough for our purposes */
	if ((wk_periodic = periodic_init(wk_evport, NULL, CLOCK_REALTIME))
	    == NULL)
		err(EXIT_FAILURE, "could not create periodic");

	mutex_enter(&worker_lock);
	list_create(&workers, sizeof (worker_t), offsetof (worker_t, w_node));
	mutex_exit(&worker_lock);

	for (size_t i = 0; i < n; i++) {
		if (!worker_add())
			err(EXIT_FAILURE, "Unable to create workers");
	}

	(void) bunyan_trace(log, "Worker threads created",
	    BUNYAN_T_UINT32, "numworkers", (uint32_t)wk_nworkers,
	    BUNYAN_T_END);
}

boolean_t
worker_add(void)
{
	worker_t *w = NULL;
	int rc;

	VERIFY(!IS_WORKER);

	/*
	 * Lock out any other global activity until after the add has
	 * succeeded or failed.
	 */
	mutex_enter(&worker_lock);
	while (worker_state != WS_NORMAL && worker_state != WS_QUITTING)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	if (worker_state == WS_QUITTING)
		goto fail;

	if ((w = umem_zalloc(sizeof (worker_t), UMEM_DEFAULT)) == NULL)
		goto fail;

	if (bunyan_child(log, &w->w_log, BUNYAN_T_END) != 0)
		goto fail;

	if ((w->w_p11 = pkcs11_new_session()) == CK_INVALID_HANDLE)
		goto fail;

again:
	rc = thr_create(NULL, 0, worker_main, w, 0, &w->w_tid);
	switch (rc) {
	case 0:
		break;
	case EAGAIN:
		goto again;
	case ENOMEM:
		(void) bunyan_warn(log,
		    "No memory to create worker",
		    BUNYAN_T_STRING, "errmsg", strerror(rc),
		    BUNYAN_T_INT32, "errno", (int32_t)rc,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_END);
		goto fail;
	default:
		(void) bunyan_fatal(log,
		    "Cannot create additional worker thread",
		    BUNYAN_T_STRING, "errmsg", strerror(rc),
		    BUNYAN_T_INT32, "errno", (int32_t)rc,
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", (int32_t)__LINE__,
		    BUNYAN_T_END);
		abort();
	}

	list_insert_tail(&workers, w);
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	return (B_TRUE);

fail:
	worker_free(w);
	mutex_enter(&worker_lock);
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);
	return (B_FALSE);
}

static void
worker_free(worker_t *w)
{
	if (w == NULL)
		return;

	if (w->w_log != NULL)
		bunyan_fini(w->w_log);

	pkcs11_session_free(w->w_p11);
	umem_free(w, sizeof (*w));
}

/*
 * Pause all the workers.  The current planned use is when we need to resize
 * the IKE SA hashes -- it's far simpler to make sure all the workers are
 * quiesced and rearrange things then restart.
 */
void
worker_suspend(void)
{
	/*
	 * We currently do not support workers suspending all the workers.
	 * This must be called from a non-worker thread.
	 */
	VERIFY(!IS_WORKER);

	mutex_enter(&worker_lock);

again:
	switch (worker_state) {
	case WS_NORMAL:
		break;
	case WS_QUITTING:
	case WS_SUSPENDING:
	case WS_SUSPENDED:
		mutex_exit(&worker_lock);
		return;
	case WS_RESUMING:
		cond_wait(&worker_cv, &worker_lock);
		goto again;
	}

	worker_state = WS_SUSPENDING;
	(void) bunyan_debug(log, "Suspending workers", BUNYAN_T_END);

	if (port_alert(wk_evport, PORT_ALERT_SET, WA_SUSPEND, NULL) == -1) {
		/*
		 * While EBUSY (alert mode already set) can in some instances
		 * not be a fatal error, we never intentionally try set a port
		 * into alert mode once it is already there.  If we encounter
		 * that, something has gone wrong, so treat it as a fatal
		 * condition.
		 */
		STDERR(fatal, log, "port_alert() failed");
		abort();
	}

	while (wk_nsuspended != wk_nworkers)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	worker_state = WS_SUSPENDED;

	if (port_alert(wk_evport, PORT_ALERT_SET, WC_NONE, NULL) == -1) {
		STDERR(fatal, log, "port_alert() failed");
		abort();
	}

	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	(void) bunyan_trace(log, "Finished suspending workers", BUNYAN_T_END);
}

static void
worker_do_suspend(worker_t *w)
{
	VERIFY(IS_WORKER);

	(void) bunyan_debug(w->w_log, "Worker suspending", BUNYAN_T_END);

	mutex_enter(&worker_lock);
	if (++wk_nsuspended == wk_nworkers) {
		(void) bunyan_trace(w->w_log, "Last one in, signaling",
		    BUNYAN_T_END);
		VERIFY0(cond_broadcast(&worker_cv));
	}
	mutex_exit(&worker_lock);

	mutex_enter(&worker_lock);
	while (worker_state != WS_RESUMING)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	VERIFY3U(wk_nsuspended, >, 0);
	if (--wk_nsuspended == 0)
		VERIFY0(cond_broadcast(&worker_cv));

	mutex_exit(&worker_lock);

	(void) bunyan_debug(w->w_log, "Worker resuming", BUNYAN_T_END);
}

void
worker_resume(void)
{
	/* Similar to worker_suspend(), can not be called from a worker */
	VERIFY(!IS_WORKER);

	mutex_enter(&worker_lock);

again:
	switch (worker_state) {
	case WS_NORMAL:
	case WS_RESUMING:
	case WS_QUITTING:
		mutex_exit(&worker_lock);
		return;
	case WS_SUSPENDING:
		VERIFY0(cond_wait(&worker_cv, &worker_lock));
		goto again;
	case WS_SUSPENDED:
		break;
	}

	(void) bunyan_debug(log, "Resuming workers", BUNYAN_T_END);

	worker_state = WS_RESUMING;

	while (wk_nsuspended > 0)
		VERIFY0(cond_wait(&worker_cv, &worker_lock));

	worker_state = WS_NORMAL;
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	(void) bunyan_trace(log, "Finished resuming workers", BUNYAN_T_END);
}

static void *
worker_main(void *arg)
{
	worker_t *w = arg;

	worker = w;
	(void) bunyan_trace(w->w_log, "Worker starting", BUNYAN_T_END);

	while (!w->w_quit) {
		port_event_t pe = { 0 };
		char portsrc[PORT_SOURCE_STR_LEN];

		/*
		 * Inbound processing will set these for the packet processing
		 * as it works it's way through processing, so clear these
		 * before we process a new event.
		 */
		(void) bunyan_key_remove(w->w_log, BLOG_KEY_SRC);
		(void) bunyan_key_remove(w->w_log, BLOG_KEY_SRCPORT);
		(void) bunyan_key_remove(w->w_log, BLOG_KEY_DEST);
		(void) bunyan_key_remove(w->w_log, BLOG_KEY_DESTPORT);

		if (port_get(wk_evport, &pe, NULL) == -1) {
			if (errno == EINTR) {
				/*
				 * This should not happen, but if it does,
				 * we can just ignore it, but at least make note
				 * of it.
				 */
				(void) bunyan_warn(w->w_log,
				    "port_get() failed with EINTR",
				    BUNYAN_T_END);
				continue;
			}

			STDERR(fatal, w->w_log, "port_get() failed");
			abort();
		}

		(void) bunyan_trace(w->w_log, "Received event",
		    BUNYAN_T_INT32, "evport", (int32_t)wk_evport,
		    BUNYAN_T_STRING, "source", port_source_str(pe.portev_source,
		    portsrc, sizeof (portsrc)),
		    BUNYAN_T_INT32, "events", (int32_t)pe.portev_events,
		    BUNYAN_T_UINT64, "object", (uint64_t)pe.portev_object,
		    BUNYAN_T_POINTER, "cookie", pe.portev_user,
		    BUNYAN_T_END);

		switch (pe.portev_source) {
		case PORT_SOURCE_TIMER:
			periodic_fire(wk_periodic);
			continue;
		case PORT_SOURCE_FD: {
			void (*fn)(int) = (void (*)(int))pe.portev_user;
			int fd = (int)pe.portev_object;

			fn(fd);
			continue;
		}
		case PORT_SOURCE_USER:
			do_user(pe.portev_events, pe.portev_user);
			continue;
		case PORT_SOURCE_ALERT:
			do_alert(pe.portev_events, pe.portev_user);
			continue;
		}
	}

	mutex_enter(&worker_lock);
	list_remove(&workers, w);
	wk_nworkers--;
	VERIFY0(cond_broadcast(&worker_cv));
	mutex_exit(&worker_lock);

	worker = NULL;
	worker_free(w);
	return (NULL);
}

static void
do_alert(int events, void *user)
{
	NOTE(ARGUNUSED(user))

	VERIFY(IS_WORKER);

	switch ((worker_alert_t)events) {
	case WA_NONE:
		return;
	case WA_SUSPEND:
		worker_do_suspend(worker);
		return;
	}
}

static void
do_user(int events, void *user)
{
	VERIFY(IS_WORKER);

	ikev2_sa_t *sa = user;

	switch((worker_cmd_t)events) {
	case WC_NONE:
		return;
	case WC_QUIT:
		/*
		 * Unless we are shutting down, must always have at least
		 * one worker running.
		 */
		mutex_enter(&worker_lock);
		if (worker_state == WS_QUITTING || wk_nworkers > 1)
			worker->w_quit = B_TRUE;
		mutex_exit(&worker_lock);
		return;
	case WC_START:
		ikev2_sa_init_outbound(sa, NULL, 0, IKEV2_DH_NONE, NULL, 0);
		return;
	}
}

static void
worker_pkt_inbound(pkt_t *pkt)
{
	switch (IKE_GET_MAJORV(pkt_header(pkt)->version)) {
	case 1:
		/* XXX: ikev1_inbound(pkt); */
		break;
	case 2:
		ikev2_inbound(pkt);
		break;
	default:
		/* XXX: log? */
		pkt_free(pkt);
	}
}

boolean_t
worker_send_cmd(worker_cmd_t cmd, void *arg)
{
again:
	if (port_send(wk_evport, (int)cmd, arg) == 0)
		return (B_TRUE);

	switch (errno) {
	case EAGAIN:
		/* This shouldn't happen, but if it does, we can try again */
		(void) bunyan_warn(log, "port_send() failed with EAGAIN",
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg,
		    BUNYAN_T_END);
		goto again;
	case ENOMEM:
		(void) bunyan_warn(log, "Out of memory trying to send command",
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg,
		    BUNYAN_T_END);
		break;
	default:
		(void) bunyan_fatal(log,
		    "Unexpected error trying to send command",
		    BUNYAN_T_STRING, "file", __FILE__,
		    BUNYAN_T_INT32, "line", __LINE__,
		    BUNYAN_T_STRING, "func", __func__,
		    BUNYAN_T_STRING, "cmd", worker_cmd_str(cmd),
		    BUNYAN_T_POINTER, "arg", arg,
		    BUNYAN_T_END);
		abort();
	}

	return (B_FALSE);
}

boolean_t
worker_del(void)
{
	return (worker_send_cmd(WC_QUIT, NULL));
}

#define	STR(x) case x: return (#x)
static const char *
worker_cmd_str(worker_cmd_t wc)
{
	switch (wc) {
	STR(WC_NONE);
	STR(WC_QUIT);
	STR(WC_START);
	}

	INVALID(wc);
	return (NULL);
}
#undef STR
