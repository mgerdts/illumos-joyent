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

/*
 * zoneadmd logging
 *
 * zoneadmd logs to log files under <zonepath>/logs.  Each log entry is a json
 * structure of the form:
 *
 *   {
 *     "log": "some message\n",
 *     "stream": "stderr",
 *     "time": "2018-03-28T13:25:02.670423000Z"
 *   }
 *
 * Unlike the example above, the entries in the log file are not pretty-printed.
 * Messages are processed so that they have the proper json escapes for
 * problematic characters.  Excessively long messages may be truncated.
 *
 * To use these interfaces:
 *
 *	int logid;
 *
 *	logstream_init(zlogp);
 *
 *	logid = logstream_open(zlogp, "stdio.log", "stdout", flags);
 *	if (logid < 0) { ... handle error ... }
 *	...
 *	logstream_write(logid, buf, len);
 *	...
 *	logstream_close(logid);
 *
 * logstream_init() needs to be called only once.
 *
 * logstream_open() opens a log file (if not already open) and associates the
 * specified stream with it.  When logstream_write() will be called with
 * partial lines (e.g. console output with slow uart emulation), the
 * LS_LINE_BUFFERED flag is recommended to prevent extreme log file bloat due to
 * timestamp and json overhead.  The zlog_t reference that is passed to
 * logstream_open() is used only during logstream_open().
 *
 * Log rotation
 *
 * Two attributes, zlog-maxsize and zlog-keep-rotated are used for automatic log
 * rotation.  zlog-maxsize is the approximate maximum size of a log before it is
 * automatically rotated.  Rotated logs are renamed as <log>.<iso-8601-stamp>.
 * If zlog-keep-rotated is specified and is an integer greater than zero, only
 * that number of rotated logs will be retained.
 *
 * If zlog-maxsize is not specified, log rotation will not happen automatically.
 * An external log rotation program may rename the log file(s), then send
 * SIGHUP to zoneadmd.
 *
 * Log rotation can be forced with SIGUSR1.  In this case, the log will be
 * rotated as though it hit the maximum size and will be subject to retention
 * rules described above.
 *
 * Locking strategy
 *
 * Callers need not worry about locking.  In the interest of simplicity, a
 * single global lock is used to protect the state of the log files and the
 * associated streams.  Locking is necessary because reboots and log rotations
 * can cause various state changes.  Without locking, races could cause log
 * entries to be directed to the wrong file descriptors.
 *
 * The simplistic global lock complicates error reporting within logging
 * routines.  All calls to zerror() in this file must be done using the ZERROR()
 * macro to prevent recursive mutex_lock() calls.  When ZERROR()-based recursion
 * is detected, the message will not be logged here, but may be logged via
 * syslog.  See zerror().
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <strings.h>
#include <synch.h>
#include <time.h>
#include <thread.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>

#include "zoneadmd.h"

/*
 * Currently we only expect stdout, stderr, zoneadmd, and console.  Increase
 * MAX_ZLOG_STREAMS if more streams are added.  If the count increases
 * significantly, logfile_t and logstream_t elements should be dynamically
 * allocated and the algorithms associated with opening and closing them should
 * become more efficient.
 */
#define	MAX_LOG_STREAMS 4

#define	ZLOG_MAXSZ	"zlog-max-size"		/* zonecfg attr */
#define	ZLOG_KEEP	"zlog-keep-rotated"	/* zonecfg attr */

#define	ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#define	ZERROR(args)							\
	{								\
		if (logstream_lock_held()) {				\
			logging_in_zerror = B_TRUE;			\
		}							\
		zerror args;						\
		if (logstream_lock_held()) {				\
			logging_in_zerror = B_FALSE;			\
		}							\
	}

typedef struct logfile {
	char	lf_path[MAXPATHLEN];	/* log file name (absolute path) */
	char	lf_name[MAXNAMELEN];	/* tail of log file name */
	int	lf_fd;			/* file descriptor */
	size_t	lf_size;		/* Current size */
	boolean_t lf_write_err;		/* Avoid spamming console via logsys */
} logfile_t;

typedef struct logstream {
	char		ls_stream[MAXNAMELEN];	/* stdout, stderr, etc. */
	char		ls_buf[BUFSIZ];	/* For LS_LINE_BUFFERED */
	int		ls_buflen;	/* For LS_LINE_BUFFERED */
	logstream_flags_t ls_flags;
	logfile_t	*ls_logfile;	/* N streams per log file */
} logstream_t;

/*
 * MAX_LOG_STREAMS is a small number so we allocate in the simplest way.
 */
static logstream_t streams[MAX_LOG_STREAMS];
static logfile_t logfiles[MAX_LOG_STREAMS];

static boolean_t logging_initialized = B_FALSE;
static uint64_t logging_rot_size;		/* See ZLOG_MAXSZ */
static uint64_t logging_rot_keep;		/* See ZLOG_KEEP */
static thread_t logging_lock_holder = -1;	/* Thread holds logging_lock */
static boolean_t logging_in_zerror = B_FALSE;	/* See ZERROR() */
static int logging_pending_sig = 0;		/* Signal recvd while logging */
static mutex_t logging_lock;			/* The global logging lock */

static void logstream_sighandler(int);
static void rotate_log(logfile_t *);

static void
logstream_lock(void)
{
	int ret;

	assert(logging_initialized);

	ret = mutex_lock(&logging_lock);
	assert(ret == 0);

	logging_lock_holder = thr_self();
}

static void
logstream_unlock(void)
{
	int ret;
	int err = errno;
	int sig = logging_pending_sig;

	logging_pending_sig = 0;
	logging_lock_holder = -1;
	ret = mutex_unlock(&logging_lock);
	assert(ret == 0);

	/*
	 * If a signal arrived while this thread was holding the lock, call the
	 * handler.
	 */
	if (sig != 0) {
		logstream_sighandler(sig);
	}

	errno = err;
}

static boolean_t
logstream_lock_held(void)
{
	return (logging_lock_holder == thr_self());
}

static void
close_log(logfile_t *lfp)
{
	int err;

	assert(logstream_lock_held());

	/*
	 * Something may have gone wrong during log rotation, leading to a
	 * zombie log.
	 */
	if (lfp->lf_fd == -1) {
		return;
	}

	err = close(lfp->lf_fd);
	assert(err == 0);
	lfp->lf_fd = -1;
}

static void
open_log(logfile_t *lfp)
{
	struct stat64 sb;
	int err;

	assert(logstream_lock_held());
	assert(lfp->lf_fd == -1);

	lfp->lf_fd = open(lfp->lf_path, O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (lfp->lf_fd == -1) {
		ZERROR((&logsys, B_TRUE, "Cannot open log file %s",
		    lfp->lf_path));
		lfp->lf_write_err = B_TRUE;
		return;
	}

	err = fstat64(lfp->lf_fd, &sb);
	assert(err == 0);
	lfp->lf_size = sb.st_size;
	lfp->lf_write_err = B_FALSE;
}

static void
logstream_sighandler(int sig)
{
	int i;

	/*
	 * Protect against recursive mutex enters when a signal comes during
	 * logging.  This will cause this function to be called again just after
	 * this thread drops the lock.
	 */
	if (logstream_lock_held()) {
		logging_pending_sig = sig;
		return;
	}

	logstream_lock();

	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		/* Inactive logfile slot */
		if (logfiles[i].lf_name[0] == '\0') {
			continue;
		}

		switch (sig) {
		case SIGHUP:
			close_log(&logfiles[i]);
			open_log(&logfiles[i]);
			break;
		case SIGUSR1:
			rotate_log(&logfiles[i]);
			break;
		default:
			ZERROR((&logsys, B_FALSE, "unhandled signal %d", sig));
		}
	}

	logstream_unlock();
}

void
get_attr_uint64(zlog_t *zlogp, zone_dochandle_t handle, const char *name,
    uint64_t *valp)
{
	struct zone_attrtab tab = { 0 };
	char *p;
	uint64_t val;

	(void) strlcpy(tab.zone_attr_name, name, sizeof (tab.zone_attr_name));
	if (zonecfg_lookup_attr(handle, &tab) != Z_OK) {
		return;
	}

	errno = 0;
	val = strtol(tab.zone_attr_value, &p, 10);
	if (errno != 0 && *p == '\0') {
		ZERROR((zlogp, errno != 0, "Bad value '%s' for 'attr name=%s'",
		    tab.zone_attr_value, tab.zone_attr_name));
		return;
	}

	*valp = val;
}

void
logstream_init(zlog_t *zlogp)
{
	zone_dochandle_t handle;
	int err;
	int i;

	assert(!logging_initialized);

	err = mutex_init(&logging_lock, USYNC_THREAD | LOCK_ERRORCHECK, 0);
	assert(err == 0);

	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		logfiles[i].lf_fd = -1;
	}

	logging_initialized = B_TRUE;

	/* Now it is safe to use zlogp */

	if ((handle = zonecfg_init_handle()) == NULL ||
	    zonecfg_get_handle(zone_name, handle) != Z_OK) {
		ZERROR((zlogp, B_FALSE, "failed to open zone configuration "
		    "while initializing logging"));
	} else {
		get_attr_uint64(zlogp, handle, ZLOG_MAXSZ, &logging_rot_size);
		get_attr_uint64(zlogp, handle, ZLOG_KEEP, &logging_rot_keep);
	}

	zonecfg_fini_handle(handle);

	/*
	 * This thread should receive SIGHUP so that it can close the log
	 * file and reopen it during log rotation.  SIGUSR1 can be used to force
	 * a log rotation.
	 */
	sigset(SIGHUP, logstream_sighandler);
	sigset(SIGUSR1, logstream_sighandler);
}

static boolean_t
is_rotated_file(const char *base, const char *file)
{
	const char *ext;
	int pos;

	if (strncmp(base, file, strlen(base)) != 0) {
		return (B_FALSE);
	}

	ext = file + strlen(base);
	if (strlen(ext) != strlen(".YYYYmmddTHHMMSSZ")) {
		return (B_FALSE);
	}
	for (pos = 0; ext[pos] != '\0'; pos++) {
		if (pos == 0) {
			if (ext[pos] != '.') {
				return (B_FALSE);
			}
			continue;
		}
		if ((pos > 0 && pos < 9) || (pos > 9 && pos < 16)) {
			if (!isdigit(ext[pos])) {
				return (B_FALSE);
			}
			continue;
		}
		if (pos == 9) {
			if (ext[pos] != 'T') {
				return (B_FALSE);
			}
			continue;
		}
		if (pos == 16) {
			if (ext[pos] != 'Z') {
				return (B_FALSE);
			}
			continue;
		}
		abort();
	}
	return (B_TRUE);
}

/*
 * Rotate a single log file.  The global lock must be held while this is called.
 */
static void
rotate_log(logfile_t *lfp)
{
	time_t t;
	struct tm gtm;
	char path[MAXPATHLEN];
	char **keepers;
	int i, j;
	char *p;
	DIR *dir;
	struct dirent *dirent;
	size_t len;

	assert(logstream_lock_held());

	if ((t = time(NULL)) == (time_t)-1 || gmtime_r(&t, &gtm) == NULL) {
		ZERROR((&logsys, B_TRUE, "failed to format time"));
		return;
	}

	(void) snprintf(path, sizeof (path), "%s.%d%02d%02dT%02d%02d%02dZ",
	    lfp->lf_path, gtm.tm_year + 1900, gtm.tm_mon + 1, gtm.tm_mday,
	    gtm.tm_hour, gtm.tm_min, gtm.tm_sec);

	if (rename(lfp->lf_path, path) != 0) {
		ZERROR((&logsys, B_TRUE, "failed to rotate log file "
		    "'%s' to '%s'", lfp->lf_path, path));
	}

	close_log(lfp);
	open_log(lfp);

	if (logging_rot_keep == 0) {
		return;
	}

	/*
	 * Remove old logs.
	 */
	if ((p = strrchr(path, '/')) == NULL) {
		ZERROR((&logsys, B_FALSE, "%s expected path '%s' to have '/'",
		    __func__, path));
		return;
	}
	*p = NULL;

	if ((dir = opendir(path)) == NULL) {
		ZERROR((&logsys, B_TRUE, "%s directory '%s'", __func__, path));
		return;
	}

	/* Set up keepers array to store the files that are being kept. */
	len = strlen(lfp->lf_name) + strlen(".YYYYmmddTHHMMSSZ") + 1;

	keepers = calloc(logging_rot_keep, sizeof (keepers[0]) + len);
	if (keepers == NULL) {
		ZERROR((&logsys, B_TRUE, "%s allocation of %llu bytes failed",
		    __func__, logging_rot_keep * len));
		(void) closedir(dir);
		return;
	}
	p = (char *)&keepers[logging_rot_keep];

	for (i = 0; i < logging_rot_keep; i++) {
		keepers[i] = p;
		p += len;
	}
	assert(p == ((char *)keepers) +
	    logging_rot_keep * (sizeof (keepers[0]) + len));

	/*
	 * Traverse the log directory looking for rotated logs matching
	 * <lf_name>.<timestamp>.  Populate the keepers array (newest first)
	 * using insertion sort.  If a file falls off the end of the array,
	 * delete it.
	 */
	while ((dirent = readdir(dir)) != NULL) {
		size_t clen;

		if (!is_rotated_file(lfp->lf_name, dirent->d_name)) {
			continue;
		}
		for (i = 0; i < logging_rot_keep; i++) {
			/* Fill empty slot */
			if (keepers[i][0] == '\0') {
				clen = strlcpy(keepers[i], dirent->d_name, len);
				assert(clen + 1 == len);

				goto nextfile;
			}

			/* Older than current slot, try next. */
			if (strcmp(dirent->d_name, keepers[i]) < 0) {
				continue;
			}

			/* Insert here */
			for (j = logging_rot_keep - 1; j >= i; j--) {
				if (j == logging_rot_keep - 1 &&
				    keepers[j][0] != 0) {
					if (unlinkat(dirfd(dir),
					    keepers[j], 0) != 0) {
						ZERROR((&logsys, B_TRUE,
						    "unlink %s", keepers[j]));
					}
				}

				if (j == i) {
					break;
				}

				assert(j > 0);
				clen = strlcpy(keepers[j], keepers[j - 1], len);
				assert(clen == 0 || clen + 1 == len);
			}
			clen = strlcpy(keepers[i], dirent->d_name, len);
			assert(clen + 1 == len);

			goto nextfile;
		}
		assert(i == logging_rot_keep);
		if (unlinkat(dirfd(dir), dirent->d_name, 0) != 0) {
			ZERROR((&logsys, B_TRUE, "unlink '%s'",
			    dirent->d_name));
		}
nextfile:
		;
	}

	free(keepers);
	(void) closedir(dir);
}

/*
 * Modify the input string with json escapes. Since the destination can thus
 * be larger than the source, it may get truncated, although we do use a
 * larger buffer.
 */
static void
escape_json(char *sbuf, int slen, char *dbuf, int dlen)
{
	int i;
	mbstate_t mbr;
	wchar_t c;
	size_t sz;

	bzero(&mbr, sizeof (mbr));

	sbuf[slen] = '\0';
	i = 0;
	while (i < dlen && (sz = mbrtowc(&c, sbuf, MB_CUR_MAX, &mbr)) > 0) {
		switch (c) {
		case '\\':
			dbuf[i++] = '\\';
			dbuf[i++] = '\\';
			break;

		case '"':
			dbuf[i++] = '\\';
			dbuf[i++] = '"';
			break;

		case '\b':
			dbuf[i++] = '\\';
			dbuf[i++] = 'b';
			break;

		case '\f':
			dbuf[i++] = '\\';
			dbuf[i++] = 'f';
			break;

		case '\n':
			dbuf[i++] = '\\';
			dbuf[i++] = 'n';
			break;

		case '\r':
			dbuf[i++] = '\\';
			dbuf[i++] = 'r';
			break;

		case '\t':
			dbuf[i++] = '\\';
			dbuf[i++] = 't';
			break;

		default:
			if ((c >= 0x00 && c <= 0x1f) ||
			    (c > 0x7f && c <= 0xffff)) {

				i += snprintf(&dbuf[i], (dlen - i), "\\u%04x",
				    (int)(0xffff & c));
			} else if (c >= 0x20 && c <= 0x7f) {
				dbuf[i++] = 0xff & c;
			}

			break;
		}
		sbuf += sz;
	}

	if (i == dlen)
		dbuf[--i] = '\0';
	else
		dbuf[i] = '\0';
}

/*
 * We output to the log file as json.
 * ex. for string 'msg\n' on the zone's stdout:
 *    {"log":"msg\n","stream":"stdout","time":"2014-10-24T20:12:11.101973117Z"}
 *
 * We use ns in the last field of the timestamp for compatibility.
 *
 * We keep track of the size of the log file and rotate it when we exceed
 * the log size limit (if one is set).
 */
void
logstream_write(int ls, char *buf, int len)
{
	struct timeval tv;
	int olen;
	char ts[64];
	char nbuf[BUFSIZ * 2];
	/* Sized for nbuf + ls_stream + timestamp + json stuff */
	char obuf[BUFSIZ * 2 + MAXNAMELEN + 64];
	logstream_t *stream;
	logfile_t *logfile;
	ssize_t wlen;

	if (ls == -1) {
		return;
	}
	assert(ls >= 0 && ls < ARRAY_SIZE(streams));

	/* Prevent recursion */
	if (logstream_lock_held() && logging_in_zerror)
		return;

	logstream_lock();

	stream = &streams[ls];

	/*
	 * In line-buffered mode, avoid emitting ~64 bytes of json for very
	 * small buffer lengths.  Instead, emit a json entry if a message
	 * contains a newline or it fills stream->ls_buf.
	 */
	if ((stream->ls_flags & LS_LINE_BUFFERED) != 0) {
		int tocopy = MIN(len, sizeof (stream->ls_buf) -
		    stream->ls_buflen);
		int left;
		char *p;

		/* buf could have '\0', so strrchr() is not an option */
		for (p = &buf[tocopy - 1]; p > buf && *p != '\n'; p--)
			;
		if (*p == '\n') {
			tocopy = p - buf + 1;
		}
		assert(tocopy <= len);

		left = len - tocopy;

		(void) memcpy(&stream->ls_buf[stream->ls_buflen], buf, tocopy);
		stream->ls_buflen += tocopy;

		if (stream->ls_buflen < sizeof (stream->ls_buf) && *p != '\n') {
			assert(left == 0);
			logstream_unlock();
			return;
		}
		escape_json(stream->ls_buf, stream->ls_buflen, nbuf,
		    sizeof (nbuf));

		left = MIN(left, sizeof (stream->ls_buf));
		(void) memcpy(stream->ls_buf, &buf[tocopy], left);
		stream->ls_buflen = left;
	} else {
		escape_json(buf, len, nbuf, sizeof (nbuf));
	}

	if (gettimeofday(&tv, NULL) != 0) {
		logstream_unlock();
		return;
	}
	(void) strftime(ts, sizeof (ts), "%FT%T", gmtime(&tv.tv_sec));


	logfile = stream->ls_logfile;
	if (stream->ls_stream[0] == '\0' || logfile == NULL) {
		logstream_unlock();
		return;
	}

	olen = snprintf(obuf, sizeof (obuf),
	    "{\"log\":\"%s\",\"stream\":\"%s\",\"time\":\"%s.%ldZ\"}\n",
	    nbuf, stream->ls_stream, ts, tv.tv_usec * 1000);
	if (olen >= sizeof (obuf)) {
		/*
		 * For this unlikely case, there's not a great way to truncate
		 * obuf without risking creation of a corrupt json stream.  We
		 * could truncate buf and try again, but it's really a
		 * programming error if we've made it here.
		 */
		logstream_unlock();
		ZERROR((&logsys, B_FALSE, "log message buffer size too small "
		    "(olen %lu)", olen));
		return;
	}

	wlen = write(logfile->lf_fd, obuf, olen);
	if (wlen > 0) {
		logfile->lf_size += wlen;

		if (logging_rot_size > 0 &&
		    logfile->lf_size > logging_rot_size) {
			rotate_log(logfile);
		}
	}

	if (wlen != olen && !logfile->lf_write_err) {
		logfile->lf_write_err = B_TRUE;
		if (wlen == -1) {
			ZERROR((&logsys, B_TRUE, "log file fd %d '%s' "
			    "write failed", logfile->lf_fd, logfile->lf_path));
		} else {
			ZERROR((&logsys, B_TRUE, "log file fd %d '%s': ",
			    "short write (%lu of %lu)", logfile->lf_fd,
			    logfile->lf_path, wlen, olen));
		}
	}

	logstream_unlock();
}

int
logstream_open(zlog_t *zlogp, const char *logname, const char *stream,
    logstream_flags_t flags)
{
	int ls = -1;
	int i;
	logstream_t *lsp;
	logfile_t *lfp = NULL;

	logstream_lock();

	/*
	 * Find an empty logstream_t and verify that the stream is not already
	 * open.
	 */
	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (ls == -1 && streams[i].ls_stream[0] == '\0') {
			assert(streams[i].ls_logfile == NULL);
			ls = i;
			continue;
		}
		if (strcmp(stream, streams[i].ls_stream) == 0) {
			logstream_unlock();
			ZERROR((zlogp, B_FALSE, "log stream %s already open",
			    stream));
			return (-1);
		}
	}

	/* Find an existing or available logfile_t */
	for (i = 0; i < ARRAY_SIZE(logfiles); i++) {
		if (lfp == NULL && logfiles[i].lf_name[0] == '\0') {
			lfp = &logfiles[i];
		}
		if (strcmp(logname, logfiles[i].lf_name) == 0) {
			lfp = &logfiles[i];
			break;
		}
	}
	if (lfp->lf_name[0] == '\0') {
		struct stat64 sb;

		if (strlcpy(lfp->lf_name, logname, sizeof (lfp->lf_name)) >=
		    sizeof (lfp->lf_name)) {
			abort();
		}
		(void) snprintf(lfp->lf_path, sizeof (lfp->lf_path), "%s/logs",
		    zonepath);
		(void) mkdir(lfp->lf_path, 0700);

		(void) snprintf(lfp->lf_path, sizeof (lfp->lf_path),
		    "%s/logs/%s", zonepath, logname);

		open_log(lfp);
		if (lfp->lf_fd == -1) {
			logstream_unlock();
			return (-1);
		}

		if (fstat64(lfp->lf_fd, &sb) == 0) {
			lfp->lf_size = sb.st_size;
		}
	}

	lsp = &streams[ls];
	if (strlcpy(lsp->ls_stream, stream, sizeof (lsp->ls_stream)) >=
	    sizeof (lsp->ls_stream)) {
		abort();
	}

	lsp->ls_flags = flags;
	lsp->ls_logfile = lfp;

	logstream_unlock();

	return (ls);
}

void
logstream_close(int ls)
{
	logstream_t *lsp;
	logfile_t *lfp;
	int i;

	if (ls == -1) {
		return;
	}
	assert(ls >= 0 && ls < ARRAY_SIZE(streams));

	logstream_lock();

	lsp = &streams[ls];
	lfp = lsp->ls_logfile;

	assert(lsp->ls_stream[0] != '\0');
	assert(lfp != NULL);

	(void) memset(lsp, 0, sizeof (*lsp));

	for (i = 0; i < ARRAY_SIZE(streams); i++) {
		if (streams[i].ls_logfile == lfp) {
			logstream_unlock();
			return;
		}
	}

	/* No more streams using this log file so return to initial state */

	close_log(lfp);

	(void) memset(lfp, 0, sizeof (*lfp));
	lfp->lf_fd = -1;

	logstream_unlock();
}
