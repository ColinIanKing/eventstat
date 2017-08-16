/*
 * Copyright (C) 2011-2017 Canonical
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * eventstat by Colin Ian King <colin.king@canonical.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <math.h>
#include <float.h>
#include <ncurses.h>
#include <ctype.h>

#define TABLE_SIZE		(1009)		/* Should be a prime */

#define OPT_QUIET		(0x00000001)
#define OPT_CUMULATIVE		(0x00000002)
#define OPT_CMD_SHORT		(0x00000004)
#define OPT_CMD_LONG		(0x00000008)
#define OPT_DIRNAME_STRIP	(0x00000010)
#define OPT_SAMPLE_COUNT	(0x00000020)
#define OPT_RESULT_STATS	(0x00000040)
#define OPT_BRIEF		(0x00000080)
#define OPT_KERNEL		(0x00000100)
#define OPT_USER		(0x00000200)
#define OPT_SHOW_WHENCE		(0x00000400)
#define OPT_TOP			(0x00000800)
#define OPT_TIMER_ID		(0x00001000)
#define OPT_CMD			(OPT_CMD_SHORT | OPT_CMD_LONG)

#define EVENT_BUF_SIZE		(64 * 1024)
#define TIMER_REAP_AGE		(600)	/* Age of timer before it is reaped */
#define TIMER_REAP_THRESHOLD	(30)
#define EVENTS_WIDTH		(8)
#define TASK_WIDTH		(15)
#define TIMER_ID_WIDTH		(16)
#define FUNC_WIDTH		(24)
#define FUNC_WIDTH_MAX		(30)

#define _VER_(major, minor, patchlevel) \
	((major * 10000) + (minor * 100) + patchlevel)

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#if defined(__GNUC_PATCHLEVEL__)
#define NEED_GNUC(major, minor, patchlevel) \
	_VER_(major, minor, patchlevel) <= \
	_VER_(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#else
#define NEED_GNUC(major, minor, patchlevel) \
	_VER_(major, minor, patchlevel) <= _VER_(__GNUC__, __GNUC_MINOR__, 0)
#endif
#else
#define NEED_GNUC(major, minor, patchlevel) (0)
#endif

#if defined(__GNUC__) && NEED_GNUC(4,6,0)
#define HOT __attribute__ ((hot))
#else
#define HOT
#endif

#if defined(__GNUC__) && !defined(__clang__) && NEED_GNUC(4,6,0)
#define OPTIMIZE3 __attribute__((optimize("-O3")))
#else
#define OPTIMIZE3
#endif

#define FLOAT_TINY		(0.0000001)
#define FLOAT_CMP(a, b)		(fabs(a - b) < FLOAT_TINY)

/*
 *  timer_info_t contains per task timer infos.
 */
typedef struct timer_info {
	struct timer_info *next;	/* Next in list */
	struct timer_info *hash_next;	/* Next in hash list */
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char 		*task_mangled;	/* Modified name of process/kernel */
	char		*cmdline;	/* From /proc/$pid/cmdline */
	char		*func;		/* Kernel waiting func */
	char		*ident;		/* Unique identity */
	bool		kernel_thread;	/* True if task is a kernel thread */
	uint32_t	ref_count;	/* Timer stat reference count */
	uint64_t	timer;		/* Timer ID */
	uint64_t	total_events;	/* Total number of events */
	uint64_t	delta_events;	/* Events in one time period */
	double		time_total;	/* Total time */
	double		last_used;	/* Last referenced */
	double		prev_used;	/* Previous time used */
} timer_info_t;

typedef struct timer_stat {
	struct timer_stat *next;	/* Next timer stat in hash table */
	struct timer_stat *sorted_freq_next; /* Next timer stat in event */
					/* frequency sorted list */
	timer_info_t	*info;		/* Timer info */
} timer_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	struct sample_delta_item *next;	/* next in list */
	int64_t		delta_events;	/* delta in events */
	double		time_delta;	/* difference in time between old */
					/* and new */
	timer_info_t	*info;		/* timer this refers to */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	struct sample_delta_list *next;	/* next in list */
	struct sample_delta_item *list;	/* list of sample delta items */
	double		whence;		/* when the sample was taken */
} sample_delta_list_t;

typedef struct {
	char *task;			/* Name of kernel task */
	size_t len;			/* Length */
} kernel_task_info;

#define KERN_TASK_INFO(str)		{ str, sizeof(str) - 1 }

static const char * const app_name = "eventstat";
static const char * const sys_tracing_enable =
	"/sys/kernel/debug/tracing/events/timer/hrtimer_start/enable";
static const char * const sys_tracing_pipe =
	"/sys/kernel/debug/tracing/trace_pipe";
static const char * const sys_tracing_set_event =
	"/sys/kernel/debug/tracing/set_event";
static const char * const sys_tracing_filter =
	"/sys/kernel/debug/tracing/events/timer/filter";

static void es_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static timer_stat_t *timer_stat_free_list; /* free list of timer stats */
static timer_info_t *timer_info_list;	/* cache list of timer_info */
static timer_info_t *timer_info_hash[TABLE_SIZE]; /* hash of timer_info */

/* head of list of samples, sorted in sample time order */
static sample_delta_list_t *sample_delta_list_head;

/* tail of list of samples, sorted in sample time order */
static sample_delta_list_t *sample_delta_list_tail;

/* ignore samples with event delta less than this */
static double opt_threshold;

static char *csv_results;		/* results in comma separated values */
static char *get_events_buf;		/* buffer to glob events into */
static uint32_t timer_info_list_length;	/* length of timer_info_list */
static uint32_t opt_flags;		/* option flags */
static volatile bool stop_eventstat = false;	/* set by sighandler */
static bool sane_procs;			/* false if we are in a container */
static bool resized;			/* window resized */
static bool curses_init;		/* curses initialised */
static int rows = 25;			/* tty size, rows */
static int cols = 80;			/* tty size, columns */

/*
 *  Attempt to catch a range of signals so
 *  we can clean
 */
static const int signals[] = {
	/* POSIX.1-1990 */
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGINT
	SIGINT,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGFPE
	SIGFPE,
#endif
#ifdef SIGTERM
	SIGTERM,
#endif
#ifdef SIGUSR1
	SIGUSR1,
#endif
#ifdef SIGUSR2
	SIGUSR2,
	/* POSIX.1-2001 */
#endif
#ifdef SIGXCPU
	SIGXCPU,
#endif
#ifdef SIGXFSZ
	SIGXFSZ,
#endif
	/* Linux various */
#ifdef SIGIOT
	SIGIOT,
#endif
#ifdef SIGSTKFLT
	SIGSTKFLT,
#endif
#ifdef SIGPWR
	SIGPWR,
#endif
#ifdef SIGINFO
	SIGINFO,
#endif
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	-1,
};

/*
 *  pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
static int pid_max_digits(void)
{
	static int max_digits;
	ssize_t n;
	int fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	if (max_digits)
		goto ret;

	max_digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	max_digits = 0;
	while ((buf[max_digits] >= '0') && (buf[max_digits] <= '9'))
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;

}

/*
 *  hash_djb2a()
 *	Hash a string, from Dan Bernstein comp.lang.c (xor version)
 */
static HOT OPTIMIZE3 uint32_t hash_djb2a(const char *str)
{
	register uint32_t hash = 5381;
	register int c;

	while ((c = *str++)) {
		/* (hash * 33) ^ c */
		hash = ((hash << 5) + hash) ^ c;
		hash = (hash * 33) ^ c;
	}
	return hash % TABLE_SIZE;
}

/*
 *  eventstat_winsize()
 *	get tty size
 */
static void eventstat_winsize(void)
{
	struct winsize ws;

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1) {
		rows = ws.ws_row;
		cols = ws.ws_col;
	}
}

/*
 *  eventstat_clear()
 *	clear screen if in top mode
 */
static inline void eventstat_clear(void)
{
	if (curses_init)
		clear();
}

/*
 *  eventstat_refresh()
 *	refresh screen if in top mode
 */
static inline void eventstat_refresh(void)
{
	if (curses_init)
		refresh();
}

/*
 *  eventstat_move()
 *	move cursor if in top mode
 */
static inline void eventstat_move(const int y, const int x)
{
	if (curses_init)
		move(y, x);
}

/*
 *  eventstat_endwin()
 *	call endwin if in top mode
 */
static void eventstat_endwin(void)
{
	if (curses_init) {
		clear();
		endwin();
	}
}

/*
 *  err_abort()
 *	print an error and exit
 */
static void __attribute__ ((noreturn)) __attribute__((format(printf, 1, 2)))
err_abort(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	eventstat_endwin();
	vfprintf(stderr,fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

/*
 *  set_tracing_enable()
 *	enable/disable timer stat
 */
static void set_tracing(const char *path, const char *str, const bool carp)
{
	int fd;
	const ssize_t len = (ssize_t)strlen(str);

	if ((fd = open(path, O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
		if (carp) {
			err_abort("Cannot open %s, errno=%d (%s)\n",
				path, errno, strerror(errno));
		}
		return;
	}
	if (write(fd, str, len) != len) {
		(void)close(fd);
		if (carp) {
			err_abort("Cannot write to %s, errno=%d (%s)\n",
				path, errno, strerror(errno));
		}
		return;
	}
	(void)close(fd);
}

/*
 *  set_tracing_enable()
 *	enable/disable timer stat
 */
static inline void set_tracing_enable(const char *str, const bool carp)
{
	set_tracing(sys_tracing_enable, str, carp);
}

static void set_tracing_event(void)
{
	char buffer[64];

	set_tracing(sys_tracing_set_event, "\n", true);
	set_tracing(sys_tracing_set_event, "hrtimer_start", true);
	set_tracing(sys_tracing_filter, "0", true);

	/* Ignore event stat and idle events */
	snprintf(buffer, sizeof(buffer),
		"common_pid != %d && common_pid != 0", getpid());
	set_tracing(sys_tracing_filter, buffer, true);
}


/*
 *  eventstat_exit()
 *	exit and set timer stat to 0
 */
static void __attribute__ ((noreturn)) eventstat_exit(const int status)
{
	set_tracing_enable("0\n", false);
	exit(status);
}


/*
 *  timeval_to_double
 *	timeval to a double (in seconds)
 */
static inline double timeval_to_double(const struct timeval *const tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  double_to_timeval
 *	seconds in double to timeval
 */
static inline struct timeval double_to_timeval(const double val)
{
	struct timeval tv;

	tv.tv_sec = val;
	tv.tv_usec = (val - (time_t)val) * 1000000.0;
	return tv;
}

/*
 *  gettime_to_double()
 *      get time as a double
 */
static double gettime_to_double(void)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0)
		err_abort("gettimeofday failed: errno=%d (%s)\n",
			errno, strerror(errno));
	return timeval_to_double(&tv);
}

/*
 *  sane_proc_pid_info()
 *	detect if proc info mapping from /proc/timer_stats
 *	maps to proc pids OK. If we are in a container or
 *	we can't tell, return false.
 */
static bool sane_proc_pid_info(void)
{
	FILE *fp;
	static const char pattern[] = "container=";
	const char *ptr = pattern;
	bool ret = true;

	fp = fopen("/proc/1/environ", "r");
	if (!fp)
		return false;

	while (!feof(fp)) {
		int ch = getc(fp);

		if (*ptr == ch) {
			ptr++;
			/* Match? So we're inside a container */
			if (*ptr == '\0') {
				ret = false;
				break;
			}
		} else {
			/* No match, skip to end of var and restart scan */
			do {
				ch = getc(fp);
			} while ((ch != EOF) && (ch != '\0'));
			ptr = pattern;
		}
	}

	(void)fclose(fp);

	return ret;
}

/*
 *  handle_sig()
 *      catch signal, flag a stop and restore timer stat
 */
static void handle_sig(int dummy)
{
	(void)dummy;	/* Stop unused parameter warning with -Wextra */

	stop_eventstat = true;
	set_tracing_enable("0\n", false);
}

/*
 *  samples_free()
 *	free collected samples
 */
static inline void samples_free(void)
{
	sample_delta_list_t *sdl = sample_delta_list_head;

	while (sdl) {
		sample_delta_list_t *sdl_next = sdl->next;
		sample_delta_item_t *sdi = sdl->list;
		while (sdi) {
			sample_delta_item_t *sdi_next = sdi->next;
			free(sdi);
			sdi = sdi_next;
		}
		free(sdl);
		sdl = sdl_next;
	}
}

/*
 *  sample_add()
 *	add a timer_stat's delta and info field to a
 *	list at time position whence
 */
static void sample_add(timer_stat_t *timer_stat, const double whence)
{
	bool	found = false;
	sample_delta_list_t *sdl;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not enabled */
		return;

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		if (FLOAT_CMP(sdl->whence, whence)) {
			found = true;
			break;
		}
	}

	/*
	 * New time period, need new sdl, we assume it goes at the end of the
	 * list since time is assumed to be increasing
	 */
	if (!found) {
		if ((sdl = calloc(1, sizeof(sample_delta_list_t))) == NULL)
			err_abort("Cannot allocate sample delta list\n");
		sdl->whence = whence;

		if (sample_delta_list_tail) {
			sample_delta_list_tail->next = sdl;
			sample_delta_list_tail = sdl;
		} else {
			sample_delta_list_head = sdl;
			sample_delta_list_tail = sdl;
		}
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL)
		err_abort("Cannot allocate sample delta item\n");
	sdi->delta_events = timer_stat->info->delta_events;
	sdi->time_delta = timer_stat->info->last_used -
			  timer_stat->info->prev_used;
	sdi->info = timer_stat->info;
	sdi->next = sdl->list;
	sdl->list = sdi;
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for timer info,
 *	return NULL if not found
 */
inline HOT static sample_delta_item_t *sample_find(
	sample_delta_list_t *sdl,
	const timer_info_t *info)
{
	sample_delta_item_t *sdi;

	for (sdi = sdl->list; sdi; sdi = sdi->next) {
		if (sdi->info == info)
			return sdi;
	}
	return NULL;
}

/*
 * info_compare_total()
 *	used by qsort to sort array in sample event total order
 */
static int info_compare_total(const void *item1, const void *item2)
{
	timer_info_t *const *info1 = (timer_info_t *const *)item1;
	timer_info_t *const *info2 = (timer_info_t *const *)item2;

	if ((*info2)->total_events == (*info1)->total_events)
		return 0;

	return ((*info2)->total_events > (*info1)->total_events) ? 1 : -1;
}

static bool pid_a_kernel_thread_guess(const char *task)
{
	/*
	 * This is not exactly accurate, but if we can't look up
	 * a process then try and infer something from the comm field.
	 * Until we have better kernel support to map /proc/timer_stats
	 * pids to containerised pids this is the best we can do.
	 */
	static const kernel_task_info kernel_tasks[] = {
		KERN_TASK_INFO("swapper/"),
		KERN_TASK_INFO("kworker/"),
		KERN_TASK_INFO("ksoftirqd/"),
		KERN_TASK_INFO("watchdog/"),
		KERN_TASK_INFO("migration/"),
		KERN_TASK_INFO("irq/"),
		KERN_TASK_INFO("mmcqd/"),
		KERN_TASK_INFO("jbd2/"),
		KERN_TASK_INFO("kthreadd"),
		KERN_TASK_INFO("kthrotld"),
		KERN_TASK_INFO("kswapd"),
		KERN_TASK_INFO("ecryptfs-kthrea"),
		KERN_TASK_INFO("kauditd"),
		KERN_TASK_INFO("kblockd"),
		KERN_TASK_INFO("kcryptd"),
		KERN_TASK_INFO("kdevtmpfs"),
		KERN_TASK_INFO("khelper"),
		KERN_TASK_INFO("khubd"),
		KERN_TASK_INFO("khugepaged"),
		KERN_TASK_INFO("khungtaskd"),
		KERN_TASK_INFO("flush-"),
		KERN_TASK_INFO("bdi-default-"),
		{ NULL, 0 }
	};

	size_t i;

	for (i = 0; kernel_tasks[i].task != NULL; i++) {
		if (!strncmp(task, kernel_tasks[i].task, kernel_tasks[i].len))
			return true;
	}
	return false;
}

/*
 *  pid_a_kernel_thread
 *
 */
static bool pid_a_kernel_thread(const char *task, const pid_t id)
{
	const pid_t pgid = id == 0 ? 0 : getpgid(id);

	/* We are either in a container, or with a task with a NULL cmdline */
	if (sane_procs || (id >= 0))
		return (pgid == 0);

	/* Can't get pgid on that pid, so make a guess */
	return pid_a_kernel_thread_guess(task);
}

/*
 *  get_pid_cmdline
 *	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t id)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%d/cmdline", id);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	ret = read(fd, buffer, sizeof(buffer));
	(void)close(fd);
	if (ret < 0)
		return NULL;
	if (ret == 0)
		return strdup("");

	buffer[sizeof(buffer)-1] = '\0';

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret - 1; ptr++) {
			if (*ptr == '\0')
				*ptr = ' ';
		}
		*ptr = '\0';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ')
				*ptr = '\0';
		}
	}

	if (opt_flags & OPT_DIRNAME_STRIP)
		return strdup(basename(buffer));

	return strdup(buffer);
}

static inline double duration_round(const double duration)
{
	return floor((duration * 100.0) + 0.5) / 100.0;
}

/*
 *  samples_dump()
 *	dump out collected sample information
 */
static void samples_dump(const char *filename)
{
	timer_info_t **sorted_timer_infos;
	size_t i, n;
	FILE *fp;
	uint64_t count = 0;
	double first_time = -1.0;
	timer_info_t *info;
	sample_delta_list_t *sdl;

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	sorted_timer_infos = calloc(timer_info_list_length,
				sizeof(timer_info_t *));
	if (!sorted_timer_infos)
		err_abort("Cannot allocate buffer for sorting timer_infos\n");

	/* Just want the timers with some non-zero total */
	for (n = 0, info = timer_info_list; info; info = info->next) {
		if (info->total_events > 0)
			sorted_timer_infos[n++] = info;
	}

	qsort(sorted_timer_infos, n,
		sizeof(timer_info_t *), info_compare_total);

	fprintf(fp, "Time:,Task:");
	for (i = 0; i < n; i++) {
		char *task;

		if (opt_flags & OPT_CMD)
			task = sorted_timer_infos[i]->cmdline;
		else
			task = sorted_timer_infos[i]->task_mangled;

		fprintf(fp, ",%s", task);
	}
	fprintf(fp, "\n");

	fprintf(fp, ",Init Function:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->func);
	fprintf(fp, "\n");

	fprintf(fp, ",Total:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%" PRIu64, sorted_timer_infos[i]->total_events);
	fprintf(fp, "\n");

	for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
		time_t t = (time_t)sdl->whence;
		struct tm *tm;

		count++;
		tm = localtime(&t);
		fprintf(fp, "%2.2d:%2.2d:%2.2d",
			tm->tm_hour, tm->tm_min, tm->tm_sec);

		if (first_time < 0)
			first_time = sdl->whence;
		fprintf(fp, ",%f", duration_round(sdl->whence - first_time));

		/*
		 * Scan in timer info order to be consistent for all sdl rows
		 */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi =
				sample_find(sdl, sorted_timer_infos[i]);
			/*
			 *  duration - if -C option is used then don't scale
			 *  by the per sample duration time, instead give the
			 *  raw sample count by scaling by 1.0 (i.e. no scaling)
			 */
			if (sdi) {
				double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
				fprintf(fp, ",%f",
					FLOAT_CMP(duration, 0.0) ? -99.99 :
					(double)sdi->delta_events / duration);
			} else
				fprintf(fp, ",%f", 0.0);
		}
		fprintf(fp, "\n");
	}

	/*
	 *  -S option - some statistics, min, max, average, std.dev.
	 */
	if (opt_flags & OPT_RESULT_STATS) {
		fprintf(fp, ",Min:");
		for (i = 0; i < n; i++) {
			double min = DBL_MAX;

			for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);

				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double val = FLOAT_CMP(duration, 0.0) ?
						0.0 : sdi->delta_events / duration;
					if (min > val)
						min = val;
				}
			}
			fprintf(fp, ",%f", min);
		}
		fprintf(fp, "\n");

		fprintf(fp, ",Max:");
		for (i = 0; i < n; i++) {
			double max = DBL_MIN;

			for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);

				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double val = FLOAT_CMP(duration, 0.0) ?
						0.0 : sdi->delta_events / duration;
					if (max < val)
						max = val;
				}
			}
			fprintf(fp, ",%f", max);
		}
		fprintf(fp, "\n");

		fprintf(fp, ",Average:");
		for (i = 0; i < n; i++)
			fprintf(fp, ",%f", count == 0 ? 0.0 :
				(double)sorted_timer_infos[i]->total_events / count);
		fprintf(fp, "\n");

		/*
		 *  population standard deviation
		 */
		fprintf(fp, ",Std.Dev.:");
		for (i = 0; i < n; i++) {
			double average = (double)
				sorted_timer_infos[i]->total_events / (double)count;
			double sum = 0.0;

			for (sdl = sample_delta_list_head; sdl; sdl = sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);
				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double diff = FLOAT_CMP(duration, 0.0) ? 0.0 :
						((double)sdi->delta_events - average) / duration;
					diff = diff * diff;
					sum += diff;
				}
			}
			sum = sum / (double)count;
			fprintf(fp, ",%f", sqrt(sum));
		}
		fprintf(fp, "\n");
	}
	free(sorted_timer_infos);
	(void)fclose(fp);
}

/*
 *  timer_info_find()
 *	try to find existing timer info in cache, and to the cache
 *	if it is new.
 */
static HOT timer_info_t *timer_info_find(
	const timer_info_t *new_info,
	const char *ident,
	const double time_now,
	const double duration)
{
	timer_info_t *info;
	const uint32_t h = hash_djb2a(ident);

	for (info = timer_info_hash[h]; info; info = info->hash_next) {
		if (strcmp(ident, info->ident) == 0) {
			info->prev_used = info->last_used;
			info->last_used = time_now;
			return info;
		}
	}
	info = calloc(1, sizeof(timer_info_t));
	if (!info)
		err_abort("Cannot allocate timer info\n");

	info->pid = new_info->pid;
	info->task = strdup(new_info->task);
	info->task_mangled = strdup(new_info->task_mangled);
	info->cmdline = strdup(new_info->cmdline);
	info->func = strdup(new_info->func);
	info->ident = strdup(ident);
	info->kernel_thread = new_info->kernel_thread;
	info->total_events = new_info->total_events;
	info->delta_events = new_info->delta_events;
	info->time_total = new_info->time_total;
	info->timer = new_info->timer;
	info->ref_count = 0;
	info->prev_used = time_now - duration;		/* Fake previous time */
	info->last_used = time_now;

	if (info->task == NULL ||
	    info->task_mangled == NULL ||
	    info->cmdline == NULL ||
	    info->func == NULL ||
	    info->ident == NULL) {
		err_abort("Out of memory allocating a timer stat fields\n");
	}

	/* Does not exist in list, append it */
	info->next = timer_info_list;
	timer_info_list = info;
	timer_info_list_length++;
	info->hash_next = timer_info_hash[h];
	timer_info_hash[h] = info;

	return info;
}

/*
 *  timer_info_free()
 *	free up timer_info
 */
static void timer_info_free(void *data)
{
	timer_info_t *info = (timer_info_t*)data;

	free(info->task);
	if (info->cmdline != info->task_mangled)
		free(info->cmdline);
	free(info->task_mangled);
	free(info->func);
	free(info->ident);
	free(info);
}

/*
 *  timer_info_purge_old_from_timer_list()
 *	remove old timer info from the timer list
 */
static void timer_info_purge_old_from_timer_list(
	timer_info_t **list,
	const double time_now)
{
	timer_info_t *prev = NULL, *info = *list;

	while (info) {
		timer_info_t *next = info->next;

		/*
		 * Only remove from list once all timer
		 * stats no longer reference it
		 */
		if ((info->ref_count == 0) &&
		    (info->last_used + TIMER_REAP_AGE < time_now)) {
			if (prev == NULL)
				*list = next;
			else
				prev->next = next;
			timer_info_list_length--;
		} else {
			prev = info;
		}
		info = next;
	}
}

/*
 *  timer_info_purge_old_from_hash_list()
 *	remove old timer info from a hash list
 */
static void timer_info_purge_old_from_hash_list(
	timer_info_t **list,
	const double time_now)
{
	timer_info_t *prev = NULL, *info = *list;

	while (info) {
		timer_info_t *next = info->hash_next;

		/*
		 * Only remove and free once all timer stats no
		 * longer reference it
		 */
		if ((info->ref_count == 0) &&
		    (info->last_used + TIMER_REAP_AGE < time_now)) {
			if (prev == NULL)
				*list = next;
			else
				prev->hash_next = next;

			timer_info_free(info);
		} else {
			prev = info;
		}
		info = next;
	}
}


/*
 *  timer_info_purge_old()
 *	clean out old timer infos
 */
static inline void timer_info_purge_old(const double time_now)
{
	static uint16_t count = 0;

	count++;
	if (count > TIMER_REAP_THRESHOLD) {
		size_t i;

		count = 0;
		timer_info_purge_old_from_timer_list(&timer_info_list, time_now);
		for (i = 0; i < TABLE_SIZE; i++)
			timer_info_purge_old_from_hash_list(&timer_info_hash[i], time_now);
	}
}

/*
 *  timer_info_list_free()
 *	free up all unique timer infos
 */
static inline void timer_info_list_free(void)
{
	timer_info_t *info = timer_info_list;

	/* Free list and timers on list */
	while (info) {
		timer_info_t *next = info->next;

		timer_info_free(info);
		info = next;
	}
}

/*
 *  make_hash_ident()
 */
static char *make_hash_ident(const timer_info_t *info)
{
	static char ident[128];

	if (opt_flags & OPT_TIMER_ID) {
		snprintf(ident, sizeof(ident), "%x%s%8.8s%" PRIx64,
			info->pid, info->task, info->func, info->timer);
	} else {
		snprintf(ident, sizeof(ident), "%x%s%8.8s",
			info->pid, info->task, info->func);
	}
	return ident;
}

/*
 *  timer_stat_free_list_free()
 *	free up the timer stat free list
 */
static void timer_stat_free_list_free(void)
{
	timer_stat_t *ts = timer_stat_free_list;

	while (ts) {
		timer_stat_t *next = ts->next;

		free(ts);
		ts = next;
	}
	timer_stat_free_list = NULL;
}

/*
 *  timer_stat_free_contents()
 *	Free timers from a hash table
 */
static void timer_stat_free_contents(timer_stat_t *timer_stats[])
{
	size_t i;

	for (i = 0; i < TABLE_SIZE; i++) {
		timer_stat_t *ts = timer_stats[i];

		while (ts) {
			timer_stat_t *next = ts->next;

			/* Decrement info ref count */
			ts->info->ref_count--;
			/* Add it onto the timer stat free list */
			ts->next = timer_stat_free_list;
			timer_stat_free_list = ts;

			ts = next;
		}
		timer_stats[i] = NULL;
	}
}

/*
 *  timer_stat_add()
 *	add timer stats to a hash table if it is new, otherwise just
 *	accumulate the event count.
 */
static void timer_stat_add(
	timer_stat_t *timer_stats[],	/* timer stat hash table */
	timer_info_t *info,		/* timer info to be added */
	const double time_now,		/* time sample was taken */
	const double duration)		/* duration of a sample */
{
	const char *ident = make_hash_ident(info);
	const uint32_t h = hash_djb2a(ident);
	timer_stat_t *ts, *ts_new;

	for (ts = timer_stats[h]; ts; ts = ts->next) {
		if (strcmp(ts->info->ident, ident) == 0) {
			ts->info->total_events++;
			ts->info->delta_events++;
			sample_add(ts, time_now);
			return;
		}
	}
	/* Not found, it is new */
	if (timer_stat_free_list) {
		/* Get new one from free list */
		ts_new = timer_stat_free_list;
		timer_stat_free_list = timer_stat_free_list->next;
	} else {
		/* Get one from heap */
		if ((ts_new = malloc(sizeof(timer_stat_t))) == NULL)
			err_abort("Out of memory allocating a timer stat\n");
	}

	ts_new->info = timer_info_find(info, ident, time_now, duration);
	ts_new->info->ref_count++;
	ts_new->next = timer_stats[h];
	ts_new->sorted_freq_next = NULL;

	ts_new->info->total_events = 1;
	ts_new->info->delta_events = 1;

	timer_stats[h] = ts_new;
	sample_add(ts_new, time_now);
}

/*
 *  timer_stat_sort_freq_add()
 *	add a timer stat to a sorted list of timer stats
 */
static void timer_stat_sort_freq_add(
	timer_stat_t **sorted,		/* timer stat sorted list */
	timer_stat_t *new)		/* timer stat to add */
{
	while (*sorted) {
		if (opt_flags & OPT_CUMULATIVE) {
			if ((*sorted)->info->total_events < new->info->total_events) {
				new->sorted_freq_next = *(sorted);
				break;
			}
		} else {
			if ((*sorted)->info->delta_events < new->info->delta_events) {
				new->sorted_freq_next = *(sorted);
				break;
			}
		}
		sorted = &(*sorted)->sorted_freq_next;
	}
	*sorted = new;
}

/*
 *  es_printf()
 *	eventstat printf - print to stdout or ncurses
 *	print depending on the mode
 */
static void es_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (curses_init) {
		char buf[256];

		vsnprintf(buf, sizeof(buf), fmt, ap);
		printw("%s", buf);
	} else {
		vprintf(fmt, ap);
	}
	va_end(ap);
}

/*
 *  timer_stat_dump()
 */
static OPTIMIZE3 void timer_stat_dump(
	const double duration,		/* time between each sample */
	const double time_delta,	/* how long been running sofar */
	const int32_t n_lines,		/* number of lines to output */
	const double whence,		/* nth sample */
	timer_stat_t *timer_stats[])	/* timer stats samples */
{
	size_t i;
	timer_stat_t *sorted = NULL;

	for (i = 0; i < TABLE_SIZE; i++) {
		timer_stat_t *ts;

		for (ts = timer_stats[i]; ts; ts = ts->next)
			timer_stat_sort_freq_add(&sorted, ts);
	}

	if (!(opt_flags & OPT_QUIET)) {
		uint64_t total = 0UL, kt_total = 0UL;
		int32_t j = 0;
		const int pid_size = pid_max_digits();
		int sz, ta_size, fn_size = 0;
		int fields;
		int min_width;

		eventstat_winsize();
		if (resized && curses_init) {
			resizeterm(rows, cols);
			refresh();
			resized = false;
		}

		if (!(opt_flags & OPT_BRIEF)) {
			fields++;
				fields++;
		}

		/* Minimum width w/o task or func info */
		min_width = EVENTS_WIDTH + 1 + \
			    1 + \
			    pid_size + 1;
		if (!(opt_flags & OPT_BRIEF)) {
			if (opt_flags & OPT_TIMER_ID)
				min_width += TIMER_ID_WIDTH + 1;
			fn_size = FUNC_WIDTH;
		}

		sz = cols - min_width;
		sz = (sz < 0) ? 0 : sz;

		if (fn_size) {
			fn_size += (sz >> 1);
			if (fn_size > FUNC_WIDTH_MAX)
				fn_size = FUNC_WIDTH_MAX;

			min_width += fn_size;
			sz = cols - min_width;
			sz = (sz < 0) ? 0 : sz;
		}
		ta_size = sz;
		if (ta_size < TASK_WIDTH)
			ta_size = TASK_WIDTH;
		
		es_printf("%*.*s %-*.*s %-*.*s",
			EVENTS_WIDTH, EVENTS_WIDTH,
			(opt_flags & OPT_CUMULATIVE) ?
				"Events" : "Event/s",
			pid_size, pid_size, "PID",
			ta_size, ta_size, "Task");
		if (!(opt_flags & OPT_BRIEF)) {
			if (opt_flags & OPT_TIMER_ID) {
				es_printf(" %-16.16s", "Timer ID");
			}
			es_printf("%-*.*s\n", fn_size, fn_size,
				" Init Function");
		} else {
			es_printf("\n");
		}

		while (sorted) {
			if (((n_lines == -1) || (j < n_lines)) &&
			    (sorted->info->delta_events != 0)) {
				char *task = (opt_flags & OPT_CMD) ?
					sorted->info->cmdline :
					sorted->info->task_mangled;
				if (!*task)
					task = sorted->info->task_mangled;

				j++;
				if (opt_flags & OPT_CUMULATIVE)
					es_printf("%*" PRIu64 " ",
						EVENTS_WIDTH,
						sorted->info->total_events);
				else
					es_printf("%*.2f ",
						EVENTS_WIDTH,
						(double)sorted->info->delta_events / duration);

				if (opt_flags & OPT_BRIEF) {

					es_printf("%*d %s\n",
						pid_size, sorted->info->pid,
						task);
				} else {
					es_printf("%*d %-*.*s",
						pid_size, sorted->info->pid,
						ta_size, ta_size, task);
					if (opt_flags & OPT_TIMER_ID) {
						es_printf(" %16" PRIx64,
							sorted->info->timer);
					}
					es_printf(" %-*.*s\n",
						fn_size - 1, fn_size - 1,
						sorted->info->func);
				}
			}
			total += sorted->info->delta_events;
			if (sorted->info->kernel_thread)
				kt_total += sorted->info->delta_events;
			sorted->info->delta_events = 0;
			sorted = sorted->sorted_freq_next;
		}
		eventstat_move(LINES - 1, 0);
		es_printf("%" PRIu64 " Total events, %5.2f events/sec "
			"(kernel: %5.2f, userspace: %5.2f)\n",
			total, (double)total / duration,
			(double)kt_total / duration,
			(double)(total - kt_total) / duration);
		if ((opt_flags & OPT_SHOW_WHENCE) && !curses_init) {
			time_t t = (time_t)whence;
			char *timestr = ctime(&t);
			char *pos = strchr(timestr, '\n');

			if (*pos)
				*pos = '\0';
			es_printf("Timestamp: %s, Total Run Duration: "
				"%.1f secs\n", timestr, time_delta);
		}

		if (!sane_procs)
			es_printf("Note: this was run inside a container, "
				"kernel tasks were guessed.\n");
		es_printf("\n");
	}
}

/*
 *  read_events()
 *	read in events data into a global read buffer.
 *	the buffer is auto-expanded where necessary and
 *	only free'd at exit time.  This way we can parse
 *	the data a little faster.
 */
static char *read_events(const double time_end)
{
	int fd;
	static size_t get_events_size;
	size_t size;

	if (get_events_buf == NULL) {
		if ((get_events_buf = malloc(EVENT_BUF_SIZE << 1)) == NULL)
			err_abort("Cannot read %s, out of memory\n",
				sys_tracing_pipe);

		get_events_size = (EVENT_BUF_SIZE << 1);
	}

	if ((fd = open(sys_tracing_pipe, O_RDONLY)) < 0)
		err_abort("Cannot open %s\n", sys_tracing_pipe);

	size = 0;
	while (!stop_eventstat) {
		ssize_t ret;
		int rc;
		static char buffer[EVENT_BUF_SIZE];
		const double duration = time_end - gettime_to_double();
		struct timeval tv;
		fd_set rfds;

		if (duration < 0.0)
			break;

		tv = double_to_timeval(duration);
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		errno = 0;
		rc = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (rc <= 0)
			break;
		if (!FD_ISSET(fd, &rfds))
			continue;
		ret = read(fd, buffer, sizeof(buffer));
		if (ret == 0)
			continue;
		if (ret < 0) {
			if (!stop_eventstat &&
			    ((errno == EINTR) ||
			     (errno != EAGAIN))) {
				continue;
			}
			break;
		}
		/* Do we need to expand the global buffer? */
		if (size + ret >= get_events_size) {
			char *tmpptr;

			get_events_size += (EVENT_BUF_SIZE << 1);
			tmpptr = realloc(get_events_buf, get_events_size + 1);
			if (!tmpptr) {
				(void)close(fd);
				err_abort("Cannot read %s, out of memory\n",
					sys_tracing_pipe);
			}
			get_events_buf = tmpptr;
		}
		memcpy(get_events_buf + size, buffer, ret);
		size += ret;
		*(get_events_buf + size) = '\0';
	}
	(void)close(fd);

	return get_events_buf;
}

/*
 *  get_events()
 *	parse /sys/kernel/debug/tracing/trace_pipe and populate
 *	a timer stat hash table with unique events
 */
static void get_events(
	timer_stat_t *timer_stats[],
	const double time_now,
	const double duration)
{
	const size_t app_name_len = strlen(app_name);
	const double time_end = time_now + duration - 0.05;
	char *tmpptr = read_events(time_end);

	if (!tmpptr)
		return;

	while (*tmpptr) {
		char *ptr, *eol = tmpptr;
		char task[64];
		char task_mangled[64];
		char func[64];
		char *cmdline;
		int mask;
		timer_info_t info;

		/* Find the end of a line */
		while (*eol) {
			if (*eol == '\n') {
				*eol = '\0';
				eol++;
				break;
			}
			eol++;
		}
		if (strstr(tmpptr, "hrtimer_start")) {
			memset(&info, 0, sizeof(info));
			memset(task, 0, sizeof(task));
			memset(func, 0, sizeof(func));

			/*
			 *  Parse something like the following:
			 *  gnome-shell-3515  [003] d.h. 101499.108349: hrtimer_start: hrtimer=ffff99979e2d4600 function=tick_sched_timer expires=101497144000000 softexpires=101497144000000
			 */
			if (sscanf(tmpptr, "%s %*s %*s %*f: hrtimer_start: hrtimer=%" PRIx64 " function=%s", task, &info.timer, func) != 3)
				goto next;
		} else {
			goto next;
		}

		/*
		 * task name in form: gnome-shell-3515, scan to end of
		 * string, then scan back to find start of PID
		 */
		ptr = task;
		while (*ptr)
			ptr++;
		ptr--;
		while (ptr >= task && (*ptr >= '0' && *ptr <= '9'))
			ptr--;

		*ptr = '\0';
		ptr++;

		if (sscanf(ptr, "%10d\n", &info.pid) != 1)
			goto next;
		if (info.pid == 0)
			goto next;

		/* Processes without a command line are kernel threads */
		cmdline = get_pid_cmdline(info.pid);
		info.kernel_thread = pid_a_kernel_thread(task, info.pid);

		/* Swapper is special, like all corner cases */
		if (strncmp(task, "swapper", 6) == 0)
			info.kernel_thread = true;

		mask = info.kernel_thread ? OPT_KERNEL : OPT_USER;
		if (!(opt_flags & mask))
			goto free_next;

		if (info.kernel_thread) {
			char tmp[sizeof(task)];

			strcpy(tmp, task);
			tmp[13] = '\0';
			snprintf(task_mangled, sizeof(task_mangled),
				"[%s]", tmp);
		} else {
			strcpy(task_mangled, task);
		}

		if (strncmp(task, app_name, app_name_len)) {
			info.task = task;
			info.cmdline = cmdline ? cmdline : task_mangled;
			info.task_mangled = task_mangled;
			info.func = func;
			info.time_total = 0.0;
			info.total_events = 1;
			info.ident = make_hash_ident(&info);
			timer_stat_add(timer_stats, &info, time_now, duration);
		}
free_next:
		free(cmdline);
next:
		tmpptr = eol;
	}
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", app_name, VERSION);
	printf("Usage: %s [options] [duration] [count]\n", app_name);
	printf("Options are:\n"
		"  -c\t\treport cumulative events rather than events per second.\n"
		"  -C\t\treport event count rather than event per second in CSV output.\n"
		"  -d\t\tremove pathname from long process name in CSV output.\n"
		"  -h\t\tprint this help.\n"
		"  -l\t\tuse long cmdline text from /proc/pid/cmdline for process name.\n"
		"  -n events\tspecifies number of events to display.\n"
		"  -q\t\trun quietly, useful with option -r.\n"
		"  -r filename\tspecifies a comma separated values (CSV) output file\n"
		"\t\tto dump samples into.\n"
		"  -s\t\tuse short process name from /proc/pid/cmdline for process name.\n"
		"  -S\t\tcalculate min, max, average and standard deviation in CSV\n"
		"\t\toutput.\n"
		"  -t threshold\tsamples less than the specified threshold are ignored.\n"
		"  -T\t\tenable \'top\' mode rather than a scrolling output.\n"
		"  -w\t\tadd time stamp (when events occurred) to output.\n");
}

/*
 *  handle_sigwinch()
 *	flag window resize on SIGWINCH
 */
static void handle_sigwinch(int sig)
{
	(void)sig;

	eventstat_winsize();

	resized = true;
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats;
	double duration_secs = 1.0, time_start, time_now;
	int64_t count = 1, t = 1;
	int32_t n_lines = -1;
	bool forever = true;
	bool redo = false;
	struct sigaction new_action;
	int i;

	for (;;) {
		int c = getopt(argc, argv, "bcCdksSlhin:qr:t:Tuw");
		if (c == -1)
			break;
		switch (c) {
		case 'b':
			opt_flags |= OPT_BRIEF;
			break;
		case 'c':
			opt_flags |= OPT_CUMULATIVE;
			break;
		case 'C':
			opt_flags |= OPT_SAMPLE_COUNT;
			break;
		case 'd':
			opt_flags |= OPT_DIRNAME_STRIP;
			break;
		case 'h':
			show_usage();
			eventstat_exit(EXIT_SUCCESS);
		case 'i':
			opt_flags |= OPT_TIMER_ID;
			break;
		case 'n':
			errno = 0;
			n_lines = (int32_t)strtol(optarg, NULL, 10);
			if (errno)
				err_abort("Invalid value for number "
					"of events to display\n");
			if (n_lines < 1)
				err_abort("-n option must be greater than 0\n");
			break;
		case 'S':
			opt_flags |= OPT_RESULT_STATS;
			break;
		case 't':
			opt_threshold = strtoull(optarg, NULL, 10);
			if (opt_threshold < 1)
				err_abort("-t threshold must be 1 or more.\n");
			break;
		case 'T':
			opt_flags |= OPT_TOP;
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'r':
			csv_results = optarg;
			break;
		case 's':
			opt_flags |= OPT_CMD_SHORT;
			break;
		case 'l':
			opt_flags |= OPT_CMD_LONG;
			break;
		case 'k':
			opt_flags |= OPT_KERNEL;
			break;
		case 'u':
			opt_flags |= OPT_USER;
			break;
		case 'w':
			opt_flags |= OPT_SHOW_WHENCE;
			break;
		default:
			show_usage();
			eventstat_exit(EXIT_FAILURE);
		}
	}

	if (!(opt_flags & (OPT_KERNEL | OPT_USER)))
		opt_flags |= (OPT_KERNEL | OPT_USER);

	if (optind < argc) {
		duration_secs = atof(argv[optind++]);
		if (duration_secs < 0.5)
			err_abort("Duration must 0.5 or more.\n");
	}

	if (optind < argc) {
		forever = false;
		errno = 0;
		count = (int64_t)strtoll(argv[optind++], NULL, 10);
		if (errno)
			err_abort("Invalid count value\n");
		if (count < 1)
			err_abort("Count must be > 0\n");
	}

	opt_threshold *= duration_secs;

	if (geteuid() != 0)
		err_abort("%s requires root privileges to gather "
			"trace event data\n", app_name);

	sane_procs = sane_proc_pid_info();
	if (!sane_procs)
		opt_flags &= ~(OPT_CMD_SHORT | OPT_CMD_LONG);

	memset(&new_action, 0, sizeof(new_action));
	for (i = 0; signals[i] != -1; i++) {
		new_action.sa_handler = handle_sig;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(signals[i], &new_action, NULL) < 0)
			err_abort("sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
	}

	if ((timer_stats = calloc(TABLE_SIZE, sizeof(timer_stat_t*))) == NULL)
		err_abort("Cannot allocate timer stats table\n");

	/* Should really catch signals and set back to zero before we die */
	set_tracing_enable("1\n", true);
	set_tracing_event();

	time_now = time_start = gettime_to_double();

	if (opt_flags & OPT_TOP) {
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = handle_sigwinch;
		if (sigaction(SIGWINCH, &sa, NULL) < 0)
			err_abort("sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
		initscr();
		cbreak();
		noecho();
		nodelay(stdscr, 1);
		keypad(stdscr, 1);
		curs_set(0);
		curses_init = true;
	}

	while (!stop_eventstat && (forever || count--)) {
		double secs, duration, time_delta;

		/* Timeout to wait for in the future for this sample */
		secs = time_start + ((double)t * duration_secs) - time_now;
		/* Play catch-up, probably been asleep */
		if (secs < 0.0) {
			t = ceil((time_now - time_start) / duration_secs);
			secs = time_start + ((double)t * duration_secs) - time_now;
			/* Really, it's impossible, but just in case.. */
			if (secs < 0.0)
				secs = 0.0;
		} else {
			if (!redo)
				t++;
		}

		redo = false;

		if (curses_init) {
			fd_set rfds;
			int ch, ret;
			struct timeval tv;

			memset(&tv, 0, sizeof(tv));

			FD_ZERO(&rfds);
			FD_SET(fileno(stdin), &rfds);

			ret = select(fileno(stdin) + 1, &rfds, NULL, NULL, &tv);
			ch = getch();
			if ((ch == 27) || (ch == 'q'))
				break;
			if (ret > 0)
				redo = true;
			if (ret < 0) {
				if (errno != EINTR) {
					eventstat_endwin();

					fprintf(stderr, "select() failed: "
						"errno=%d (%s)\n",
						errno, strerror(errno));
					goto abort;
				}
				redo = true;
			}
		}

		get_events(timer_stats, time_now, secs);

		duration = gettime_to_double() - time_now;
		duration = floor((duration * 1000.0) + 0.5) / 1000.0;
		time_now = gettime_to_double();
		time_delta = time_now - time_start;

		eventstat_clear();
		timer_stat_dump(duration, time_delta, n_lines, time_now, timer_stats);
		eventstat_refresh();
		timer_stat_free_contents(timer_stats);
		timer_info_purge_old(time_now);
	}
	eventstat_endwin();
abort:
	samples_dump(csv_results);

	timer_stat_free_contents(timer_stats);
	free(timer_stats);
	samples_free();
	timer_info_list_free();
	timer_stat_free_list_free();
	free(get_events_buf);

	eventstat_exit(EXIT_SUCCESS);
}
