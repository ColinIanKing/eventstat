/*
 * Copyright (C) 2011-2016 Canonical
 * Hugely modified parts from powertop-1.13, Copyright 2007, Intel Corporation
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
#define OPT_CMD			(OPT_CMD_SHORT | OPT_CMD_LONG)
#define OPT_SHOW_WHENCE		(0x00000400)
#define OPT_TOP			(0x00000800)

#define EVENT_BUF_SIZE		(8192)
#define TIMER_REAP_AGE		(600)	/* Age of timer before it is reaped */
#define TIMER_REAP_THRESHOLD	(30)

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

typedef struct timer_info {
	struct timer_info *next;	/* Next in list */
	struct timer_info *hash_next;	/* Next in hash list */
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char 		*task_mangled;	/* Modified name of process/kernel */
	char		*cmdline;	/* From /proc/$pid/cmdline */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	bool		kernel_thread;	/* True if task is a kernel thread */
	uint32_t	ref_count;	/* timer stat reference count */
	uint64_t	total;		/* Total number of events */
	double		time_total;	/* Total time */
	double		last_used;	/* Last referenced */
} timer_info_t;

typedef struct timer_stat {
	struct timer_stat *next;	/* Next timer stat in hash table */
	struct timer_stat *sorted_freq_next; /* Next timer stat in event frequency sorted list */
	uint64_t	count;		/* Number of events */
	int64_t		delta;		/* Change in events since last time */
	double		time;		/* Time of sample */
	double		time_delta;	/* Change in time since last time */
	timer_info_t	*info;		/* Timer info */
} timer_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	struct sample_delta_item *next;	/* next in list */
	int64_t		delta;		/* difference in timer events between old and new */
	double		time_delta;	/* difference in time between old and new */
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

static const char *app_name = "eventstat";
static const char *proc_timer_stats = "/proc/timer_stats";

static timer_stat_t *timer_stat_free_list; /* free list of timer stats */
static timer_info_t *timer_info_list;	/* cache list of timer_info */
static timer_info_t *timer_info_hash[TABLE_SIZE]; /* hash of timer_info */
static sample_delta_list_t *sample_delta_list;	/* list of samples, sorted in sample time order */
static char *csv_results;		/* results in comma separated values */
static char *get_events_buf;		/* buffer to glob events into */
static double  opt_threshold;		/* ignore samples with event delta less than this */
static uint32_t timer_info_list_length;	/* length of timer_info_list */
static uint32_t opt_flags;		/* option flags */
static volatile bool stop_eventstat = false;	/* set by sighandler */
static bool sane_procs;			/* false if we are in a container */
static bool resized;			/* window resized */
static bool curses_init;		/* curses initialised */

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
	}
	return hash % TABLE_SIZE;
}

/*
 *  eventstat_clear();
 *  	clear screen if in top mode
 */
static void eventstat_clear(void)
{
	if (curses_init)
		clear();
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
static void __attribute__ ((noreturn)) err_abort(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	eventstat_endwin();
	vfprintf(stderr,fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

/*
 *  set_timer_stat()
 *	enable/disable timer stat
 */
static void set_timer_stat(const char *str, const bool carp)
{
	int fd;
	const ssize_t len = (ssize_t)strlen(str);

	if ((fd = open(proc_timer_stats, O_WRONLY, S_IRUSR | S_IWUSR)) < 0) {
		if (carp) {
			err_abort("Cannot open %s, errno=%d (%s)\n",
				proc_timer_stats, errno, strerror(errno));
		}
		return;
	}
	if (write(fd, str, len) != len) {
		close(fd);
		if (carp) {
			err_abort("Cannot write to %s, errno=%d (%s)\n",
				proc_timer_stats, errno, strerror(errno));
		}
		return;
	}
	(void)close(fd);
}

/*
 *  eventstat_exit()
 *	exit and set timer stat to 0
 */
static void __attribute__ ((noreturn)) eventstat_exit(const int status)
{
	set_timer_stat("0\n", false);
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
	set_timer_stat("0\n", false);
}

/*
 *  samples_free()
 *	free collected samples
 */
static inline void samples_free(void)
{
	sample_delta_list_t *sdl = sample_delta_list;

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
static void sample_add(
	timer_stat_t *timer_stat,
	const double whence)
{
	bool	found = false;
	sample_delta_list_t *sdl;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (sdl = sample_delta_list; sdl; sdl = sdl->next) {
		if (sdl->whence == whence) {
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
		sdl->next = sample_delta_list;
		sample_delta_list = sdl;
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL)
		err_abort("Cannot allocate sample delta item\n");
	sdi->delta = timer_stat->delta;
	sdi->time_delta = timer_stat->time_delta;
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
	timer_info_t **info1 = (timer_info_t **)item1;
	timer_info_t **info2 = (timer_info_t **)item2;

	if ((*info2)->total == (*info1)->total)
		return 0;

	return ((*info2)->total > (*info1)->total) ? 1 : -1;
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
static bool pid_a_kernel_thread(
	const char *cmdline,
	const char *task,
	const pid_t id)
{
	pid_t pgid;

	if (sane_procs && (cmdline != NULL))
		return (*cmdline == '\0');

	/* We are either in a container, or with a task with a NULL cmdline */
	pgid = getpgid(id);
	if (pgid >= 0)
		return (pgid == 0);

	/* Can't get pgid on that pid, so make a guess */
	return pid_a_kernel_thread_guess(task);
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
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
	size_t i = 0;
	size_t n;
	FILE *fp;
	uint64_t count = 0;
	double first_time = -1.0;
	double duration;
	timer_info_t *info;
	sample_delta_list_t *sdl;

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	if ((sorted_timer_infos = calloc(timer_info_list_length, sizeof(timer_info_t*))) == NULL)
		err_abort("Cannot allocate buffer for sorting timer_infos\n");

	/* Just want the timers with some non-zero total */
	for (n = 0, info = timer_info_list; info; info = info->next) {
		if (info->total > 0)
			sorted_timer_infos[n++] = info;
	}

	qsort(sorted_timer_infos, n, sizeof(timer_info_t *), info_compare_total);

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

	fprintf(fp, ",Callback:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->callback);
	fprintf(fp, "\n");

	fprintf(fp, ",Total:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%" PRIu64, sorted_timer_infos[i]->total);
	fprintf(fp, "\n");

	for (sdl = sample_delta_list; sdl; sdl= sdl->next) {
		time_t t = (time_t)sdl->whence;
		struct tm *tm;

		count++;
		tm = localtime(&t);
		fprintf(fp, "%2.2d:%2.2d:%2.2d",
			tm->tm_hour, tm->tm_min, tm->tm_sec);

		if (first_time < 0)
			first_time = sdl->whence;
		fprintf(fp, ",%f", duration_round(sdl->whence - first_time));

		/* Scan in timer info order to be consistent for all sdl rows */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi =
				sample_find(sdl, sorted_timer_infos[i]);
			/*
			 *  duration - if -C option is used then don't scale
			 *  by the per sample duration time, instead give the
			 *  raw sample count by scaling by 1.0 (i.e. no scaling)
			 */
			if (sdi) {
				duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
				fprintf(fp, ",%f", duration == 0.0 ? 0.0 :
					(double)sdi->delta / duration);
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
			sample_delta_list_t *sdl;

			for (sdl = sample_delta_list; sdl; sdl = sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);

				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double val = (duration == 0.0) ?
						0.0 : sdi->delta / duration;
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
			sample_delta_list_t *sdl;

			for (sdl = sample_delta_list; sdl; sdl= sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);

				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double val = (duration == 0.0) ?
						0.0 : sdi->delta / duration;
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
				(double)sorted_timer_infos[i]->total / count);
		fprintf(fp, "\n");

		/*
		 *  population standard deviation
		 */
		fprintf(fp, ",Std.Dev.:");
		for (i = 0; i < n; i++) {
			double average = (double)
				sorted_timer_infos[i]->total / (double)count;
			double sum = 0.0;
			sample_delta_list_t *sdl;

			for (sdl = sample_delta_list; sdl; sdl = sdl->next) {
				sample_delta_item_t *sdi =
					sample_find(sdl, sorted_timer_infos[i]);
				if (sdi) {
					double duration = duration_round((opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : sdi->time_delta);
					double diff = duration == 0.0 ? 0.0 :
						((double)sdi->delta - average) / duration;
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
	const double time_now)
{
	timer_info_t *info;
	const uint32_t h = hash_djb2a(ident);

	for (info = timer_info_hash[h]; info; info = info->hash_next) {
		if (strcmp(ident, info->ident) == 0) {
			info->last_used = time_now;
			return info;
		}
	}
	if ((info = calloc(1, sizeof(timer_info_t))) == NULL)
		err_abort("Cannot allocate timer info\n");

	info->pid = new_info->pid;
	info->task = strdup(new_info->task);
	info->task_mangled = strdup(new_info->task_mangled);
	info->cmdline = strdup(new_info->cmdline);
	info->func = strdup(new_info->func);
	info->callback = strdup(new_info->callback);
	info->ident = strdup(ident);
	info->kernel_thread = new_info->kernel_thread;
	info->total = new_info->total;
	info->time_total = new_info->time_total;
	info->last_used = time_now;
	info->ref_count = 0;

	if (info->task == NULL ||
	    info->task_mangled == NULL ||
	    info->cmdline == NULL ||
	    info->func == NULL ||
	    info->callback == NULL ||
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
	free(info->callback);
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
 *  	clean out old timer infos
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
	static char ident[1024];

	snprintf(ident, sizeof(ident), "%x%s%8.8s%8.8s%s",
		info->pid, info->task, info->func,
		info->callback, info->cmdline);
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
static void timer_stat_free_contents(
	timer_stat_t *timer_stats[])	/* timer stat hash table */
{
	int i;

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
	const double time_now,		/* time sample was taken */
	timer_info_t *info)		/* timer info to be added */
{
	const char *ident = make_hash_ident(info);
	const uint32_t h = hash_djb2a(ident);
	timer_stat_t *ts, *ts_new;

	for (ts = timer_stats[h]; ts; ts = ts->next) {
		if (strcmp(ts->info->ident, ident) == 0) {
			ts->count += info->total;
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

	ts_new->count = info->total;
	ts_new->info = timer_info_find(info, ident, time_now);
	ts_new->info->ref_count++;
	ts_new->next = timer_stats[h];
	ts_new->time = time_now;
	ts_new->sorted_freq_next = NULL;
	timer_stats[h] = ts_new;
}

/*
 *  timer_stat_find()
 *	find a timer stat (needle) in a timer stat hash table (haystack)
 */
static OPTIMIZE3 timer_stat_t *timer_stat_find(
	timer_stat_t *haystack[],	/* timer stat hash table */
	timer_stat_t *needle)		/* timer stat to find */
{
	timer_stat_t *ts;
	const char *ident = make_hash_ident(needle->info);

	for (ts = haystack[hash_djb2a(ident)]; ts; ts = ts->next) {
		if (strcmp(ts->info->ident, ident) == 0)
			return ts;
	}

	return NULL;	/* no success */
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
			if ((*sorted)->count < new->count) {
				new->sorted_freq_next = *(sorted);
				break;
			}
		} else {
			if ((*sorted)->delta < new->delta) {
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
 *  timer_stat_diff()
 *	find difference in event count between to hash table samples of timer
 *	stats.  We are interested in just current and new timers, not ones that
 *	silently die
 */
static OPTIMIZE3 void timer_stat_diff(
	const double duration,		/* time between each sample */
	const double time_delta,	/* how long been running sofar */
	const int32_t n_lines,		/* number of lines to output */
	const double whence,		/* nth sample */
	timer_stat_t *timer_stats_old[],/* old timer stats samples */
	timer_stat_t *timer_stats_new[])/* new timer stats samples */
{
	int i;
	timer_stat_t *sorted = NULL;

	for (i = 0; i < TABLE_SIZE; i++) {
		timer_stat_t *ts;

		for (ts = timer_stats_new[i]; ts; ts = ts->next) {
			ts->info->last_used = whence;
			timer_stat_t *found =
				timer_stat_find(timer_stats_old, ts);
			if (found) {
				found->info->last_used = whence;
				ts->delta = ts->count - found->count;
				ts->time_delta = ts->time - found->time;
				if (ts->delta >= opt_threshold) {
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
					found->info->total += ts->delta;
					found->info->time_total += ts->time_delta;
				}
			} else {
				ts->delta = ts->count;
				ts->time_delta = duration;
				if (ts->delta >= opt_threshold) {
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		uint64_t total = 0UL, kt_total = 0UL;
		int32_t j = 0;

		es_printf("%8s %-5s %-15s",
			(opt_flags & OPT_CUMULATIVE) ?
				"Events" : "Event/s", "PID", "Task");
		if (!(opt_flags & OPT_BRIEF))
			es_printf(" %-25s %-s\n",
				"Init Function", "Callback");
		else
			es_printf("\n");

		while (sorted) {
			if (((n_lines == -1) || (j < n_lines)) &&
			    (sorted->delta != 0)) {
				j++;
				if (opt_flags & OPT_CUMULATIVE)
					es_printf("%8" PRIu64 " ",
						sorted->count);
				else
					es_printf("%8.2f ", (double)sorted->delta / duration);

				if (opt_flags & OPT_BRIEF) {
					char *cmd = sorted->info->cmdline;

					es_printf("%5d %s\n",
						sorted->info->pid,
						(opt_flags & OPT_CMD) ?
							cmd : sorted->info->task_mangled);
				} else {
					es_printf("%5d %-15s %-25s %-s\n",
						sorted->info->pid,
						sorted->info->task_mangled,
						sorted->info->func,
						sorted->info->callback);
				}
			}
			total += sorted->delta;
			if (sorted->info->kernel_thread)
				kt_total += sorted->delta;

			sorted = sorted->sorted_freq_next;
		}
		if (opt_flags & OPT_TOP)
			move(LINES - 1, 0);
		es_printf("%" PRIu64 " Total events, %5.2f events/sec "
			"(kernel: %5.2f, userspace: %5.2f)\n",
			total, (double)total / duration,
			(double)kt_total / duration,
			(double)(total - kt_total) / duration);
		if ((opt_flags & OPT_SHOW_WHENCE) &&
		    (!(opt_flags & OPT_TOP))) {
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
static char *read_events(void)
{
	int fd;
	static size_t get_events_size;
	size_t size;

	if (get_events_buf == NULL) {
		if ((get_events_buf = malloc(EVENT_BUF_SIZE << 1)) == NULL)
			err_abort("Cannot read %s, out of memory\n",
				proc_timer_stats);

		get_events_size = (EVENT_BUF_SIZE << 1);
	}

	if ((fd = open(proc_timer_stats, O_RDONLY)) < 0)
		err_abort("Cannot open %s\n", proc_timer_stats);

	size = 0;
	for (;;) {
		ssize_t ret;
		char buffer[EVENT_BUF_SIZE];

		ret = read(fd, buffer, sizeof(buffer));
		if (ret == 0)
			break;
		if (ret < 0) {
			if ((errno == EINTR) ||
			    (errno != EAGAIN)) {
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
					proc_timer_stats);
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
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
static void get_events(
	timer_stat_t *timer_stats[],
	const double time_now)
{
	char *tmpptr;
	const size_t app_name_len = strlen(app_name);

	if ((tmpptr = read_events()) == NULL)
		return;

	while (*tmpptr) {
		char *ptr = tmpptr, *eol = tmpptr;
		char task[64];
		char task_mangled[64];
		char func[64];
		char callback[64];
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

		/* Is this the last line we want to parse? */
		if (strstr(tmpptr, "total events") != NULL)
			break;

		/* Looking for a format: "count[D], pid, task, func (timer)" */
		while (*ptr && *ptr != ',')
			ptr++;
		if (*ptr != ',')
			goto next;
		if (ptr > tmpptr && *(ptr - 1) == 'D')
			goto next;	/* Deferred event, skip */

		/* Now we're ready to fetch info fields */
		memset(&info, 0, sizeof(info));

		ptr++;
		if (sscanf(tmpptr, "%21" SCNu64, &info.total) != 1)
			goto next;
		memset(task, 0, sizeof(task));
		memset(func, 0, sizeof(func));
		memset(callback, 0, sizeof(callback));
		info.pid = -1;
		if (sscanf(ptr, "%10d %63s %63s (%63[^)])",
		    &info.pid, task, func, callback) != 4)
			goto next;

		/* Processes without a command line are kernel threads */
		cmdline = get_pid_cmdline(info.pid);
		info.kernel_thread = pid_a_kernel_thread(cmdline, task, info.pid);

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
			snprintf(task_mangled, sizeof(task_mangled), "[%s]", tmp);
		} else {
			strcpy(task_mangled, task);
		}

		if (strcmp(task, "insmod") == 0)
			strncpy(task, "[kern mod]", 13);
		if (strcmp(task, "modprobe") == 0)
			strncpy(task, "[kern mod]", 13);

		if (strncmp(func, "tick_nohz_", 10) &&
		    strncmp(func, "tick_setup_sched_timer", 20) &&
		    strncmp(task, app_name, app_name_len)) {
			info.task = task;
			info.cmdline = cmdline ? cmdline : task_mangled;
			info.task_mangled = task_mangled;
			info.func = func;
			info.callback = callback;
			info.ident = tmpptr;
			info.time_total = 0.0;
			timer_stat_add(timer_stats, time_now, &info);
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
		"  -l\t\tuse long cmdline text from /proc/pid/cmdline in CSV output.\n"
		"  -n events\tspecifies number of events to display.\n"
		"  -q\t\trun quietly, useful with option -r.\n"
		"  -r filename\tspecifies a comma separated values (CSV) output file\n"
		"\t\tto dump samples into.\n"
		"  -s\t\tuse short process name from /proc/pid/cmdline in CSV output.\n"
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

	resized = true;
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	double duration_secs = 1.0, time_start, time_now;
	int64_t count = 1, t = 1;
	int32_t n_lines = -1;
	bool forever = true;
	bool redo = false;
	struct sigaction new_action;
	int i;

	for (;;) {
		int c = getopt(argc, argv, "bcCdksSlhn:qr:t:Tuw");
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
		case 'n':
			errno = 0;
			n_lines = (int32_t)strtol(optarg, NULL, 10);
			if (errno)
				err_abort("Invalid value for number "
					"of events to display\n");
			if (n_lines < 1)
				err_abort("-n option must be greater than 0\n");
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
		case 'S':
			opt_flags |= OPT_RESULT_STATS;
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
		err_abort("%s requires root privileges to write to %s\n",
			app_name, proc_timer_stats);

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

	if ((timer_stats_old = calloc(TABLE_SIZE, sizeof(timer_stat_t*))) == NULL)
		err_abort("Cannot allocate old timer stats table\n");
	if ((timer_stats_new = calloc(TABLE_SIZE, sizeof(timer_stat_t*))) == NULL)
		err_abort("Cannot allocate old timer stats table\n");

	/* Should really catch signals and set back to zero before we die */
	set_timer_stat("1\n", true);
	time_now = time_start = gettime_to_double();

	get_events(timer_stats_old, time_now);

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
		struct timeval tv;
		double secs, duration, time_delta;
		int ret;

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
		tv = double_to_timeval(secs);

		if (curses_init) {
			fd_set rfds;
			int ch;

			FD_ZERO(&rfds);
			FD_SET(fileno(stdin), &rfds);

			ret = select(fileno(stdin) + 1, &rfds, NULL, NULL, &tv);
			ch = getch();
			if ((ch == 27) || (ch == 'q'))
				break;
			if (resized) {
				struct winsize ws;
				if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1) {
					resizeterm(ws.ws_row, ws.ws_col);
					refresh();
				}
				resized = false;
			}
			if (ret > 0)
				redo = true;
		} else {
			ret = select(0, NULL, NULL, NULL, &tv);
		}

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

		duration = gettime_to_double() - time_now;
		duration = floor((duration * 1000.0) + 0.5) / 1000.0;
		time_now = gettime_to_double();
		time_delta = time_now - time_start;

		get_events(timer_stats_new, time_now);
		eventstat_clear();
		timer_stat_diff(duration, time_delta, n_lines, time_now,
			timer_stats_old, timer_stats_new);
		if (opt_flags & OPT_TOP)
			refresh();
		timer_stat_free_contents(timer_stats_old);

		tmp             = timer_stats_old;
		timer_stats_old = timer_stats_new;
		timer_stats_new = tmp;

		timer_info_purge_old(time_now);
	}
	eventstat_endwin();
abort:
	samples_dump(csv_results);

	timer_stat_free_contents(timer_stats_old);
	timer_stat_free_contents(timer_stats_new);
	free(timer_stats_old);
	free(timer_stats_new);
	samples_free();
	timer_info_list_free();
	timer_stat_free_list_free();
	free(get_events_buf);

	eventstat_exit(EXIT_SUCCESS);
}
