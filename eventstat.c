/*
 * Copyright (C) 2011-2013 Canonical
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <math.h>

#define APP_NAME		"eventstat"
#define TIMER_STATS		"/proc/timer_stats"
#define TABLE_SIZE		(32771)		/* Should be a prime */

#define OPT_QUIET		(0x00000001)
#define OPT_CUMULATIVE		(0x00000002)
#define OPT_CMD_SHORT		(0x00000004)
#define OPT_CMD_LONG		(0x00000008)
#define OPT_DIRNAME_STRIP	(0x00000010)
#define OPT_SAMPLE_COUNT	(0x00000020)
#define OPT_RESULT_STATS	(0x00000040)
#define OPT_CMD			(OPT_CMD_SHORT | OPT_CMD_LONG)

typedef struct link {
	void *data;			/* Data in list */
	struct link *next;		/* Next item in list */
} link_t;

typedef struct {
	link_t	*head;			/* Head of list */
	link_t	*tail;			/* Tail of list */
	size_t	length;			/* Length of list */
} list_t;

typedef void (*list_link_free_t)(void *);

typedef struct timer_info {
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*cmdline;	/* From /proc/$pid/cmdline */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	bool		kernel_thread;	/* True if task is a kernel thread */
	unsigned long	total;		/* Total number of events */
} timer_info_t;

typedef struct timer_stat {
	unsigned long	count;		/* Number of events */
	unsigned long	delta;		/* Change in events since last time */
	timer_info_t	*info;		/* Timer info */
	struct timer_stat *next;	/* Next timer stat in hash table */
	struct timer_stat *sorted_freq_next;	/* Next timer stat in event frequency sorted list */
} timer_stat_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	unsigned long	delta;		/* difference in timer events between old and new */
	timer_info_t	*info;		/* timer this refers to */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	struct timeval 	whence;		/* when the sample was taken */
	list_t		list;
} sample_delta_list_t;

typedef struct {
	char *task;			/* Name of kernel task */
	size_t len;			/* Length */
} kernel_task_info;

#define KERN_TASK_INFO(str)		{ str, sizeof(str) - 1 }

static list_t timer_info_list;		/* cache list of timer_info */
static list_t sample_list;		/* list of samples, sorted in sample time order */
static char *csv_results;		/* results in comma separated values */
static volatile bool stop_eventstat = false;	/* set by sighandler */
static double  opt_threshold;		/* ignore samples with event delta less than this */
static unsigned int opt_flags;		/* option flags */
static bool sane_procs;			/* false if we are in a container */

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

	fclose(fp);

	return ret;
}

/*
 *  timeval_sub()
 *	timeval a - b
 */
static struct timeval timeval_sub(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret, _b;

	_b.tv_sec = b->tv_sec;
	_b.tv_usec = b->tv_usec;

	if (a->tv_usec < _b.tv_usec) {
		int nsec = ((_b.tv_usec - a->tv_usec) / 1000000) + 1;
		_b.tv_sec += nsec;
		_b.tv_usec -= (1000000 * nsec);
	}
	if (a->tv_usec - _b.tv_usec > 1000000) {
		int nsec = (a->tv_usec - _b.tv_usec) / 1000000;
		_b.tv_sec -= nsec;
		_b.tv_usec += (1000000 * nsec);
	}

	ret.tv_sec = a->tv_sec - _b.tv_sec;
	ret.tv_usec = a->tv_usec - _b.tv_usec;

	return ret;
}

/*
 *  timeval_add()
 *	timeval a + b
 */
static struct timeval timeval_add(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret;

	ret.tv_sec = a->tv_sec + b->tv_sec;
	ret.tv_usec = a->tv_usec + b->tv_usec;
	if (ret.tv_usec > 1000000) {
		int nsec = (ret.tv_usec / 1000000);
		ret.tv_sec += nsec;
		ret.tv_usec -= (1000000 * nsec);
	}

	return ret;
}

/*
 *  timeval_double
 *	timeval to a double
 */
static inline double timeval_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  set_timer_stat()
 *	enable/disable timer stat
 */
static void set_timer_stat(const char *str, const bool carp)
{
	FILE *fp;

	if ((fp = fopen(TIMER_STATS, "w")) == NULL) {
		if (carp) {
			fprintf(stderr, "Cannot write to %s\n",TIMER_STATS);
			exit(EXIT_FAILURE);
		} else {
			return;
		}
	}
	fprintf(fp, "%s\n", str);
	fclose(fp);
}

/*
 *  Stop gcc complaining about no return func
 */
static void eventstat_exit(const int status) __attribute__ ((noreturn));

/*
 *  eventstat_exit()
 *	exit and set timer stat to 0
 */
static void eventstat_exit(const int status)
{
	set_timer_stat("0", false);

	exit(status);
}

/*
 *  list_init()
 *	initialize list
 */
static inline void list_init(list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

/*
 *  list_append()
 *	add a new item to end of the list
 */
static link_t *list_append(list_t *list, void *data)
{
	link_t *link;

	if ((link = calloc(1, sizeof(link_t))) == NULL) {
		fprintf(stderr, "Cannot allocate list link\n");
		eventstat_exit(EXIT_FAILURE);
	}
	link->data = data;

	if (list->head == NULL) {
		list->head = link;
	} else {
		list->tail->next = link;
	}
	list->tail = link;
	list->length++;

	return link;
}

/*
 *  list_free()
 *	free the list
 */
static void list_free(list_t *list, const list_link_free_t freefunc)
{
	link_t	*link, *next;

	if (list == NULL)
		return;

	for (link = list->head; link; link = next) {
		next = link->next;
		if (link->data && freefunc)
			freefunc(link->data);
		free(link);
	}
}

/*
 *  handle_sigint()
 *      catch SIGINT and flag a stop
 */
static void handle_sigint(int dummy)
{
	(void)dummy;	/* Stop unused parameter warning with -Wextra */

	stop_eventstat = true;
}

/*
 *  sample_delta_free()
 *	free the sample delta list
 */
static void sample_delta_free(void *data)
{
	sample_delta_list_t *sdl = (sample_delta_list_t*)data;

	list_free(&sdl->list, free);
	free(sdl);
}

/*
 *  samples_free()
 *	free collected samples
 */
static void samples_free(void)
{
	list_free(&sample_list, sample_delta_free);
}

/*
 *  sample_add()
 *	add a timer_stat's delta and info field to a list at time position whence
 */
static void sample_add(timer_stat_t *timer_stat, struct timeval *whence)
{
	link_t	*link;
	bool	found = false;
	sample_delta_list_t *sdl = NULL;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
		if ((sdl->whence.tv_sec == whence->tv_sec) &&
		    (sdl->whence.tv_usec == whence->tv_usec)) {
			found = true;
			break;
		}
	}

	/*
	 * New time period, need new sdl, we assume it goes at the end of the
	 * list since time is assumed to be increasing
	 */
	if (!found) {
		if ((sdl = calloc(1, sizeof(sample_delta_list_t))) == NULL) {
			fprintf(stderr, "Cannot allocate sample delta list\n");
			eventstat_exit(EXIT_FAILURE);
		}
		sdl->whence = *whence;
		list_append(&sample_list, sdl);
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate sample delta item\n");
		eventstat_exit(EXIT_FAILURE);
	}
	sdi->delta = timer_stat->delta;
	sdi->info  = timer_stat->info;

	list_append(&sdl->list, sdi);
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for timer info, return NULL if not found
 */
inline static sample_delta_item_t *sample_find(sample_delta_list_t *sdl, const timer_info_t *info)
{
	link_t *link;

	for (link = sdl->list.head; link; link = link->next) {
		sample_delta_item_t *sdi = (sample_delta_item_t*)link->data;
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

	return (*info2)->total - (*info1)->total;
}

/*
 *  pid_a_kernel_thread
 *
 */
static bool pid_a_kernel_thread(const char *task, const pid_t id)
{
	char buffer[128];
	char path[32];

	if (sane_procs) {
		snprintf(buffer, sizeof(buffer), "/proc/%d/exe", id);
		if (readlink(buffer, path, sizeof(path)) < 0)
			if (errno == ENOENT)
				return true;
	} else {
		/* In side a container, make a guess at kernel threads */
		int i;

		/*
		 * This is not exactly accurate, but if we can't look up
		 * a process then try and infer something from the comm field.
		 * Until we have better kernel support to map /proc/timer_stats
		 * pids to containerised pids this is the best we can do.
		 */
		static kernel_task_info kernel_tasks[] = {
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

		for (i = 0; kernel_tasks[i].task != NULL; i++) {
			if (strncmp(task, kernel_tasks[i].task, kernel_tasks[i].len) == 0)
				return true;
		}
	}

	return false;
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

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}

	close(fd);

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

/*
 *  samples_dump()
 *	dump out collected sample information
 */
static void samples_dump(const char *filename, const struct timeval *duration)
{
	sample_delta_list_t	*sdl;
	timer_info_t **sorted_timer_infos;
	link_t	*link;
	size_t i = 0;
	size_t n = timer_info_list.length;
	FILE *fp;
	unsigned long count = 0;
	double dur;
	bool dur_zero;

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	if ((sorted_timer_infos = calloc(n, sizeof(timer_info_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate buffer for sorting timer_infos\n");
		eventstat_exit(EXIT_FAILURE);
	}

	/* Just want the timers with some non-zero total */
	for (n = 0, link = timer_info_list.head; link; link = link->next) {
		timer_info_t *info = (timer_info_t*)link->data;
		if (info->total > 0)
			sorted_timer_infos[n++] = info;
	}

	qsort(sorted_timer_infos, n, sizeof(timer_info_t *), info_compare_total);

	fprintf(fp, "Task:");
	for (i = 0; i < n; i++) {
		char *task;

		if ((opt_flags & OPT_CMD) && (sorted_timer_infos[i]->cmdline != NULL))
			task = sorted_timer_infos[i]->cmdline;
		else
			task = sorted_timer_infos[i]->task;

		fprintf(fp, ",%s", task);
	}
	fprintf(fp, "\n");

	fprintf(fp, "Init Function:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->func);
	fprintf(fp, "\n");

	fprintf(fp, "Callback:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->callback);
	fprintf(fp, "\n");

	fprintf(fp, "Total:");
	for (i = 0; i < n; i++)
		fprintf(fp, ",%lu", sorted_timer_infos[i]->total);
	fprintf(fp, "\n");

	/*
	 *  duration - if -C option is used then don't scale by the
	 *  per sample duration time, instead give the raw sample count
	 *  by scaling by 1.0 (i.e. no scaling).
	 */
	dur = (opt_flags & OPT_SAMPLE_COUNT) ? 1.0 : timeval_double(duration);
	dur_zero = (duration->tv_sec == 0) && (duration->tv_usec == 0);

	for (link = sample_list.head; link; link = link->next) {
		count++;
		sdl = (sample_delta_list_t*)link->data;
		fprintf(fp, "%f", timeval_double(&sdl->whence));

		/* Scan in timer info order to be consistent for all sdl rows */
		for (i = 0; i < n; i++) {
			sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
			if (sdi)
				fprintf(fp, ",%f", dur_zero ? 0.0 : (double)sdi->delta / dur);
			else
				fprintf(fp, ",%f", 0.0);
		}
		fprintf(fp, "\n");
	}

	/*
	 *  -S option - some statistics, min, max, average, std.dev.
	 */
	if (opt_flags & OPT_RESULT_STATS) {
		fprintf(fp, "Min:");
		for (i = 0; i < n; i++) {
			unsigned long min = ~0;

			for (link = sample_list.head; link; link = link->next) {
				sdl = (sample_delta_list_t*)link->data;
				sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
				if (sdi && min > sdi->delta)
					min = sdi->delta;
			}
			fprintf(fp, ",%f", dur_zero ? 0.0 : (double)min / dur);
		}
		fprintf(fp, "\n");

		fprintf(fp, "Max:");
		for (i = 0; i < n; i++) {
			unsigned long max = 0;

			for (link = sample_list.head; link; link = link->next) {
				sdl = (sample_delta_list_t*)link->data;
				sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
				if (sdi && max < sdi->delta)
					max = sdi->delta;
			}
			fprintf(fp, ",%f", dur_zero ? 0.0 : (double)max / dur);
		}
		fprintf(fp, "\n");

		fprintf(fp, "Average:");
		for (i = 0; i < n; i++)
			fprintf(fp, ",%f", dur_zero ? 0.0 : ((double)sorted_timer_infos[i]->total / dur) / (double)count);
		fprintf(fp, "\n");

		/*
		 *  population standard deviation
		 */
		fprintf(fp, "Std.Dev.:");
		for (i = 0; i < n; i++) {
			double average = (double)sorted_timer_infos[i]->total / (double)count;
			double sum = 0.0;

			for (link = sample_list.head; link; link = link->next) {
				sdl = (sample_delta_list_t*)link->data;
				sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
				if (sdi) {
					double diff = dur_zero ? 0.0 : ((double)sdi->delta - average) / dur;
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
	fclose(fp);
}

/*
 *  timer_info_find()
 *	try to find existing timer info in cache, and to the cache
 *	if it is new.
 */
static timer_info_t *timer_info_find(const timer_info_t *new_info)
{
	link_t *link;
	timer_info_t *info;

	for (link = timer_info_list.head; link; link = link->next) {
		info = (timer_info_t*)link->data;
		if (strcmp(new_info->ident, info->ident) == 0)
			return info;
	}

	if ((info = calloc(1, sizeof(timer_info_t))) == NULL) {
		fprintf(stderr, "Cannot allocate timer info\n");
		eventstat_exit(EXIT_FAILURE);
	}

	info->pid = new_info->pid;
	info->task = strdup(new_info->task);
	if (opt_flags & OPT_CMD)
		info->cmdline = get_pid_cmdline(new_info->pid);

	info->func = strdup(new_info->func);
	info->callback = strdup(new_info->callback);
	info->ident = strdup(new_info->ident);
	info->kernel_thread = new_info->kernel_thread;
	info->total = new_info->total;

	if (info->task == NULL ||
	    info->func == NULL ||
	    info->callback == NULL ||
	    info->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat fields\n");
		eventstat_exit(EXIT_FAILURE);
	}

	/* Does not exist in list, append it */

	list_append(&timer_info_list, info);

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
	free(info->cmdline);
	free(info->func);
	free(info->callback);
	free(info->ident);
	free(info);
}

/*
 *  timer_info_free
 *	free up all unique timer infos
 */
static void timer_info_list_free(void)
{
	list_free(&timer_info_list, timer_info_free);
}

/*
 *  hash_pjw()
 *	Hash a string, from Aho, Sethi, Ullman, Compiling Techniques.
 */
static unsigned long hash_pjw(const char *str)
{
  	unsigned long h=0, g;

	while (*str) {
		h = (h << 4) + (*str);
		if (0 != (g = h&0xf0000000)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		str++;
	}

  	return h % TABLE_SIZE;
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
			free(ts);

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
	const unsigned long count,	/* event count */
	const pid_t pid,		/* PID of task */
	char *task,			/* Name of task */
	char *func,			/* Kernel function */
	char *callback,			/* Kernel timer callback */
	const bool kernel_thread)	/* Is a kernel thread */
{
	char buf[4096];
	timer_stat_t *ts;
	timer_stat_t *ts_new;
	timer_info_t info;
	unsigned long h;

	snprintf(buf, sizeof(buf), "%d:%s:%s:%s", pid, task, func, callback);
	h = hash_pjw(buf);
	ts = timer_stats[h];

	for (ts = timer_stats[h]; ts; ts = ts->next) {
		if (strcmp(ts->info->ident, buf) == 0) {
			ts->count += count;
			return;
		}
	}
	/* Not found, it is new! */

	if ((ts_new = malloc(sizeof(timer_stat_t))) == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat\n");
		eventstat_exit(EXIT_FAILURE);
	}

	info.pid = pid;
	info.task = task;
	info.func = func;
	info.callback = callback;
	info.ident = buf;
	info.kernel_thread = kernel_thread;
	info.total = count;

	ts_new->count  = count;
	ts_new->info = timer_info_find(&info);
	ts_new->next  = timer_stats[h];
	ts_new->sorted_freq_next = NULL;

	timer_stats[h] = ts_new;
}

/*
 *  timer_stat_find()
 *	find a timer stat (needle) in a timer stat hash table (haystack)
 */
static timer_stat_t *timer_stat_find(
	timer_stat_t *haystack[],	/* timer stat hash table */
	timer_stat_t *needle)		/* timer stat to find */
{
	timer_stat_t *ts;
	char buf[4096];

	snprintf(buf, sizeof(buf), "%d:%s:%s:%s",
		needle->info->pid, needle->info->task,
		needle->info->func, needle->info->callback);

	for (ts = haystack[hash_pjw(buf)]; ts; ts = ts->next) {
		if (strcmp(ts->info->ident, buf) == 0)
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
 *  timer_stat_diff()
 *	find difference in event count between to hash table samples of timer
 *	stats.  We are interested in just current and new timers, not ones that
 *	silently die
 */
static void timer_stat_diff(
	struct timeval *duration,	/* time between each sample */
	const int n_lines,		/* number of lines to output */
	struct timeval *whence,		/* nth sample */
	timer_stat_t *timer_stats_old[],/* old timer stats samples */
	timer_stat_t *timer_stats_new[])/* new timer stats samples */
{
	int i;
	int j = 0;
	unsigned long total = 0UL;
	unsigned long kt_total = 0UL;
	double dur = timeval_double(duration);

	timer_stat_t *sorted = NULL;

	for (i = 0; i < TABLE_SIZE; i++) {
		timer_stat_t *ts;

		for (ts = timer_stats_new[i]; ts; ts = ts->next) {
			timer_stat_t *found =
				timer_stat_find(timer_stats_old, ts);
			if (found) {
				ts->delta = ts->count - found->count;
				if (ts->delta >= opt_threshold) {
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
					found->info->total += ts->delta;
				}
			} else {
				ts->delta = ts->count;
				if (ts->delta >= opt_threshold) {
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		printf("%8s %-5s %-15s %-25s %-s\n",
			opt_flags & OPT_CUMULATIVE ? "Events" : "Event/s",
			"PID", "Task", "Init Function", "Callback");

		while (sorted) {
			if (((n_lines == -1) || (j < n_lines)) && (sorted->delta != 0)) {
				j++;
				if (opt_flags & OPT_CUMULATIVE) {
					printf("%8lu %5d %-15s %-25s %-s\n",
						sorted->count,
						sorted->info->pid, sorted->info->task,
						sorted->info->func, sorted->info->callback);
				} else {
					printf("%8.2f %5d %-15s %-25s %-s\n",
						(double)sorted->delta / dur,
						sorted->info->pid, sorted->info->task,
						sorted->info->func, sorted->info->callback);
				}
			}
			total += sorted->delta;
			if (sorted->info->kernel_thread)
				kt_total += sorted->delta;

			sorted = sorted->sorted_freq_next;
		}
		printf("%lu Total events, %5.2f events/sec (kernel: %5.2f, userspace: %5.2f)\n",
			total, (double)total / dur,
			(double)kt_total / dur,
			(double)(total - kt_total) / dur);
		if (!sane_procs)
			printf("Note: this was run inside a container, kernel tasks were guessed.\n");
		printf("\n");
	}
}

/*
 *  get_events()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
static void get_events(timer_stat_t *timer_stats[])	/* hash table to populate */
{
	FILE *fp;
	char buf[4096];

	if ((fp = fopen(TIMER_STATS, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s\n", TIMER_STATS);
		return;
	}

	/* Originally from PowerTop, but majorly re-worked */
	while (!feof(fp)) {
		char *ptr = buf;
		unsigned long count = -1;
		pid_t pid = -1;
		char task[64];
		char func[128];
		char timer[128];
		bool kernel_thread;

		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;

		if (strstr(buf, "total events") != NULL)
			break;

		if (strstr(buf, ",") == NULL)
			continue;

		/* format: count[D], pid, task, func (timer) */

		while (*ptr && *ptr != ',')
			ptr++;

		if (*ptr != ',')
			continue;

		if (ptr > buf && *(ptr-1) == 'D')
			continue;	/* Deferred event, skip */

		ptr++;
		sscanf(buf, "%lu", &count);
		sscanf(ptr, "%d %s %s (%[^)])", &pid, task, func, timer);

		kernel_thread = pid_a_kernel_thread(task, pid);

		if (kernel_thread) {
			char tmp[64];
			task[13] = '\0';
			snprintf(tmp, sizeof(tmp), "[%s]", task);
			strcpy(task, tmp);
		}

		if (strcmp(task, "insmod") == 0)
			strcpy(task, "[kern mod]");
		if (strcmp(task, "modprobe") == 0)
			strcpy(task, "[kern mod]");
		if (strcmp(task, "swapper") == 0)
			strcpy(task, "[kern core]");

		if ((strncmp(func, "tick_nohz_", 10) == 0) ||
		    (strncmp(func, "tick_setup_sched_timer", 20) == 0) ||
		    (strcmp(task, APP_NAME) == 0))
			continue;

		timer_stat_add(timer_stats, count, pid, task, func, timer, kernel_thread);
	}

	fclose(fp);
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage: %s [options] [duration] [count]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -c\t\treport cumulative events rather than events per second.\n");
	printf("  -C\t\treport event count rather than event per second in CSV output.\n");
	printf("  -d\t\tremove pathname from long process name in CSV output.\n");
	printf("  -h\t\tprint this help.\n");
	printf("  -l\t\tuse long cmdline text from /proc/pid/cmdline in CSV output.\n");
	printf("  -n events\tspecifies number of events to display.\n");
	printf("  -q\t\trun quietly, useful with option -r.\n");
	printf("  -r filename\tspecifies a comma separated values (CSV) output file to dump samples into.\n");
	printf("  -s\t\tuse short process name from /proc/pid/cmdline in CSV output.\n");
	printf("  -S\t\tcalculate min, max, average and standard deviation in CSV output.\n");
	printf("  -t threshold\tsamples less than the specified threshold are ignored.\n");
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	double duration_secs = 1.0;
	int count = 1;
	int n_lines = -1;
	bool forever = true;
	struct timeval tv1, tv2, duration, whence;

	list_init(&timer_info_list);
	list_init(&sample_list);

	for (;;) {
		int c = getopt(argc, argv, "cCdsSlhn:qr:t:");
		if (c == -1)
			break;
		switch (c) {
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
			n_lines = atoi(optarg);
			if (n_lines < 1) {
				fprintf(stderr, "-n option must be greater than 0\n");
				eventstat_exit(EXIT_FAILURE);
			}
			break;
		case 't':
			opt_threshold = strtoull(optarg, NULL, 10);
			if (opt_threshold < 1) {
				fprintf(stderr, "-t threshold must be 1 or more.\n");
				eventstat_exit(EXIT_FAILURE);
			}
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
		}
	}

	if (optind < argc) {
		duration_secs = atof(argv[optind++]);
		if (duration_secs < 0.5) {
			fprintf(stderr, "Duration must 0.5 or more.\n");
			eventstat_exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		forever = false;
		count = atoi(argv[optind++]);
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			eventstat_exit(EXIT_FAILURE);
		}
	}

	duration.tv_sec = (time_t)duration_secs;
	duration.tv_usec = (suseconds_t)(duration_secs * 1000000.0) - (duration.tv_sec * 1000000);
	opt_threshold *= duration_secs;

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to write to %s\n",
			APP_NAME, TIMER_STATS);
		eventstat_exit(EXIT_FAILURE);
	}

	sane_procs = sane_proc_pid_info();
	if (!sane_procs)
		opt_flags &= ~(OPT_CMD_SHORT | OPT_CMD_LONG);

	signal(SIGINT, &handle_sigint);

	if ((timer_stats_old = calloc(TABLE_SIZE, sizeof(timer_stat_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate old timer stats table\n");
		eventstat_exit(EXIT_FAILURE);
	}
	if ((timer_stats_new = calloc(TABLE_SIZE, sizeof(timer_stat_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate old timer stats table\n");
		eventstat_exit(EXIT_FAILURE);
	}

	/* Should really catch signals and set back to zero before we die */
	set_timer_stat("1", true);
	gettimeofday(&tv1, NULL);
	get_events(timer_stats_old);

	whence.tv_sec = 0;
	whence.tv_usec = 0;

	while (!stop_eventstat && (forever || count--)) {
		struct timeval tv;
		int ret;

		gettimeofday(&tv2, NULL);

		tv = timeval_add(&duration, &whence);
		tv = timeval_add(&tv, &tv1);
		tv2 = tv = timeval_sub(&tv, &tv2);

		/* Play catch-up, probably been asleep */
		if (tv.tv_sec < 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			tv2 = tv;
		}

		ret = select(0, NULL, NULL, NULL, &tv2);
		if (ret < 0) {
			if (errno == EINTR) {
				duration = timeval_sub(&tv, &tv2);
				stop_eventstat = true;
			} else {
				fprintf(stderr, "Select failed: %s\n", strerror(errno));
				break;
			}
		}

		get_events(timer_stats_new);
		timer_stat_diff(&duration, n_lines, &whence,
			timer_stats_old, timer_stats_new);
		timer_stat_free_contents(timer_stats_old);

		tmp             = timer_stats_old;
		timer_stats_old = timer_stats_new;
		timer_stats_new = tmp;

		whence = timeval_add(&duration, &whence);
	}

	samples_dump(csv_results, &duration);

	timer_stat_free_contents(timer_stats_old);
	timer_stat_free_contents(timer_stats_new);
	free(timer_stats_old);
	free(timer_stats_new);
	samples_free();
	timer_info_list_free();

	eventstat_exit(EXIT_SUCCESS);
}
