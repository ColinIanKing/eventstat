/*
 * Copyright (C) 2011-2012 Canonical
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
#include <limits.h>
#include <errno.h>

#define APP_NAME	"eventstat"
#define TIMER_STATS	"/proc/timer_stats"
#define TABLE_SIZE	(1997)		/* Should be a prime */

#define OPT_QUIET	(0x00000001)

typedef struct link {
	void *data;
	struct link *next;
} link_t;

typedef struct {
	link_t	*head;
	link_t	*tail;
	size_t	length;
} list_t;

typedef void (*list_link_free_t)(void *);

typedef struct timer_info {
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	bool		kernel_thread;	/* True if task is a kernel thread */
	unsigned long	total;		/* Total number of events */
} timer_info_t;

typedef struct timer_stat {
	unsigned long	count;		/* Number of events */
	unsigned long	delta;		/* Change in events since last time */
	bool		old;		/* Existing event, not a new one */
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
	unsigned long		whence;	/* when the sample was taken */
	list_t			list;
} sample_delta_list_t;

static list_t timer_info_list;			/* cache list of timer_info */
static list_t sample_list;			/* list of samples, sorted in sample time order */
static char *csv_results;			/* results in comma separated values */
static volatile bool stop_eventstat = false;	/* set by sighandler */
static unsigned long opt_threshold;		/* ignore samples with event delta less than this */
static unsigned int opt_flags;			/* option flags */

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

	if ((link = calloc(sizeof(link_t), 1)) == NULL) {
		fprintf(stderr, "Cannot allocate list link\n");
		exit(EXIT_FAILURE);
	}
	link->data = data;

	if (list->head == NULL) {
		list->head = link;
		list->tail = link;
	} else {
		list->tail->next = link;
		list->tail = link;
	}
	list->length++;

	return link;
}

/*
 *  list_free()
 *	free the list
 */
static void list_free(list_t *list, list_link_free_t freefunc)
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
static void sample_add(timer_stat_t *timer_stat, unsigned long whence)
{
	link_t	*link;
	bool	found = false;
	sample_delta_list_t *sdl = NULL;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
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
		if ((sdl = calloc(1, sizeof(sample_delta_list_t))) == NULL) {
			fprintf(stderr, "Cannot allocate sample delta list\n");
			exit(EXIT_FAILURE);
		}
		sdl->whence = whence;
		list_append(&sample_list, sdl);
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate sample delta item\n");
		exit(EXIT_FAILURE);
	}
	sdi->delta = timer_stat->delta;
	sdi->info  = timer_stat->info;

	list_append(&sdl->list, sdi);
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for timer info, return NULL if not found
 */
static sample_delta_item_t inline *sample_find(sample_delta_list_t *sdl, timer_info_t *info)
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
static bool pid_a_kernel_thread(pid_t id)
{
	char buffer[128];
	char path[PATH_MAX];

	snprintf(buffer, sizeof(buffer), "/proc/%d/exe", id);
	if (readlink(buffer, path, sizeof(path)) < 0)
		if (errno == ENOENT)
			return true;

	return false;
}

/*
 *  samples_dump()
 *	dump out collected sample information
 */
static void samples_dump(const char *filename, const int duration)
{
	sample_delta_list_t	*sdl;
	timer_info_t **sorted_timer_infos;
	link_t	*link;
	int i = 0;
	size_t n = timer_info_list.length;
	FILE *fp;

	if (filename == NULL)
		return;

	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot write to file %s\n", filename);
		return;
	}

	if ((sorted_timer_infos = calloc(n, sizeof(timer_info_t*))) == NULL) {
		fprintf(stderr, "Cannot allocate buffer for sorting timer_infos\n");
		exit(EXIT_FAILURE);
	}

	/* Just want the timers with some non-zero total */
	for (n = 0, link = timer_info_list.head; link; link = link->next) {
		timer_info_t *info = (timer_info_t*)link->data;
		if (info->total > 0)
			sorted_timer_infos[n++] = info;
	}

	qsort(sorted_timer_infos, n, sizeof(timer_info_t *), info_compare_total);

	fprintf(fp, "Task:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->task);
	fprintf(fp, "\n");

	fprintf(fp, "Init Function:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->func);
	fprintf(fp, "\n");

	fprintf(fp, "Callback:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->callback);
	fprintf(fp, "\n");

	fprintf(fp, "Total:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%lu", sorted_timer_infos[i]->total);
	fprintf(fp, "\n");

	for (link = sample_list.head; link; link = link->next) {
		sdl = (sample_delta_list_t*)link->data;
		fprintf(fp, "%lu", sdl->whence);

		/* Scan in timer info order to be consistent for all sdl rows */
		for (i=0; i<n; i++) {
			sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
			if (sdi)
				fprintf(fp,",%f", (double)sdi->delta / (double)duration);
			else
				fprintf(fp,",");
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
static timer_info_t *timer_info_find(timer_info_t *new_info)
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
		exit(EXIT_FAILURE);
	}

	info->pid = new_info->pid;
	info->task = strdup(new_info->task);
	info->func = strdup(new_info->func);
	info->callback = strdup(new_info->callback);
	info->ident = strdup(new_info->ident);
	info->kernel_thread = new_info->kernel_thread;

	if (info->task == NULL ||
	    info->func == NULL ||
	    info->callback == NULL ||
	    info->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat fields\n");
		exit(1);
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
static unsigned long hash_pjw(char *str)
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

	for (i=0; i<TABLE_SIZE; i++) {
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
	unsigned long count,		/* event count */
	pid_t pid,			/* PID of task */
	char *task,			/* Name of task */
	char *func,			/* Kernel function */
	char *callback,			/* Kernel timer callback */
	bool kernel_thread)		/* Is a kernel thread */
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
		exit(1);
	}

	info.pid = pid;
	info.task = task;
	info.func = func;
	info.callback = callback;
	info.ident = buf;
	info.kernel_thread = kernel_thread;

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

	for (ts = haystack[hash_pjw(buf)]; ts; ts = ts->next)
		if (strcmp(ts->info->ident, buf) == 0)
			return ts;

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
		if ((*sorted)->delta < new->delta) {
			new->sorted_freq_next = *(sorted);
			break;
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
	const int duration,		/* time between each sample */
	const int n_lines,		/* number of lines to output */
	unsigned long whence,		/* nth sample */
	timer_stat_t *timer_stats_old[],/* old timer stats samples */
	timer_stat_t *timer_stats_new[])/* new timer stats samples */
{
	int i;
	int j = 0;
	unsigned long total = 0UL;
	unsigned long kt_total = 0UL;

	timer_stat_t *sorted = NULL;

	for (i=0; i<TABLE_SIZE; i++) {
		timer_stat_t *ts;

		for (ts = timer_stats_new[i]; ts; ts = ts->next) {
			timer_stat_t *found =
				timer_stat_find(timer_stats_old, ts);
			if (found) {
				ts->delta = ts->count - found->count;
				if (ts->delta >= opt_threshold) {
					ts->old = true;
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
					found->info->total += ts->delta;
				}
			} else {
				ts->delta = 0;
				if (ts->delta >= opt_threshold) {
					ts->old = false;
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
				}
			}
		}
	}

	if (!(opt_flags & OPT_QUIET)) {
		printf("%1s %6s %-5s %-15s %-25s %-s\n",
			"", "Evnt/s", "PID", "Task", "Init Function", "Callback");

		while (sorted) {
			if (((n_lines == -1) || (j < n_lines)) && (sorted->delta != 0)) {
				j++;
				printf("%1s %6.2f %5d %-15s %-25s %-s\n",
					sorted->old ? " " : "N",
					(double)sorted->delta / (double)duration,
					sorted->info->pid, sorted->info->task,
					sorted->info->func, sorted->info->callback);
			}
			total += sorted->delta;
			if (sorted->info->kernel_thread)
				kt_total += sorted->delta;

			sorted = sorted->sorted_freq_next;
		}
		printf("%lu Total events, %5.2f events/sec (kernel: %5.2f, userspace: %5.2f)\n\n",
			total, (double)total / duration,
			(double)kt_total / duration,
			(double)(total - kt_total) / duration);
	}
}


/*
 *  get_events()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
void get_events(timer_stat_t *timer_stats[])	/* hash table to populate */
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

		kernel_thread = pid_a_kernel_thread(pid);

		if (kernel_thread) {
			char tmp[64];
			task[13] = '\0';
			snprintf(tmp, sizeof(tmp), "[%s]", task);
			strcpy(task, tmp);
		}

		if (strcmp(task, "swapper") == 0 &&
		    strcmp(func, "hrtimer_start_range_ns") == 0 &&
		    strcmp(timer, "tick_sched_timer") == 0) {
			strcpy(task, "[kern sched]");
			strcpy(func, "Load balancing tick");
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
 *  set_timer_stat()
 *	enable/disable timer stat
 */
void set_timer_stat(char *str)
{
	FILE *fp;

	if ((fp = fopen(TIMER_STATS, "w")) == NULL) {
		fprintf(stderr, "Cannot write to %s\n",TIMER_STATS);
		exit(EXIT_FAILURE);
	}
	fprintf(fp, "%s\n", str);
	fclose(fp);
}

/*
 *  show_usage()
 *	show how to use
 */
void show_usage(void)
{
	printf("Usage: %s [-q] [-r csv_file] [-n event_count] [duration] [count]\n", APP_NAME);
	printf("\t-h help\n");
	printf("\t-n specifies number of events to display\n");
	printf("\t-q run quietly, useful with option -r\n");
	printf("\t-r specifies a comma separated values output file to dump samples into.\n");
	printf("\t-t specifies an event threshold where samples less than this are ignored.\n");
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	int duration = 1;
	int count = 1;
	int n_lines = -1;
	unsigned long whence = 0;
	bool forever = true;
	struct timeval tv1, tv2;

	list_init(&timer_info_list);
	list_init(&sample_list);

	for (;;) {
		int c = getopt(argc, argv, "hn:qr:t:");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'n':
			n_lines = atoi(optarg);
			if (n_lines < 1) {
				fprintf(stderr, "-n option must be greater than 0\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 't':
			opt_threshold = strtoull(optarg, NULL, 10);
			if (opt_threshold < 1) {
				fprintf(stderr, "-t threshold must be 1 or more.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'r':
			csv_results = optarg;
			break;
		}
	}

	if (optind < argc) {
		duration = atoi(argv[optind++]);
		if (duration < 1) {
			fprintf(stderr, "Duration must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		forever = false;
		count = atoi(argv[optind++]);
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	opt_threshold *= duration;

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to write to %s\n",
			APP_NAME, TIMER_STATS);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, &handle_sigint);

	/* Should really catch signals and set back to zero before we die */
	set_timer_stat("1");
	sleep(1);

	timer_stats_old = calloc(TABLE_SIZE, sizeof(timer_stat_t*));
	timer_stats_new = calloc(TABLE_SIZE, sizeof(timer_stat_t*));

	gettimeofday(&tv1, NULL);
	get_events(timer_stats_old);

	while (!stop_eventstat && (forever || count--)) {
		suseconds_t usec;

		gettimeofday(&tv2, NULL);
		usec = ((tv1.tv_sec + whence + duration - tv2.tv_sec) * 1000000) +
		       (tv1.tv_usec - tv2.tv_usec);
		tv2.tv_sec = usec / 1000000;
		tv2.tv_usec = usec % 1000000;

		select(0, NULL, NULL, NULL, &tv2);

		get_events(timer_stats_new);
		timer_stat_diff(duration, n_lines, whence,
			timer_stats_old, timer_stats_new);
		timer_stat_free_contents(timer_stats_old);

		tmp             = timer_stats_old;
		timer_stats_old = timer_stats_new;
		timer_stats_new = tmp;

		whence += duration;
	}

	samples_dump(csv_results, duration);

	timer_stat_free_contents(timer_stats_old);
	timer_stat_free_contents(timer_stats_new);
	free(timer_stats_old);
	free(timer_stats_new);
	samples_free();
	timer_info_list_free();

	set_timer_stat("0");

	exit(EXIT_SUCCESS);
}
