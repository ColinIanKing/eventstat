/*
 * Copyright (C) 2011 Canonical
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

#define APP_NAME	"eventstat"
#define TIMER_STATS	"/proc/timer_stats"
#define TABLE_SIZE	(251)		/* Should be a prime */

#define DEBUG_TIMER_STAT_DUMP	(0)

typedef struct timer_info {
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*func;		/* Kernel waiting func */
	char		*timer;		/* Kernel timer */
	char		*ident;		/* Unique identity */
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

/* timer info item as an element of the timer_info_list_t */
typedef struct timer_info_item {
	timer_info_t		info;	/* Timer info */
	struct timer_info_item	*next;	/* Next timer info in list */
} timer_info_item_t;

/* list of timer_info_item_t elements */
typedef struct {
	timer_info_item_t	*head;	/* list head */
	timer_info_item_t	*tail;	/* list tail */
	size_t			length;	/* length of list */
} timer_info_list_t;

/* sample delta item as an element of the sample_delta_list_t */
typedef struct sample_delta_item {
	unsigned long	delta;		/* difference in timer events between old and new */
	timer_info_t	*info;		/* timer this refers to */
	struct sample_delta_item *next;	/* next sample delta item in the list */
} sample_delta_item_t;

/* list of sample_delta_items */
typedef struct sample_delta_list {
	unsigned long		whence;	/* when the sample was taken */
	sample_delta_item_t	*head;	/* list head */
	sample_delta_item_t	*tail;	/* list tail */
	struct sample_delta_list *next;	/* next sample_delta_list */
} sample_delta_list_t;

/* list of sample_delta_list_t items */
typedef struct {
	sample_delta_list_t	*head;	/* head */
	sample_delta_list_t	*tail;	/* tail */
} sample_list_t;

static timer_info_list_t timer_info_list;	/* cache list of timer_info */
static sample_list_t sample_list;		/* list of samples, sorted in sample time order */
static char *csv_results;			/* results in comma separated values */
static volatile bool stop_eventstat = false;	/* set by sighandler */

/*
 *  handle_sigint()
 *      catch SIGINT and flag a stop
 */
static void handle_sigint(int dummy)
{
	stop_eventstat = true;
}

/*
 *  samples_free()
 *	free collected samples
 */
static void samples_free(void)
{
	sample_delta_list_t *sdl = sample_list.head;

	while (sdl) {
		sample_delta_list_t *sdl_next = sdl->next;
		sample_delta_item_t *sdi = sdl->head;

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
 *	add a timer_stat's delta and info field to a list at time position whence
 */
static void sample_add(timer_stat_t *timer_stat, unsigned long whence)
{
	sample_delta_list_t *sdl = sample_list.head;
	sample_delta_item_t *sdi;

	if (csv_results == NULL)	/* No need if not request */
		return;

	for (sdl = sample_list.head; sdl; sdl = sdl->next)
		if (sdl->whence == whence)
			break;

	/*
	 * New time period, need new sdl, we assume it goes at the end of the
	 * list since time is assumed to be increasing
	 */
	if (sdl == NULL) {
		if ((sdl = calloc(1, sizeof(sample_delta_list_t))) == NULL) {
			fprintf(stderr, "Cannot allocate sample delta list\n");
			exit(EXIT_FAILURE);
		}
		sdl->whence = whence;

		if (sample_list.head == NULL) {
			sample_list.head = sdl;
			sample_list.tail = sdl;
		} else {
			sample_list.tail->next = sdl;
			sample_list.tail = sdl;
		}
	}

	/* Now append the sdi onto the list */
	if ((sdi = calloc(1, sizeof(sample_delta_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate sample delta item\n");
		exit(EXIT_FAILURE);
	}
	sdi->delta = timer_stat->delta;
	sdi->info  = timer_stat->info;

	if (sdl->head == NULL) {
		sdl->head = sdi;
		sdl->tail = sdi;
	} else {
		sdl->tail->next = sdi;
		sdl->tail = sdi;
	}
}

/*
 *  sample_find()
 *	scan through a sample_delta_list for timer info, return NULL if not found
 */
static sample_delta_item_t inline *sample_find(sample_delta_list_t *sdl, timer_info_t *info)
{
	sample_delta_item_t	*sdi = sdl->head;

	while (sdi) {
		if (sdi->info == info)
			return sdi;
		sdi = sdi->next;
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

static void samples_dump(const char *filename)
{
	sample_delta_list_t	*sdl;
	timer_info_t **sorted_timer_infos;
	timer_info_item_t *item = timer_info_list.head;
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
	for (n = 0, item = timer_info_list.head; item; item = item->next)
		if (item->info.total > 0)
			sorted_timer_infos[n++] = &item->info;

	qsort(sorted_timer_infos, n, sizeof(timer_info_t *), info_compare_total);

	fprintf(fp, "Task:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->task);
	fprintf(fp, "\n");

	fprintf(fp, "Func:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->func);
	fprintf(fp, "\n");

	fprintf(fp, "Timer:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%s", sorted_timer_infos[i]->timer);
	fprintf(fp, "\n");

	fprintf(fp, "Total:");
	for (i=0; i<n; i++)
		fprintf(fp, ",%lu", sorted_timer_infos[i]->total);
	fprintf(fp, "\n");

	for (sdl = sample_list.head; sdl; sdl = sdl->next) {
		fprintf(fp, "%lu", sdl->whence);

		/* Scan in timer info order to be consistent for all sdl rows */
		for (i=0; i<n; i++) {
			sample_delta_item_t *sdi = sample_find(sdl, sorted_timer_infos[i]);
			if (sdi)
				fprintf(fp,",%lu", sdi->delta);
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
static timer_info_t *timer_info_find(timer_info_t *info)
{
	timer_info_item_t *item = timer_info_list.head;

	while (item) {
		if (strcmp(info->ident, item->info.ident) == 0)
			return &item->info;
		item = item->next;
	}
	if ((item = calloc(1, sizeof(timer_info_item_t))) == NULL) {
		fprintf(stderr, "Cannot allocate timer info\n");
		exit(EXIT_FAILURE);
	}

	item->info.pid = info->pid;
	item->info.task = strdup(info->task);
	item->info.func = strdup(info->func);
	item->info.timer = strdup(info->timer);
	item->info.ident = strdup(info->ident);

	if (item->info.task == NULL ||
	    item->info.func == NULL ||
	    item->info.timer == NULL ||
	    item->info.ident == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat fields\n");
		exit(1);
	}

	/* Does not exist in list, append it */

	if (timer_info_list.head == NULL) {
		timer_info_list.head = item;
		timer_info_list.tail = item;
	} else {
		timer_info_list.tail->next = item;
		timer_info_list.tail = item;
	}

	timer_info_list.length++;

	return &item->info;
}

/*
 *  timer_info_free
 *	free up all unique timer infos
 */
static void timer_info_free(void)
{
	timer_info_item_t *item = timer_info_list.head;

	while (item) {
		timer_info_item_t *next = item->next;
		free(item->info.task);
		free(item->info.func);
		free(item->info.timer);
		free(item->info.ident);
		free(item);
		item = next;
	}
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

#if DEBUG_TIMER_STAT_DUMP
static void timer_stat_dump(timer_stat_t *timer_stats[])
{
	int i;

	printf("Timer stat dump:\n");

	for (i=0; i<TABLE_SIZE; i++) {
		timer_stat_t *ts = timer_stats[i];
		while (ts) {
			printf("%d : %s\n",i, ts->info->ident);
			ts = ts->next;
		}
	}
}
#endif

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
	char *timer)			/* Kernel timer */
{
	char buf[4096];
	timer_stat_t *ts;
	timer_stat_t *ts_new;
	timer_info_t info;
	unsigned long h;

	snprintf(buf, sizeof(buf), "%d:%s:%s:%s", pid, task, func, timer);
	h = hash_pjw(buf);
	ts = timer_stats[h];

	while (ts) {
		if (strcmp(ts->info->ident, buf) == 0) {
			ts->count += count;
			return;
		}
		ts = ts->next;
	}
	/* Not found, it is new! */

	if ((ts_new = malloc(sizeof(timer_stat_t))) == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat\n");
		exit(1);
	}

	info.pid = pid;
	info.task = task;
	info.func = func;
	info.timer = timer;
	info.ident = buf;

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
		needle->info->func, needle->info->timer);

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
	while (*sorted != NULL) {
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
	timer_stat_t *timer_stats_new[],/* new timer stats samples */
	unsigned long *total)		/* total number of events */
{
	int i;
	int j = 0;

	timer_stat_t *sorted = NULL;

	for (i=0; i<TABLE_SIZE; i++) {
		timer_stat_t *ts = timer_stats_new[i];
		while (ts) {
			timer_stat_t *found =
				timer_stat_find(timer_stats_old, ts);
			if (found) {
				ts->delta = ts->count - found->count;
				if (ts->delta) {
					ts->old = true;
					timer_stat_sort_freq_add(&sorted, ts);
					sample_add(ts, whence);
					found->info->total += ts->delta;
				}
			} else {
				ts->delta = 0;
				ts->old = false;
				timer_stat_sort_freq_add(&sorted, ts);
				sample_add(ts, whence);
			}
			ts = ts->next;
		}
	}

	*total = 0UL;

	printf("%1s %6s %-5s %-15s %-25s %-s\n",
		"", "Evnt/s", "PID", "Task", "Func", "Timer");
	while (sorted) {
		if ((n_lines == -1) || (j < n_lines)) {
			j++;
			printf("%1s %6.2f %5d %-15s %-25s %-s\n",
				sorted->old ? " " : "N",
				(double)sorted->delta / duration,
				sorted->info->pid, sorted->info->task,
				sorted->info->func, sorted->info->timer);
		}
		*total += sorted->delta;
		sorted = sorted->sorted_freq_next;
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

		timer_stat_add(timer_stats, count, pid, task, func, timer);
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
	printf("Usage: %s [-r csv_file] [-n event_count] [duration] [count]\n", APP_NAME);
	printf("\t-h help\n");
	printf("\t-n specifies number of events to display\n");
	printf("\t-r specify a comma separated values output file to dump samples into.\n");
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	unsigned long total;
	int duration = 1;
	int count = 1;
	int n_lines = -1;
	unsigned long whence = 0;
	bool forever = true;
	struct timeval tv1, tv2;

	for (;;) {
		int c = getopt(argc, argv, "hn:r:");
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

#if DEBUG_TIMER_STAT_DUMP
	timer_stat_dump(timer_stats_old);
#endif
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
			timer_stats_old, timer_stats_new, &total);
		timer_stat_free_contents(timer_stats_old);

		tmp             = timer_stats_old;
		timer_stats_old = timer_stats_new;
		timer_stats_new = tmp;

		printf("%lu Total events, %5.2f events/sec\n\n",
			total, (double)total / duration);

		whence += duration;
	}

	samples_dump(csv_results);

	timer_stat_free_contents(timer_stats_old);
	timer_stat_free_contents(timer_stats_new);
	free(timer_stats_old);
	free(timer_stats_new);
	samples_free();
	timer_info_free();

	set_timer_stat("0");

	exit(EXIT_SUCCESS);
}
