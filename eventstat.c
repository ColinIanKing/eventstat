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
#include <unistd.h>

#define APP_NAME	"eventstat"
#define TIMER_STATS	"/proc/timer_stats"

#define TABLE_SIZE	(251)		/* Should be a prime */

typedef struct {
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*func;		/* Kernel waiting func */
	char		*timer;		/* Kernel timer */
	char		*ident;		/* Unique identity */
} timer_info_t;

typedef struct timer_stat {
	unsigned long	count;		/* Number of events */
	unsigned long	delta;		/* Change in events since last time */
	bool		old;		/* Existing event, not a new one */
	timer_info_t	*info;		/* Timer info */
	struct timer_stat *next;	/* Next timer stat in hash table */
	struct timer_stat *sorted_freq_next;	/* Next timer stat in event frequency sorted list */
	struct timer_stat *sorted_ident_next;	/* Next timer stat in ident sorted list */
} timer_stat_t;

typedef struct timer_info_item {
	timer_info_t		info;
	struct timer_info_item	*next;
} timer_info_item_t;

typedef struct {
	timer_info_item_t	*head;
	timer_info_item_t	*tail;
} timer_info_list_t;

timer_info_list_t timer_info_list;	/* cache list of timer_info */

/*
 *  timer_info_find()
 *	try to find existing timer info in cache, and to the cache
 *	if it is new.
 */
timer_info_t *timer_info_find(timer_info_t *info)
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
	return &item->info;
}

/*
 *  timer_info_free
 *	free up all unique timer infos
 */
void timer_info_free(void)
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
unsigned long hash_pjw(char *str)
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
void timer_stat_free_contents(
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
void timer_stat_add(
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

	while (ts != NULL) {
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
	ts_new->sorted_ident_next = NULL;


	timer_stats[h] = ts_new;
}

/*
 *  timer_stat_find()
 *	find a timer stat (needle) in a timer stat hash table (haystack)
 */
timer_stat_t *timer_stat_find(
	timer_stat_t *haystack[],	/* timer stat hash table */
	timer_stat_t *needle)		/* timer stat to find */
{
	timer_stat_t *ts;
	char buf[4096];

	snprintf(buf, sizeof(buf), "%d:%s:%s:%s",
		needle->info->pid, needle->info->task,
		needle->info->func, needle->info->timer);

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
void timer_stat_sort_freq_add(
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
 *  timer_stat_sort_ident_add()
 *	add a timer stat to a sorted list of timer stats
 */
void timer_stat_sort_ident_add(
	timer_stat_t **sorted,		/* timer stat sorted list */
	timer_stat_t *new)		/* timer stat to add */
{
	while (*sorted != NULL) {
		if (strcmp((*sorted)->info->ident, new->info->ident) < 0) {
			new->sorted_ident_next = *(sorted);
			break;
		}
		sorted = &(*sorted)->sorted_ident_next;
	}
	*sorted = new;
}

/*
 *  timer_stat_diff()
 *	find difference in event count between to hash table samples of timer
 *	stats.  We are interested in just current and new timers, not ones that
 *	silently die
 */
void timer_stat_diff(
	const int duration,
	const int n_lines,
	timer_stat_t *timer_stats_old[],
	timer_stat_t *timer_stats_new[],
	unsigned long *total)
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
				}
			} else {
				ts->delta = 0;
				ts->old = false;
				timer_stat_sort_freq_add(&sorted, ts);
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

void show_usage(void)
{
	printf("Usage: %s [-n event_count] [duration] [count]\n", APP_NAME);
	printf("\t-h help\n");
	printf("\t-n specifies number of events to display\n");
}

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	unsigned long total;
	int duration = 1;
	int count = 1;
	int n_lines = -1;
	bool forever = true;

	for (;;) {
		int c = getopt(argc, argv, "hn:");
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

	/* Should really catch signals and set back to zero before we die */
	set_timer_stat("1");

	timer_stats_old = calloc(TABLE_SIZE, sizeof(timer_stat_t*));
	timer_stats_new = calloc(TABLE_SIZE, sizeof(timer_stat_t*));

	get_events(timer_stats_old);

	while (forever || count--) {
		sleep(duration);
		get_events(timer_stats_new);
		timer_stat_diff(duration, n_lines,
			timer_stats_old, timer_stats_new, &total);
		timer_stat_free_contents(timer_stats_old);

		tmp             = timer_stats_old;
		timer_stats_old = timer_stats_new;
		timer_stats_new = tmp;

		printf("%lu Total events, %5.2f events/sec\n\n",
			total, (double)total / duration);
	}

	timer_stat_free_contents(timer_stats_old);
	timer_stat_free_contents(timer_stats_new);
	free(timer_stats_old);
	free(timer_stats_new);

	timer_info_free();

	set_timer_stat("0");

	exit(EXIT_SUCCESS);
}
