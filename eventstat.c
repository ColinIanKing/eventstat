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

typedef struct timer_stat {
	unsigned long	count;		/* Number of events */
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*func;		/* Kernel waiting func */
	char		*timer;		/* Kernel timer */
	char		*ident;		/* Unique identity */
	unsigned long	delta;		/* Change in events since last time */
	bool		old;		/* Existing event, not a new one */
	struct timer_stat *next;	/* Next timer stat in hash table */
	struct timer_stat *sorted_next;	/* Next timer stat in sorted list */
} timer_stat_t;

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

			free(ts->task);
			free(ts->func);
			free(ts->timer);
			free(ts->ident);
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
	unsigned long h;

	snprintf(buf, sizeof(buf), "%d:%s:%s:%s", pid, task, func, timer);
	h = hash_pjw(buf);
	ts = timer_stats[h];

	while (ts != NULL) {
		if (strcmp(ts->ident, buf) == 0) {
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

	ts_new->count  = count;
	ts_new->pid    = pid;
	ts_new->task   = strdup(task);
	ts_new->func   = strdup(func);
	ts_new->timer  = strdup(timer);
	ts_new->ident  = strdup(buf);
	ts_new->next   = timer_stats[h];
	ts_new->sorted_next = NULL;

	if (ts_new->task == NULL ||
	    ts_new->func == NULL ||
	    ts_new->timer == NULL ||
	    ts_new->ident == NULL) {
		fprintf(stderr, "Out of memory allocating a timer stat fields\n");
		exit(1);
	}

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
		needle->pid, needle->task, needle->func, needle->timer);

	for (ts = haystack[hash_pjw(buf)]; ts; ts = ts->next) {
		if (strcmp(ts->ident, buf) == 0)
			return ts;
	}
	return NULL;	/* no success */
}

/*
 *  timer_stat_sort_add()
 *	add a timer stat to a sorted list of timer stats
 */
void timer_stat_sort_add(
	timer_stat_t **sorted,		/* timer stat sorted list */
	timer_stat_t *new)		/* timer stat to add */
{
	while (*sorted != NULL) {
		if ((*sorted)->delta < new->delta) {
			new->sorted_next = *(sorted);
			break;
		}
		sorted = &(*sorted)->sorted_next;
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
	int duration,
	timer_stat_t *timer_stats_old[],
	timer_stat_t *timer_stats_new[],
	unsigned long *total)
{
	int i;

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
					timer_stat_sort_add(&sorted, ts);
				}
			} else {
				ts->delta = 0;
				ts->old = false;
				timer_stat_sort_add(&sorted, ts);
			}
			ts = ts->next;
		}
	}

	*total = 0UL;

	printf("%1s %6s %-5s %-15s %-25s %-s\n",
		"", "Evnt/s", "PID", "Task", "Func", "Timer");
	while (sorted) {
		printf("%1s %6.2f %5d %-15s %-25s %-s\n",
			sorted->old ? " " : "N",
			(double)sorted->delta / duration,
			sorted->pid, sorted->task,
			sorted->func, sorted->timer);
		*total += sorted->delta;
		sorted = sorted->sorted_next;
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

int main(int argc, char **argv)
{
	timer_stat_t **timer_stats_old, **timer_stats_new, **tmp;
	unsigned long total;
	int duration = 1;
	int count = 1;
	bool forever = true;

	if (argc >= 2) {
		duration = atoi(argv[1]);
		if (duration < 1) {
			fprintf(stderr, "Duration must be > 1\n");
			exit(EXIT_FAILURE);
		}
	}

	if (argc == 3) {
		forever = false;
		count = atoi(argv[2]);
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
		timer_stat_diff(duration,
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

	set_timer_stat("0");

	exit(EXIT_SUCCESS);
}
