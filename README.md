# Eventstat

Eventstat periodically dumps out the current kernel event state.
It keeps track of current events and outputs the change in events
on each output update.

# Eventstat command line options:

* -c report cumulative events rather than events per second.
* -C report event count rather than event per second in CSV output.
* -d remove pathname from long process name in CSV output.
* -h print this help.
* -l use long cmdline text from /proc/pid/cmdline in CSV output.
* -n events - specifies number of events to display.
* -q run quietly, useful with option -r.
* -r filename  - specifies a comma separated values (CSV) output file to dump samples into.
* -s use short process name from /proc/pid/cmdline in CSV output.
* -S calculate min, max, average and standard deviation in CSV output.
* -t threshold - samples less than the specified threshold are ignored.
* -T 'top' mode

# Example Output:
```
sudo eventstat 10 1
  Evnt/s PID   Task            Init Function             Callback
  123.30  2253 alsa-sink       hrtimer_start_range_ns    hrtimer_wakeup
   55.20  2252 alsa-source     hrtimer_start_range_ns    hrtimer_wakeup
   41.20     0 swapper/0       hrtimer_start_range_ns    tick_sched_timer
   24.60     0 swapper/1       hrtimer_start_range_ns    tick_sched_timer
   22.70     0 swapper/0       hrtimer_start             tick_sched_timer
   18.20  2186 compiz          hrtimer_start_range_ns    hrtimer_wakeup
    8.00     0 swapper/1       usb_hcd_poll_rh_status    rh_timer_func
    5.00  2245 syndaemon       hrtimer_start_range_ns    hrtimer_wakeup
    2.20     0 swapper/1       hrtimer_start             tick_sched_timer
    2.10  3116 xchat-gnome     hrtimer_start_range_ns    hrtimer_wakeup
    2.00  3088 mumble          hrtimer_start_range_ns    hrtimer_wakeup
    1.10  2232 gvfs-afc-volume hrtimer_start_range_ns    hrtimer_wakeup
    1.00     5 kworker/u:0     queue_delayed_work        delayed_work_timer_fn
    1.00  2641 ubuntuone-syncd hrtimer_start_range_ns    hrtimer_wakeup
    1.00     0 swapper/1       add_timer                 tg3_timer
    1.00     1 swapper/0       start_bandwidth_timer     sched_rt_period_timer
    0.60 12547 firefox         hrtimer_start_range_ns    hrtimer_wakeup
    0.60  3097 threaded-ml     hrtimer_start_range_ns    hrtimer_wakeup
    0.50  1218 Xorg            intel_mark_busy           intel_gpu_idle_timer
    0.20  2178 gnome-settings- hrtimer_start_range_ns    hrtimer_wakeup
    0.20  3123 mumble          hrtimer_start_range_ns    hrtimer_wakeup
    0.20  1218 Xorg            hrtimer_start_range_ns    hrtimer_wakeup
    0.20  3123 mumble          sk_reset_timer            tcp_write_timer
    0.10  2465 gnome-terminal  hrtimer_start_range_ns    hrtimer_wakeup
N   0.00 13143 kworker/0:2     queue_delayed_work        delayed_work_timer_fn
N   0.00  1706 upowerd         schedule_timeout_interruptible process_timeout
N   0.00 12546 firefox         hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  2415 unity-applicati hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  2456 zeitgeist-datah hrtimer_start_range_ns    hrtimer_wakeup
N   0.00 12893 thunderbird-bin hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  1218 Xorg            i915_add_request          i915_hangcheck_elapsed
N   0.00  2200 nautilus        hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  3091 threaded-ml     laptop_io_completion      laptop_mode_timer_fn
N   0.00  1218 Xorg            intel_mark_busy           intel_crtc_idle_timer
N   0.00  1190 irqbalance      hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  1959 rtkit-daemon    hrtimer_start_range_ns    hrtimer_wakeup
N   0.00     0 swapper/0       dev_watchdog              dev_watchdog
N   0.00  1706 upowerd         acpi_ec_transaction_unlocked process_timeout
N   0.00  1706 upowerd         schedule_timeout_uninterruptible process_timeout
N   0.00    12 watchdog/1      hrtimer_start             watchdog_timer_fn
N   0.00  2153 ssh-agent       hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  1706 upowerd         hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  1570 accounts-daemon hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  2282 unity-panel-ser hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  1218 Xorg            drm_vblank_put            vblank_disable_fn
N   0.00 12896 thunderbird-bin hrtimer_start_range_ns    hrtimer_wakeup
N   0.00  2189 gconfd-2        hrtimer_start_range_ns    hrtimer_wakeup
N   0.00     7 watchdog/0      hrtimer_start             watchdog_timer_fn
N   0.00 13361 kworker/0:0     schedule_timeout_uninterruptible process_timeout
3122 Total events, 312.20 events/sec
```
