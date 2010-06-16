/*
 * proc.h
 *
 *  Created on: Jun 15, 2010
 *      Author: chh
 */

#ifndef PROC_H_
#define PROC_H_

typedef struct proc_t {
// 1st 16 bytes
    int
        tid,            // (special)       task id, the POSIX thread ID (see also: tgid)
        ppid;           // stat,status     pid of parent process
    unsigned
        pcpu;           // stat (special)  %CPU usage (is not filled in by readproc!!!)
    char
        state,          // stat,status     single-char code for process state (S=sleeping)
        pad_1,          // n/a             padding
        pad_2,          // n/a             padding
        pad_3;          // n/a             padding
// 2nd 16 bytes
    unsigned long long
        utime,          // stat            user-mode CPU time accumulated by process
        stime,          // stat            kernel-mode CPU time accumulated by process
// and so on...
        cutime,         // stat            cumulative utime of process and reaped children
        cstime,         // stat            cumulative stime of process and reaped children
        start_time;     // stat            start time of process -- seconds since 1-1-70
#ifdef SIGNAL_STRING
    char
        // Linux 2.1.7x and up have 64 signals. Allow 64, plus '\0' and padding.
        signal[18],     // status          mask of pending signals, per-task for readtask() but per-proc for readproc()
        blocked[18],    // status          mask of blocked signals
        sigignore[18],  // status          mask of ignored signals
        sigcatch[18],   // status          mask of caught  signals
        _sigpnd[18];    // status          mask of PER TASK pending signals
#else
    long long
        // Linux 2.1.7x and up have 64 signals.
        signal,         // status          mask of pending signals, per-task for readtask() but per-proc for readproc()
        blocked,        // status          mask of blocked signals
        sigignore,      // status          mask of ignored signals
        sigcatch,       // status          mask of caught  signals
        _sigpnd;        // status          mask of PER TASK pending signals
#endif
    unsigned
		start_code,     // stat            address of beginning of code segment
        end_code,       // stat            address of end of code segment
        start_stack,    // stat            address of the bottom of stack for the process
        kstk_esp,       // stat            kernel stack pointer
        kstk_eip,       // stat            kernel instruction pointer
        wchan;          // stat (special)  address of kernel wait channel proc is sleeping in
    long
        priority,       // stat            kernel scheduling priority
        nice,           // stat            standard unix nice level of process
        rss,            // stat            resident set size from /proc/#/stat (pages)
        alarm,          // stat            ?
    // the next 7 members come from /proc/#/statm
        size,           // statm           total # of pages of memory
        resident,       // statm           number of resident set (non-swapped) pages (4k)
        share,          // statm           number of pages of shared (mmap'd) memory
        trs,            // statm           text resident set size
        lrs,            // statm           shared-lib resident set size
        drs,            // statm           data resident set size
        dt;             // statm           dirty pages
    unsigned long
        vm_size,        // status          same as vsize in kb
        vm_lock,        // status          locked pages in kb
        vm_rss,         // status          same as rss in kb
        vm_data,        // status          data size
        vm_stack,       // status          stack size
        vm_exe,         // status          executable size
        vm_lib,         // status          library size (all pages, not just used ones)
        rtprio,         // stat            real-time priority
        sched,          // stat            scheduling class
        vsize,          // stat            number of pages of virtual memory ...
        rss_rlim,       // stat            resident set size limit?
        flags,          // stat            kernel flags for the process
        min_flt,        // stat            number of minor page faults since process start
        maj_flt,        // stat            number of major page faults since process start
        cmin_flt,       // stat            cumulative min_flt of process and child processes
        cmaj_flt;       // stat            cumulative maj_flt of process and child processes
    char
        **environ,      // (special)       environment string vector (/proc/#/environ)
        **cmdline;      // (special)       command line string vector (/proc/#/cmdline)
    int
        pgrp,           // stat            process group id
        session,        // stat            session id
        nlwp,           // stat,status     number of threads, or 0 if no clue
        tgid,           // (special)       task group ID, the POSIX PID (see also: tid)
        tty,            // stat            full device number of controlling terminal
        euid, egid,     // stat(),status   effective
        ruid, rgid,     // status          real
        suid, sgid,     // status          saved
        fuid, fgid,     // status          fs (used for file access only)
        tpgid,          // stat            terminal process group id
        exit_signal,    // stat            might not be SIGCHLD
        processor;      // stat            current (or most recent?) CPU
} proc_t;


#endif /* PROC_H_ */
