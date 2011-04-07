/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network based on hash-based packet selection.
 *
 * Copyright (c) 2011
 *
 * Fraunhofer FOKUS
 * www.fokus.fraunhofer.de
 *
 * in cooperation with
 *
 * Technical University Berlin
 * www.av.tu-berlin.de
 *
 * authors:
 * Ramon Masek <ramon.masek@fokus.fraunhofer.de>
 * Christian Henke <c.henke@tu-berlin.de>
 * Carsten Schmoll <carsten.schmoll@fokus.fraunhofer.de>
 *
 * For questions/comments contact packettracking@fokus.fraunhofer.de
 *
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation;
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */



/*
  Get process and system statistics. It only supports linux and depends on the proc filesystem.
 */

#include "stats.h"
#include <stdbool.h>
#include "logger.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>

/* from /usr/src/linux/fs/proc/array.c.  */
#define PROC_PID_STAT_FORMAT "%d %s %c %d %d %d %d %d %u %lu \
		%lu %lu %lu %lu %lu %ld %ld %ld %ld %d %d %llu %lu %ld %lu %lu %lu %lu %lu \
		%lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u %llu %lu %ld\n"
#define PROC_STAT_CPU_FORMAT "cpu  %llu %llu %llu %llu %llu %llu %llu %llu %llu\n"
#define PROC_MEMINFO_FORMAT "MemTotal: %lu kB\nMemFree: %lu kB"
#define PROC_PID_STAT_FILENAME	"/proc/%u/stat"
#define PROC_STAT_FILENAME      "/proc/stat"
#define PROC_MEMINFO_FILENAME   "/proc/meminfo"
#define MAX_COMM_LEN 16
#define STATS_MISSING -1
/* */

/* see man 5 proc */
struct proc_stat_cpu {
	unsigned long long user;
	unsigned long long nice;
	unsigned long long system;
	unsigned long long idle;
	unsigned long long iowait;
	unsigned long long irq;
	unsigned long long softirq;
	unsigned long long steal;
	unsigned long long guest;
};
struct proc_pid_stat {
	pid_t pid;
	char  comm[MAX_COMM_LEN];
	char state ;
	pid_t ppid;
	pid_t  pgrp ;
	pid_t  session;
	int   tty_nr;
	int   tpgid ;
	unsigned int   flags;
	unsigned long  minflt;
	unsigned long  cminflt;
	unsigned long  majflt;
	unsigned long  cmajflt;
	unsigned long  utime;
	unsigned long  stime;
	unsigned long  cutime;
	unsigned long  cstime ;
	long  priority ;
	long  nice ;
	int  num_threads ;
	int  itrealvalue;
	unsigned long long  starttime;
	unsigned long vsize ;
	unsigned long rss ;
	unsigned long rsslim ;
	unsigned long startcode;
	unsigned long endcode;
	unsigned long startstack ;
	unsigned long kstkesp;
	unsigned long kstkeip ;
	unsigned long signal;
	unsigned long blocked;
	unsigned long sigignore;
	unsigned long sigcatch;
	unsigned long wchan ;
	unsigned long nswap;
	unsigned long cnswap ;
	int exit_signal;
	int processor ;
	unsigned int rt_priority ;
	unsigned int policy ;
	unsigned long long  delayacct_blkio_ticks  ;
	unsigned long guest_time;
	long  cguest_time ;
};
/**
 * Debugging function to consume cpu cycles
 */
void usecpu(){
	struct timeval  tv;
	struct timezone tz;
	int i;
	for(i=0; i< 100000; i++){
		getpid();
		gettimeofday(&tv, &tz);
	}
}
/**
 * Debugging function to read file into a string
 *
 * @param *buf
 * @param size  number of bytes to read
 * @param filename
 *
 * TODO review
 */
int get_file_contents( char *buf, int size, char *filename) {
	FILE *fp;
	if ((fp = fopen(filename, "r")) == NULL){
		LOGGER_error("fopen: %s", strerror(errno));
		return -1;
	}
	if(fgets(buf,size,fp)==NULL){
		LOGGER_error("could not read into buffer");
		return -1;
	}
	fclose(fp);
	return 0;
}

/**
 * get memory usage
 */
int get_mem_usage( long* total, long* free ) {
	FILE *fp;
	if ((fp = fopen(PROC_MEMINFO_FILENAME, "r")) == NULL){
		LOGGER_error("fopen error: %s", strerror(errno));
		return -1;
	}
	if( fscanf(fp, PROC_MEMINFO_FORMAT, total, free )==EOF ){
		LOGGER_error("mem stats failed");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/**
 * get process statistics
 */
int get_proc_pid_stat( struct proc_pid_stat* process ) {
	FILE *fp;
	char filename[128];

	sprintf(filename, PROC_PID_STAT_FILENAME, getpid());
	if ((fp = fopen(filename, "r")) == NULL){
		LOGGER_error("fopen error: %s", strerror(errno));
		return -1;
	}
	if( fscanf(fp,
			PROC_PID_STAT_FORMAT,
			&process->pid,
			process->comm,
			&process->state ,
			&process->ppid,
			&process->pgrp ,
			&process->session,
			&process->tty_nr,
			&process->tpgid ,
			&process->flags,
			&process->minflt,
			&process->cminflt,
			&process->majflt,
			&process->cmajflt,
			&process->utime,
			&process->stime,
			&process->cutime,
			&process->cstime ,
			&process->priority ,
			&process->nice ,
			&process->num_threads ,
			&process->itrealvalue,
			&process->starttime,
			&process->vsize ,
			&process->rss ,
			&process->rsslim ,
			&process->startcode,
			&process->endcode,
			&process->startstack ,
			&process->kstkesp,
			&process->kstkeip ,
			&process->signal,
			&process->blocked,
			&process->sigignore,
			&process->sigcatch,
			&process->wchan ,
			&process->nswap,
			&process->cnswap ,
			&process->exit_signal,
			&process->processor ,
			&process->rt_priority ,
			&process->policy ,
			&process->delayacct_blkio_ticks  ,
			&process->guest_time,
			&process->cguest_time )==EOF){
		LOGGER_error("probe stats failed: %s", strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/**
 * get system statistics
 */
int get_proc_stat( struct proc_stat_cpu* cpu ) {
	FILE *fp;

	if ((fp = fopen(PROC_STAT_FILENAME, "r")) == NULL){
		LOGGER_error("Could not open file for reading: %s",PROC_STAT_FILENAME);
		return -1;
	}
	if(fscanf(fp, PROC_STAT_CPU_FORMAT,
			&cpu->user,
			&cpu->nice,
			&cpu->system,
			&cpu->idle,
			&cpu->iowait,
			&cpu->irq,
			&cpu->softirq,
			&cpu->steal,
			&cpu->guest)==EOF ){
		LOGGER_error("probe stats failed: %s", strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/**
 * Get probe statistics
 *
 * return 0 when successful, -1 otherwise
 */
int get_probe_stats(struct probe_stat *stat ){
	static bool first_execution = true;

	static struct proc_pid_stat process;
	static struct proc_stat_cpu cpu;

	static unsigned long long cpu_total          = 0;
	static unsigned long long cpu_total_prev     = 0;
	static unsigned long long cpu_idle_prev      = 0;
	static unsigned long long process_utime_prev = 0;
	static unsigned long long process_stime_prev = 0;

	float cpu_total_delta = 0;

	long memTotal = 0;
	long memFree  = 0;
	static int pagesize= 0;
	pagesize = pagesize? pagesize:getpagesize();

	// initialize stats
	stat->systemCpuIdle  = STATS_MISSING;
	stat->processCpuSys  = STATS_MISSING;
	stat->processCpuUser = STATS_MISSING;
	stat->systemMemFree  = STATS_MISSING;
	stat->processMemVzs  = STATS_MISSING;
	stat->processMemRss  = STATS_MISSING;

	// init prev values - sialates a previous execution
	if( true == first_execution ) {
		// Getting system cpu stats
		if( -1 == get_proc_stat(&cpu) ) return -1;
		// Getting process stats
		if( -1 == get_proc_pid_stat(&process) ) return -1;

		// just to create a difference during start-up
		--cpu.idle;
		// calculate total cpu usage
		cpu_total = cpu.user + cpu.nice + cpu.system + cpu.idle;
//				+ cpu.iowait + cpu.irq + cpu.softirq + cpu.steal;

		first_execution = false;
	}

	// saving data from previous run to yield delta
	cpu_total_prev     = cpu_total;
	cpu_idle_prev      = cpu.idle;
	process_stime_prev = process.stime;
	process_utime_prev = process.utime;

	// Memory usage stats
	if( -1 == get_mem_usage(&memTotal, &memFree) ) return -1;
	// Getting process stats
	if( -1 == get_proc_pid_stat(&process) ) return -1;
	// Getting system cpu stats
	if( -1 == get_proc_stat(&cpu) ) return -1;

	//    usecpu();

	cpu_total = cpu.user + cpu.nice + cpu.system + cpu.idle;
//			+ cpu.iowait + cpu.irq + cpu.softirq + cpu.steal;

	fprintf(stderr, "(t,i,st,ut) %llu %llu %lu %lu\n"
				, cpu_total, cpu.idle, process.stime, process.utime);

	cpu_total_delta = cpu_total - cpu_total_prev;
	if(cpu_total_delta <= 0){
		LOGGER_warn("could not get cpu usage");
		return -1;
	}

	// set all values of stat structure
	stat->systemCpuIdle  = (cpu.idle - cpu_idle_prev)/cpu_total_delta;
	stat->processCpuSys  = (process.stime - process_stime_prev) / cpu_total_delta ;
	stat->processCpuUser = (process.utime - process_utime_prev) / cpu_total_delta ;
	stat->systemMemFree  = memFree;
	stat->processMemVzs  = process.vsize;
	stat->processMemRss  = process.rss * pagesize;

	return 0;
}
