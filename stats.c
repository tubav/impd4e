/*
  Get process and system statistics. It only supports linux and depends on the proc filesystem.
 */

#include "stats.h"
#include "logger.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

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
	unsigned int flags;
	unsigned long   minflt;
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
 * Get probe statistics
 *
 * return 0 when successful, -1 otherwise
 */
int get_probe_stats(struct probe_stat *stat ){
	FILE *fp;
	char filename[128];
	static struct proc_pid_stat process;
	static struct proc_stat_cpu cpu;
	static unsigned long long cpu_total_prev=0, cpu_total=0,
			cpu_idle_prev=0,
			process_utime_prev =0,
			process_stime_prev=0;
	long memTotal = 0;
	long memFree = 0;
	static int pagesize= 0;
	pagesize = pagesize? pagesize:getpagesize();

	stat->processCpuSys = STATS_MISSING;
	stat->processCpuUser = STATS_MISSING;
	stat->systemMemFree = STATS_MISSING;
	stat->processMemVzs =  STATS_MISSING;
	stat->processMemRss =  STATS_MISSING;

	/* saving data from previous run to yield delta  */
	cpu_total_prev = cpu_total;
	cpu_idle_prev = cpu.idle;
	process_stime_prev = process.stime;
	process_utime_prev = process.utime;
	/*
	 * Memory usage
	 */
	if ((fp = fopen(PROC_MEMINFO_FILENAME, "r")) == NULL){
		LOGGER_error("fopen error: %s", strerror(errno));
		return -1;
	}
	if( fscanf(fp, PROC_MEMINFO_FORMAT, &memTotal, &memFree )==EOF ){
		LOGGER_error("mem stats failed");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	stat->systemMemFree =memFree;
	/*
	 * Getting process stats
	 */
	sprintf(filename, PROC_PID_STAT_FILENAME, getpid());
	if ((fp = fopen(filename, "r")) == NULL){
		LOGGER_error("fopen error: %s", strerror(errno));
		return -1;
	}
	if( fscanf(fp,
			PROC_PID_STAT_FORMAT,
			&process.pid,
			process.comm,
			&process.state ,
			&process.ppid,
			&process.pgrp ,
			&process.session,
			&process.tty_nr,
			&process.tpgid ,
			&process.flags,
			&process.minflt,
			&process.cminflt,
			&process.majflt,
			&process.cmajflt,
			&process.utime,
			&process.stime,
			&process.cutime,
			&process.cstime ,
			&process.priority ,
			&process.nice ,
			&process.num_threads ,
			&process.itrealvalue,
			&process.starttime,
			&process.vsize ,
			&process.rss ,
			&process.rsslim ,
			&process.startcode,
			&process.endcode,
			&process.startstack ,
			&process.kstkesp,
			&process.kstkeip ,
			&process.signal,
			&process.blocked,
			&process.sigignore,
			&process.sigcatch,
			&process.wchan ,
			&process.nswap,
			&process.cnswap ,
			&process.exit_signal,
			&process.processor ,
			&process.rt_priority ,
			&process.policy ,
			&process.delayacct_blkio_ticks  ,
			&process.guest_time,
			&process.cguest_time )==EOF){
		LOGGER_error("probe stats failed: %s", strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	//    usecpu();
	stat->processMemVzs =  process.vsize;
	stat->processMemRss = process.rss *pagesize;

	/*
	 * Getting system cpu stats
	 */
	if ((fp = fopen(PROC_STAT_FILENAME, "r")) == NULL){
		LOGGER_error("Could not open file for reading: %s",PROC_STAT_FILENAME);
		return -1;
	}
	if(fscanf(fp, PROC_STAT_CPU_FORMAT,
			&cpu.user,
			&cpu.nice,
			&cpu.system,
			&cpu.idle,
			&cpu.iowait,
			&cpu.irq,
			&cpu.softirq,
			&cpu.steal,
			&cpu.guest)==EOF ){
		LOGGER_error("probe stats failed: %s", strerror(errno));
		fclose(fp);
		return -1;
	}
	fclose(fp);
	cpu_total = cpu.user+
			cpu.nice+
			cpu.system+
			cpu.idle+
			cpu.iowait+
			cpu.irq+
			cpu.softirq+
			cpu.steal;

	if(cpu_total_prev> 0 ){
		float total_cpu_delta= cpu_total - cpu_total_prev;
		if(total_cpu_delta <= 0){
			LOGGER_warn("could not get cpu usage");
			return -1;
		}
		stat->systemCpuIdle=(cpu.idle - cpu_idle_prev)/total_cpu_delta;
		stat->processCpuSys = (process.stime - process_stime_prev) / total_cpu_delta ;
		stat->processCpuUser = (process.utime - process_utime_prev) / total_cpu_delta ;
	}
	return 0;
}
