
#ifndef STAT_H_
#define STAT_H_
#include <pcap.h>

struct probe_stat {
	/**
	 *
	 */
	u_int64_t observationTimeMilliseconds;
	/**
	 * System idle CPU
	 */
	float systemCpuIdle;
	/**
	 * System free memory in kilobytes
	 */
	u_int64_t systemMemFree;
	/**
	 * percentage of CPU used in user level (application)
	 */
	float processCpuUser;
	/**
	 * percentage of CPU used in system level (kernel)
	 */
	float processCpuSys;
	/**
	 * the process virtual memory used in bytes
	 */
	u_int64_t processMemVzs;
	/**
	 * the process resident set size in bytes
	 */
	u_int64_t processMemRss;

};
int get_probe_stats(struct probe_stat *stats );


#endif /* STAT_H_ */
