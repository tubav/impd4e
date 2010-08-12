
#ifndef STAT_H_
#define STAT_H_
#include <pcap.h>

struct probe_stat {
	/**
	 *
	 */
	u_int64_t observationTimeMilliseconds;
	/**
	 * System idle CPU, see "man mpstat" for more information.
	 */
	float systemCpuIdle;
	/**
	 * System free memory in kilobytes, see "man pidstat" for more information.
	 */
	u_int64_t systemMemFree;
	/**
	 * percentage of CPU used in user level (application), see "man pidstat" for
	 * more information"
	 */
	float processCpuUser;
	/**
	 * percentage of CPU used in system level (kernel), see "man pidstat" for
	 * more information"
	 */
	float processCpuSys;
	/**
	 * the process virtual memory used in kilobytes, see "man pidstat" for more
	 * information"
	 */
	u_int64_t processMemVzs;
	/**
	 * the process resident set size in kilobytes, see "man pidstat" for more
	 * information"
	 */
	u_int64_t processMemRss;

};
int get_probe_stats(struct probe_stat *stats );


#endif /* STAT_H_ */
