/*


 */

#include "stats.h"
#include "logger.h"
/**
 * Get probe statistics
 */
int get_probe_stats(struct probe_stat *stat ){
	int ret =0;
	stat->systemCpuIdle=0.123;
	stat->systemMemFree =12345;
	stat->processCpuUser=0.456;
	stat->processCpuSys =0.789;
	stat->processMemVzs = 67890;
	stat->processMemRss = 11;
	return ret;
}
