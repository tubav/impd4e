/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll, Tacio Santos)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation either version 3 of the License, or (at your option) any
 * later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

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
