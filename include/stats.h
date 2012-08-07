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


#ifndef STAT_H_
#define STAT_H_
#ifndef PFRING
#include <pcap.h>
#endif

#include <stdint.h>

struct probe_stat {
	/**
	 *
	 */
	uint64_t observationTimeMilliseconds;
	/**
	 * System idle CPU
	 */
	float systemCpuIdle;
	/**
	 * System free memory in kilobytes
	 */
	uint64_t systemMemFree;
	/**
	 * System total memory in kilobytes
	 */
	uint64_t systemMemTotal;
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
	uint64_t processMemVzs;
	/**
	 * the process resident set size in bytes
	 */
	uint64_t processMemRss;

};
int get_probe_stats(struct probe_stat *stats );


#endif /* STAT_H_ */
