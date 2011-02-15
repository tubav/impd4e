/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Ramon Massek)
 * Copyright (c) 2010, Robert Wuttke <flash@jpod.cc>
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

#ifndef HELPER_H_
#define HELPER_H_

#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>

#include "constants.h"

#ifdef PFRING
/*
 * These are the types that are the same on all platforms, and that
 * have been defined by <net/bpf.h> for ages.
 */
#define DLT_NULL    0   /* BSD loopback encapsulation */
#define DLT_EN10MB  1   /* Ethernet (10Mb) */
#define DLT_EN3MB   2   /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3   /* Amateur Radio AX.25 */
#define DLT_PRONET  4   /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5   /* Chaos */
#define DLT_IEEE802 6   /* 802.5 Token Ring */
#define DLT_ARCNET  7   /* ARCNET, with BSD-style header */
#define DLT_SLIP    8   /* Serial Line IP */
#define DLT_PPP     9   /* Point-to-point Protocol */
#define DLT_FDDI    10  /* FDDI */
#endif

uint32_t getIPv4AddressFromDevice(char* dev_name);

char* htoa(uint32_t ipaddr);

int set_sampling_ratio(options_t *options, char* value);
int set_sampling_lowerbound(options_t *options, char* value);
int set_sampling_upperbound(options_t *options, char* value);

#ifndef PFRING
void setNONBlocking( device_dev_t* pDevice );
#endif

int get_file_desc( device_dev_t* pDevice );

#ifndef PFRING
int socket_dispatch(int socket, int max_packets, pcap_handler packet_handler, u_char* user_args);
#endif

#ifdef PFRING
#ifdef PFRING_STATS
void print_stats( device_dev_t* dev );
#endif
int pfring_dispatch(pfring* pd, int max_packets, void(*packet_handler)(u_char*, const struct pfring_pkthdr*, const u_char*), u_char* user_args);
int setPFRingFilter(device_dev_t* pfring_device);
int8_t setPFRingFilterPolicy(device_dev_t* pfring_device);
#endif

#ifndef PFRING
void determineLinkType(device_dev_t* pcap_device);
int  set_all_filter(const char* bpf);
int  set_filter(device_dev_t* pd, const char* bpf);
void setFilter(device_dev_t* pcap_device);
#endif

void print_byte_array_hex( uint8_t* p, int length );

#endif /* HELPER_H_ */
