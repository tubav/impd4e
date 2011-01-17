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
#include <sys/types.h>

#include "constants.h"


uint32_t getIPv4AddressFromDevice(char* dev_name);

char* htoa(uint32_t ipaddr);

int sampling_set_ratio(options_t *options, double sampling_ratio);

void setNONBlocking( device_dev_t* pDevice );

int get_file_desc( device_dev_t* pDevice );

int socket_dispatch(int socket, int max_packets, pcap_handler packet_handler, u_char* user_args);

#ifdef PFRING
#ifdef PFRING_STATS
void print_stats( device_dev_t* dev );
#endif
int pfring_dispatch(pfring* pd, int max_packets, void(*packet_handler)(u_char*, const struct pfring_pkthdr*, const u_char*), u_char* user_args);
int setPFRingFilter(device_dev_t* pfring_device);
int8_t setPFRingFilterPolicy(device_dev_t* pfring_device);
#endif

void determineLinkType(device_dev_t* pcap_device);

void setFilter(device_dev_t* pcap_device);

void print_byte_array_hex( uint8_t* p, int length );

#endif /* HELPER_H_ */
