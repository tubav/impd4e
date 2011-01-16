/*
 * helper.h
 *
 *  Created on: 12.10.2010
 *      Author: rma
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
#endif

void determineLinkType(device_dev_t* pcap_device);

void setFilter(device_dev_t* pcap_device);
int8_t setPFRingFilterPolicy(device_dev_t* pfring_device);

void print_byte_array_hex( uint8_t* p, int length );

#endif /* HELPER_H_ */
