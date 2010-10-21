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

void determineLinkType(device_dev_t* pcap_device);

void setFilter(device_dev_t* pcap_device);

#endif /* HELPER_H_ */
