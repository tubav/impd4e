/*
 * helper.c
 *
 *  Created on: 12.10.2010
 *      Author: rma
 */

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>

#include <string.h>

#include "logger.h"
#include "helper.h"

uint32_t getIPv4AddressFromDevice(char* dev_name) {

	int fd;
	struct ifreq ifr;
	uint32_t IPv4_Address = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror("cannot create socket: ");
		exit(1);
	}

	/* I want to get an IPv4 IP address */
	ifr.ifr_addr.sa_family = AF_INET;

	/* I want IP address attached to device */
	strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);

	IPv4_Address = ntohl(
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);

	close(fd);

	return IPv4_Address;
}

/**
 * Helper for printing out IPv4 address
 */
char *htoa(uint32_t ipaddr) {
	static char addrstr[16];
	ipaddr = htonl(ipaddr);
	uint8_t *p = (uint8_t*) &ipaddr;
	sprintf(addrstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return addrstr;
}

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int sampling_set_ratio(options_t *options, double sampling_ratio) {
	LOGGER_debug("sampling ratio: %lf", sampling_ratio);
	/*
	 * for the sampling ratio we do not like values at the edge, therefore we use values beginning at the 10% slice.
	 */
	options->sel_range_min = 0x19999999;
	options->sel_range_max = (double) UINT32_MAX / 100 * sampling_ratio;

	if (UINT32_MAX - options->sel_range_max > options->sel_range_min) {
		options->sel_range_min = 0x19999999;
		options->sel_range_max += options->sel_range_min;
	} else {
		/* more than 90% therefore use also values from first 10% slice */
		options->sel_range_min = UINT32_MAX - options->sel_range_max;
		options->sel_range_max = UINT32_MAX;
	}
	return 0;
}


