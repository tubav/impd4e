/*
 * helper.c
 *
 *  Created on: 12.10.2010
 *      Author: rma
 */

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <net/if.h>
#include <netinet/in.h>

#include <pcap.h>

#include <string.h>

#include "mlog.h"
#include "logger.h"
#include "helper.h"
#include "constants.h"


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


void setNONBlocking( device_dev_t* pDevice )
{
	switch (pDevice->device_type) {
	case TYPE_PCAP_FILE:
	case TYPE_PCAP:
		if (pcap_setnonblock(pDevice->device_handle.pcap, 1, errbuf) < 0) {
			mlogf(ALWAYS, "pcap_setnonblock: %s: %s"
						, pDevice->device_name, errbuf);
			LOGGER_error( "pcap_setnonblock: %s: %s"
					, pDevice->device_name, errbuf );

		}
		break;

	case TYPE_SOCKET_INET:
	case TYPE_SOCKET_UNIX: {
		int flags = 0;
		if ((flags = fcntl(pDevice->device_handle.socket, F_GETFL, 0)) < 0) {
			// todo: handle error
			mlogf(ALWAYS, "fcntl (F_GETFL) fails\n");
			LOGGER_error( "fcntl (F_GETFL) fails");
		}

		if (fcntl(pDevice->device_handle.socket, F_SETFL, flags | O_NONBLOCK) < 0) {
			// todo: handle error
			mlogf(ALWAYS, "fcntl (F_SETFL - _NONBLOCK) fails\n");
			LOGGER_error( "fcntl (F_SETFL - _NONBLOCK) fails\n");
		}

		break;
	}

	default:
		break;
	}
}

int get_file_desc( device_dev_t* pDevice ) {
	switch (pDevice->device_type) {
	case TYPE_testtype:
	case TYPE_PCAP_FILE:
	case TYPE_PCAP:
		return pcap_fileno(pDevice->device_handle.pcap);
		break;

	case TYPE_SOCKET_INET:
	case TYPE_SOCKET_UNIX:
		return pDevice->device_handle.socket;
		break;

	default:
		return 0;
		break;
	}

}

int socket_dispatch(int socket, int max_packets, pcap_handler packet_handler, u_char* user_args)
{
	int32_t  i;
	int32_t  nPackets = 0;
	uint8_t  buffer[BUFFER_SIZE];

	struct pcap_pkthdr hdr;

	for ( i = 0
		; i < max_packets || 0 == max_packets || -1 == max_packets
		; ++i)
	{
		// ensure buffer will fit
		uint32_t caplen = BUFFER_SIZE;
		if( BUFFER_SIZE > g_options.snapLength )
		{
			caplen = g_options.snapLength;
		}
		else
		{
			mlogf( WARNING, "socket_dispatch: snaplan exceed Buffer size (%d); "
							"use Buffersize instead.\n", BUFFER_SIZE );
		}

		// recv is blocking; until connection is closed
		switch(hdr.caplen = recv(socket, buffer, caplen, 0)) {
		case 0: {
			fprintf(stderr, "socket: recv(); connection shutdown\n");
			return -1;
		}

		case -1: {
			if (EAGAIN == errno || EWOULDBLOCK == errno) {
				return nPackets;
			} else {
				perror("socket: recv()");
				return -1;
			}
		}

		default: {
			// get timestamp
			gettimeofday(&hdr.ts, NULL);

			hdr.len = hdr.caplen;

			// print received data
			// be aware of the type casts need
			packet_handler(user_args, &hdr, buffer);
			++nPackets;
		}
		} // switch(recv())
	}

	return nPackets;
}

void determineLinkType(device_dev_t* pcap_device) {

	pcap_device->link_type = pcap_datalink(pcap_device->device_handle.pcap);
	switch (pcap_device->link_type) {
	case DLT_EN10MB:
		pcap_device->offset[L_NET] = 14;
		LOGGER_info("dltype: DLT_EN10M");
		break;
	case DLT_ATM_RFC1483:
		pcap_device->offset[L_NET] = 8;
		LOGGER_info("dltype: DLT_ATM_RFC1483");
		break;
	case DLT_LINUX_SLL:
		pcap_device->offset[L_NET] = 16;
		LOGGER_info("dltype: DLT_LINUX_SLL");
		break;
	case DLT_RAW:
		pcap_device->offset[L_NET] = 0;
		LOGGER_info("dltype: DLT_RAW");
		break;
	default:
		mlogf(ALWAYS, "Link Type (%d) not supported - default to DLT_RAW \n",
				pcap_device->link_type);
		pcap_device->offset[L_NET] = 0;
		break;
	}
}

void setFilter(device_dev_t* pcap_device) {
	/* apply filter */
	struct bpf_program fp;

	if (g_options.bpf) {
		if (-1 == pcap_compile(pcap_device->device_handle.pcap, &fp,
				g_options.bpf, 0, 0)) {
			mlogf(ALWAYS, "Couldn't parse filter %s: %s\n", g_options.bpf,
					pcap_geterr(pcap_device->device_handle.pcap));
		}
		if (-1 == pcap_setfilter(pcap_device->device_handle.pcap, &fp)) {
			mlogf(ALWAYS, "Couldn't install filter %s: %s\n", g_options.bpf,
					pcap_geterr(pcap_device->device_handle.pcap));
		}
	}
}


void print_byte_array_hex( char* p, int length ) {
	int i = 0;
	fprintf( stderr, "bytes(length=%d): ", length );
	for( i = 0; i < length; ++i )
		fprintf( stderr, "%02x ", p[i] );
	fprintf( stderr, "\n" );
}




