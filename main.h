/* impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll) & TU-Berlin (Christian Henke)
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation;
 *  either version 3 of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MAIN_H_
#define MAIN_H_

#include <pcap.h>
#include <ipfix.h>
#include <stdbool.h>

#define MAX_INTERFACES 10
#define PCAP_DISPATCH_PACKET_COUNT 10 /*!< max number of packets to be processed on each dispatch */

typedef uint32_t (*hashFunction)(uint8_t*,uint16_t);
typedef uint16_t (*selectionFunction) (const uint8_t *, uint16_t , uint8_t *, uint16_t, int16_t *, uint8_t*);
/**
 * program / device options
 *
 */
typedef struct options
{	char basedir[100];
	uint8_t number_interfaces;
	char *if_names[MAX_INTERFACES];
	uint32_t templateID;
	char collectorIP[256];
	int16_t collectorPort;
	char* bpf; // berkley packet filter
	uint32_t observationDomainID;
	hashFunction hash_function;
	hashFunction pktid_function;
	selectionFunction selection_function;
	uint32_t sel_range_min;
	uint32_t sel_range_max;
	uint16_t snapLength;
	uint8_t verbosity;
	uint32_t export_packet_count;
	uint32_t export_interval;
	double sampling_ratio;
	bool samplingResultExport;
	bool export_sysinfo;
	bool export_times;
	int hashAsPacketID;
	char *file;
} options_t;


/**
 * Capture devices
 */
typedef struct pcap_dev {
	pcap_t *pcap_handle;
	char * ifname;
	options_t *options;
	bpf_u_int32 IPv4address;
	bpf_u_int32 mask;
	int link_type;
	ipfix_t *ipfixhandle;
	ipfix_template_t *ipfixtemplate_min;
	ipfix_template_t *ipfixtemplate_ttl;
	ipfix_template_t *ipfixtemplate_sampling;
	int16_t offset[4];
	uint8_t *outbuffer;
	uint16_t outbufferLength;
	uint32_t export_packet_count;
	uint64_t totalpacketcount;
	struct timeval last_export_time;
} pcap_dev_t;

// hash functions for parsing


#define HASH_FUNCTION_BOB "BOB"
#define HASH_FUNCTION_OAAT "OAAT"
#define HASH_FUNCTION_TWMX "TWMX"
#define HASH_FUNCTION_HSIEH "HSIEH"

char* hashfunctionname[] = {
 "dummy",
 "BOB",
 "TWMX",
 "OAAT",
 "SBOX"
};

//hash input selection functions for parsing
#define HASH_INPUT_REC8 "REC8"
#define HASH_INPUT_IP "IP"
#define HASH_INPUT_IPTP "IP+TP"
#define HASH_INPUT_PACKET "PACKET"

// template definition

#define MINT_ID 0
#define TS_TTL_PROTO_ID 1

#define MIN_NAME  "min"
#define TS_TTL_RROTO_NAME "lp"

typedef enum hash_function {
	FUNCTION_BOB		= 0x001,
	FUNCTION_TWMX		= 0x002,
	FUNCTION_OAAT		= 0x003,
	FUNCTION_SBOX		= 0x004,
} hash_function_t;



typedef enum hash_input_selection {
	INPUT_8_RECOMMENDED_BYTES = 0x001,
	INPUT_IP_HEADER 	  = 0x002,
	INPUT_IP_TRANSPORT_HEADER = 0x003,
	INPUT_WHOLE_PACKET	  = 0x004,
} hash_input_selection_t;


// log level

#define ALWAYS 0
#define CRITICAL 1
#define WARNING 2
#define INFO 3



#endif /* MAIN_H_ */
