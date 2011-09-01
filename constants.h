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

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifndef PFRING
#include <pcap.h>
#endif

#include <ipfix.h>

#ifdef PFRING
#include <pfring.h>
#endif

#include "hash.h" // todo:


#ifndef MAX_INTERFACES
#define MAX_INTERFACES 10
#endif

#define PCAP_DISPATCH_PACKET_COUNT 10 /*!< max number of packets to be processed on each dispatch */

#define BUFFER_SIZE 1024

#ifdef PFRING
#define MAX_RULES 256
#endif // PFRING

typedef uint32_t (*hashFunction)(uint8_t*,uint16_t);
typedef uint16_t (*selectionFunction) (const uint8_t *, uint16_t , uint8_t *, uint16_t, int16_t *, uint8_t*);

typedef void (*device_handler)(u_char*, void* , const u_char* );


typedef struct {
	uint8_t*       ptr;
	uint32_t       len;
	const uint32_t max_len;
}
buffer_t;

typedef union device {
    #ifndef PFRING
	pcap_t* pcap;
    #endif
	char*   pcap_file;
	int     socket;
	#ifdef PFRING
	pfring* pfring;
	#endif
} device_t;

typedef enum {
	  TYPE_UNKNOWN
	, TYPE_PCAP
	, TYPE_PCAP_FILE
	, TYPE_SOCKET_UNIX
	, TYPE_SOCKET_INET
	, TYPE_FILE
	, TYPE_testtype
	#ifdef PFRING
	, TYPE_PFRING
	#endif
} device_type_t;

typedef struct device_desc {
	device_type_t	  type;
	char*             name;	// network adapter; file-name; socket-name; depends on device type
	device_t          handle;
} device_desc_t;

typedef struct ipfix_conf {
	ipfix_t*          handle;
	ipfix_template_t* template;
	ipfix_template_t* sampling_template;
} ipfix_conf_t;

typedef struct device_dev {
	device_type_t     device_type;
	char*             device_name;	// network adapter; file-name; socket-name; depends on device type
	device_t          device_handle;
    #ifndef PFRING
	bpf_u_int32       IPv4address; // network byte order
	bpf_u_int32       mask;
    #else
    uint32_t          IPv4address;
    uint32_t          mask;
    #endif
	int               link_type;
	ipfix_t*          ipfixhandle;
//	ipfix_template_t* ipfixtemplate;
	ipfix_template_t *ipfixtmpl_min;
	ipfix_template_t *ipfixtmpl_ts;
	ipfix_template_t *ipfixtmpl_ts_ttl;
	ipfix_template_t *ipfixtmpl_ts_ttl_ip;
	ipfix_template_t *ipfixtmpl_interface_stats;
	ipfix_template_t *ipfixtmpl_probe_stats;
	ipfix_template_t *ipfixtmpl_sync;
	ipfix_template_t *ipfixtmpl_location;
	ipfix_template_t *sampling_export_template;
	int16_t           offset[4];
	uint8_t*          outbuffer;
	uint16_t          outbufferLength;
	uint32_t          export_packet_count;
	uint64_t          totalpacketcount;
	struct timeval    last_export_time;
	uint32_t sampling_size;
	uint64_t sampling_delta_count;
} device_dev_t;

typedef struct packet_data {
	const uint8_t*  packet;
	uint32_t        length;
	uint32_t        capture_length;
	struct timeval  timestamp;
} packet_data_t;

typedef struct export_data {
	buffer_t    buffer;
	// layer offsets (IP Stack)
	uint64_t    timestamp;
	int16_t     layer_offsets[4];
	netProt_t   net;
	transProt_t transport;
	uint8_t     ttl;
} export_data_t;

// hash functions for parsing
#define HASH_FUNCTION_BOB   "BOB"
#define HASH_FUNCTION_OAAT  "OAAT"
#define HASH_FUNCTION_TWMX  "TWMX"
#define HASH_FUNCTION_HSIEH "HSIEH"

//hash input selection functions for parsing
#define HASH_INPUT_REC8    "REC8"
#define HASH_INPUT_IP      "IP"
#define HASH_INPUT_IPTP    "IP+TP"
#define HASH_INPUT_PACKET  "PACKET"
#define HASH_INPUT_RAW     "RAW"
#define HASH_INPUT_LINK    "LINK"
#define HASH_INPUT_NET     "NET"
#define HASH_INPUT_TRANS   "TRANS"
#define HASH_INPUT_PAYLOAD "PAYLOAD"
#define HASH_INPUT_SELECT  "SELECT"

// template definition
#define MINT_ID         	0
#define TS_TTL_PROTO_ID 	1
#define TS_ID           	2
#define TS_TTL_PROTO_IP_ID 	3

#define MIN_NAME  		"min"
#define TS_TTL_RROTO_NAME 	"lp"
#define TS_NAME			"ts"
#define TS_TTL_RROTO_IP_NAME 	"ls"

typedef enum hash_function {
	FUNCTION_BOB		 = 0x001,
	FUNCTION_TWMX		= 0x002,
	FUNCTION_OAAT		= 0x003,
	FUNCTION_SBOX		= 0x004,
} hash_function_t;



typedef enum hash_input_selection {
	INPUT_8_RECOMMENDED_BYTES = 0x001,
	INPUT_IP_HEADER           = 0x002,
	INPUT_IP_TRANSPORT_HEADER = 0x003,
	INPUT_WHOLE_PACKET        = 0x004,
} hash_input_selection_t;


// log level
enum {
	  ALWAYS=0
	, ERROR=1
	, CRITICAL=1
	, WARNING=2
	, INFO
	, DEBUG
	, ALL
};

// todo: use getter instead
extern device_dev_t  if_devices[];
#ifndef PFRING
extern char pcap_errbuf[PCAP_ERRBUF_SIZE];
extern char errbuf[PCAP_ERRBUF_SIZE];
#endif


#endif /* CONSTANTS_H_ */
