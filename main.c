/**
 * @file
 * @brief parse command line, event handing, control functions.
 */
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

#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h> /* TODO review: sysinfo is Linux only */
#include <sys/times.h>

#include <netinet/in.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <pcap.h>

// event loop
#include <ev.h>
#include "ev_handler.h"

#include "main.h"

#include "templates.h"
#include "constants.h"
#include "main.h"
#include "hash.h"
#include "mlog.h"
#include "ipfix.h"
#include "ipfix_fields_fokus.h"
#include "stats.h"

// Custom logger
#include "logger.h"
#include "helper.h"
#include "netcon.h"

/*----------------------------------------------------------------------------
 Globals
 ----------------------------------------------------------------------------- */

char pcap_errbuf[PCAP_ERRBUF_SIZE];
char errbuf[PCAP_ERRBUF_SIZE];

options_t     g_options;
device_dev_t* if_devices;

char* hashfunctionname[] = {
 "dummy",
 "BOB",
 "TWMX",
 "OAAT",
 "SBOX"
};

/**
 * Print out command usage
 */
void print_help() {
	printf(
			"impd4e - a libpcap based measuring probe which uses hash-based packet\n"
				"         selection and exports packetIDs via IPFIX to a collector.\n\n"
				"USAGE: impd4e -i interface [options] \n"
				"\n");
	printf(
			"options: \n"
			"   -C  <collector IP> \n"
			"   -c  <export packet count>      size of export buffer after which packets\n"
			"                                  are flushed (per device)\n"
			"   -f  <bpf>                      Berkeley Packet Filter expression (e.g. \n"
			"                                  tcp udp icmp)\n"
			"   -F  <hash_function>            hash function to use \"BOB\", \"OAAT\", \n"
			"                                  \"TWMX\", \"HSIEH\"\n"
			"   -h                             print this help \n"
			"   -I  <interval>                 pktid export interval in seconds. Use 0 for \n"
			"                                  disabling pkid export. Ex. -I 1.5  \n"
			"   -i  <interface>                interface(s) to listen on. It can be used \n"
			"                                  multiple times.   \n"
			"   -J  <interval>                 probe stats export interval in seconds. \n"
			"                                  Measurement is done at each elapsed interval. \n"
			"                                  Use -J 0 for disabling this export.\n"
			"                                  Default: 30.0 \n"
			"      Example: \n"
			"        DATA RECORD: \n"
			"         template id:  259 \n"
			"         nfields:      9 \n"
			"         observationTimeMilliseconds: 1282142171000 \n"
			"         sys_cpu_idle: 0.960396   (1.0 = 100%%)\n"
			"         sys_mem_free: 848244     (kbytes) \n"
			"         proc_cpu_user: 0.000000  (1.0 = 100%%) \n"
			"         proc_cpu_sys: 0.000000   (1.0 = 100%%)\n"
			"         proc_mem_vzs: 4456448    (bytes) \n"
			"         proc_mem_rss: 3145728    (bytes) \n"
			"         pcap_recv: 146           (packets) \n"
			"         pcap_drop: 0             (packets) \n"
			"\n"
			"   -K  <interval>                 sampling stats export interval in seconds. \n"
			"                                  Measurement is done at each elapsed interval. \n"
			"                                  Use -K 0 for disabling this export.\n"
			"                                  Default: 10.0 \n"
			"      Example: \n"
			"        DATA RECORD: \n"
			"         template id:  258 \n"
			"         nfields:      3 \n"
			"         observationTimeMilliseconds: 1282142171000 \n"
			"         samplingSize: 18 \n"
			"         packetDeltaCount: 470  \n"
			"\n"
			"   -M  <maximum selection range>  integer - do not use in conjunction with -r \n"
			"   -m  <minimum selection range>  integer - do not use in conjunction with -r \n"
			"   -o  <observation domain id>    identification of the interface in\n"
			"                                  the IPFIX Header\n"
			"   -P  <collector port> \n"
			"   -p  <hash function>            use different hash_function for packetID\n"
			"                                  generation: \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\" \n"
			"   -r  <sampling ratio>           in %% (double)\n"
			"   -s  <selection function>       which parts of the header used for hashing\n"
			"                                  either \"IP+TP\", \"IP\", \"REC8\", \"PACKET\" \n"
			"   -t  <template>                 either \"min\" or \"lp\"\n"
			"   -u                             use only one oid from the first interface \n"
			"   -v  verbose-level              can be used multiple times to increase output \n\n");

}

void ipfix_reconnect() {
	int i;
	LOGGER_info("trying to reconnect ");
	for (i = 0; i < g_options.number_interfaces; i++) {
		ipfix_export_flush(if_devices[i].ipfixhandle);
		ipfix_close(if_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	init_libipfix(if_devices, &g_options);

}
/**
 * Shutdown impd4e
 */
void impd4e_shutdown() {
	int i;
	LOGGER_info("Shutting down..");
	for (i = 0; i < g_options.number_interfaces; i++) {
		ipfix_export_flush(if_devices[i].ipfixhandle);
		ipfix_close(if_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	free(if_devices);
}

/**
 * Set default options
 */
void options_set_defaults(options_t *options) {
	options->number_interfaces = 0;
	options->bpf = NULL;
	options->templateID = MINT_ID;
	options->collectorPort = 4739;
	strcpy(options->collectorIP, "localhost");
	options->observationDomainID = 0;
	options->hash_function = calcHashValue_BOB;
	options->selection_function = copyFields_U_TCP_and_Net;
	options->sel_range_min = 0x19999999; // (2^32 / 10)
	options->sel_range_max = 0x33333333; // (2^32 / 5)
	options->snapLength = 80;
	options->verbosity = 0;
	options->export_packet_count = 1000;
	options->export_pktid_interval = 3.0; /* seconds */
	options->export_sampling_interval = 10.0; /* seconds */
	options->export_stats_interval = 30.0; /* seconds */

	options->hashAsPacketID = 1;
	options->file = NULL;
	options->use_oid_first_interface = 0;

	//	options->samplingResultExport = false;
	//	options->export_sysinfo = false;
}
/**
 * Parse command line hash function
 */
hashFunction parseFunction(char *arg_string, options_t *options) {
	int k;
	int j = 0;
	struct hashfunction {
		char *hstring;
		hashFunction function;
	} hashfunctions[] = { { HASH_FUNCTION_BOB, calcHashValue_BOB }
						, { HASH_FUNCTION_TWMX, calcHashValue_TWMXRSHash }
						, { HASH_FUNCTION_HSIEH, calcHashValue_Hsieh }
						, { HASH_FUNCTION_OAAT, calcHashValue_OAAT } };

	for (k = 0; k < (sizeof(hashfunctions) / sizeof(struct hashfunction)); k++) {
		if (strncasecmp(arg_string, hashfunctions[k].hstring
				, strlen(hashfunctions[k].hstring)) == 0)
		{
			j = k;
			LOGGER_info("using %s as hashFunction \n", hashfunctions[k].hstring);

		}
	}
	return hashfunctions[j].function;
}
/**
 * Parse command line selection function
 */
void parseSelFunction(char *arg_string, options_t *options) {
	int k;
	struct selfunction {
		char *hstring;
		selectionFunction selfunction;
	} selfunctions[] = 	{ { HASH_INPUT_REC8, copyFields_Rec }
						, { HASH_INPUT_IP, copyFields_Only_Net }
						, { HASH_INPUT_IPTP, copyFields_U_TCP_and_Net }
						, { HASH_INPUT_PACKET, copyFields_Packet }
						, { HASH_INPUT_RAW, copyFields_Raw }
						, { HASH_INPUT_SELECT, copyFields_Select } };

	for (k = 0; k < (sizeof(selfunctions) / sizeof(struct selfunction)); k++) {
		if (strncasecmp(arg_string, selfunctions[k].hstring
				, strlen(selfunctions[k].hstring)) == 0)
		{
			options->selection_function = selfunctions[k].selfunction;
			// todo: special handling for raw and select
		}
	}
}
/**
 * Parse command line template
 */
void parseTemplate(char *arg_string, options_t *options) {
	int k;
	struct templateDef {
		char *hstring;
		int templateID;
	} templates[] = { { MIN_NAME, MINT_ID }, { TS_TTL_RROTO_NAME,
			TS_TTL_PROTO_ID }, { TS_NAME, TS_ID } };

	for (k = 0; k < (sizeof(templates) / sizeof(struct templateDef)); k++) {
		if (strncasecmp(arg_string, templates[k].hstring, strlen(
				templates[k].hstring)) == 0) {
			options->templateID = templates[k].templateID;
		}
	}
}

/**
 * Process command line arguments
 */
void parse_cmdline(int argc, char **argv) {

	options_t* options = &g_options;
	int c;
	char par[] = "vJ:K:i:I:o:r:t:f:m:M:hs:F:c:P:C:R:nSu";
	char *endptr;
	errno = 0;
	double sampling_ratio;

	options->number_interfaces = 0;

	while ((c = getopt(argc, argv, par)) != -1) {
		switch (c) {
		case 'C':
			/* collector port */
			strcpy(options->collectorIP, optarg);
			break;
		case 'c': /* export count */
			options->export_packet_count = atoi(optarg);
			break;
		case 'f':
			options->bpf = strdup(optarg);
			break;
		case 'h':
			print_help();
			exit(0);
			break;
		case 'i':
			if (options->number_interfaces == MAX_INTERFACES) {
				mlogf(ALWAYS, "specify at most %d interfaces with -i",
						MAX_INTERFACES);
				exit(1);
			}
			options->if_names[options->number_interfaces++] = strdup(optarg);
			break;
		case 'I':
			options->export_pktid_interval = atof(optarg);
			break;
		case 'J':
			options->export_stats_interval = atof(optarg);
			break;
		case 'K':
			options->export_sampling_interval = atof(optarg);
			break;

		case 'o':
			options->observationDomainID = atoi(optarg);
			break;
		case 't':
			parseTemplate(optarg, options);
			break;
		case 'm':
			options->sel_range_min = strtoll(optarg, &endptr, 0);
			if ((*endptr != '\0') || (errno == ERANGE
					&& (options->sel_range_min == LONG_MAX
							|| options->sel_range_min == LONG_MIN)) || (errno
					!= 0 && options->sel_range_min == 0)) {
				mlogf(ALWAYS,
						"error parsing selection_miminum_range - needs to be (uint32_t) \n");
				exit(1);
			}
			break;
		case 'M':
			options->sel_range_max = strtoll(optarg, NULL, 0);
			if ((*endptr != '\0') || (errno == ERANGE
					&& (options->sel_range_max == LONG_MAX
							|| options->sel_range_max == LONG_MIN)) || (errno
					!= 0 && options->sel_range_max == 0)) {
				mlogf(ALWAYS,
						"error parsing selection_maximum_range - needs to be (uint32_t) \n");
				exit(1);
			}
			break;
		case 's':
			parseSelFunction(optarg, options);
			break;
		case 'F':
			options->hash_function = parseFunction(optarg, options);
			break;
		case 'p':
			options->pktid_function = parseFunction(optarg, options);
			options->hashAsPacketID = 0;
			break;
		case 'P':
			if ((options->collectorPort = atoi(optarg)) < 0) {
				mlogf(ALWAYS, "Invalid -p argument!\n");
				exit(1);
			}
			break;
		case 'v':
			mlog_set_vlevel(options->verbosity++);
			break;
		case 'l':
			options->snapLength = atoi(optarg);
			break;
		case 'r':
			sscanf(optarg, "%lf", &sampling_ratio);
			sampling_set_ratio(options, sampling_ratio);
			break;
		case 'R':
			options->file = strdup(optarg);
			options->number_interfaces++;
			break;
		case 'u':
			options->use_oid_first_interface=1;
			break;
		case 'n':
			// TODO parse enable export sampling
			break;
		case 'S':
			// TODO
			//			options->export_sysinfo = true;
			break;
		default:
			printf("unknown parameter: %d \n", c);
			break;
		}

	}

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

void open_pcap_file(device_dev_t* if_dev, options_t *options) {

	// todo: parameter check

	if_dev->device_handle.pcap = pcap_open_offline(if_dev->device_name, errbuf);
	if (NULL == if_dev->device_handle.pcap) {
		mlogf(ALWAYS, "%s \n", errbuf);
	}
	determineLinkType(if_dev);
	setFilter(if_dev);
}

void open_pcap(device_dev_t* if_dev, options_t *options) {

	if_dev->device_handle.pcap = pcap_open_live(if_dev->device_name,
			options->snapLength, 1, 1000, errbuf);
	if (NULL == if_dev->device_handle.pcap) {
		mlogf(ALWAYS, "%s \n", errbuf);
		exit(1);
	}

	// if (pcap_lookupnet(options->if_names[i],
	//		&(if_devices[i].IPv4address), &(if_devices[i].mask), errbuf)
	//		< 0) {
	//	printf("could not determine netmask and Ip-Adrdess of device %s \n",
	//			options->if_names[i]);
	// }

	/* I want IP address attached to device */
	if_dev->IPv4address = getIPv4AddressFromDevice(if_dev->device_name);

	/* display result */
	mlogf(ALWAYS, "Device %s has IP %s \n", if_dev->device_name, htoa(
			if_dev->IPv4address));

	determineLinkType(if_dev);
	setFilter(if_dev);

	// dirty IP read hack - but socket problem with embedded interfaces

	//			FILE *fp;
	//			char *script = "getIPAddress.sh ";
	//			char *cmdLine;
	//			cmdLine = (char *) malloc((strlen(script) + strlen(
	//					options->if_names[i]) + 1) * sizeof(char));
	//			strcpy(cmdLine, script);
	//			strcat(cmdLine, options->if_names[i]);
	//			fp = popen(cmdLine, "r");
	//
	//			char IPAddress[LINE_LENGTH];
	//			fgets(IPAddress, LINE_LENGTH, fp);
	//			struct in_addr inp;
	//			if (inet_aton(IPAddress, &inp) < 0) {
	//				mlogf(ALWAYS, "read wrong IP format of Interface %s \n",
	//						options->if_names[i]);
	//				exit(1);
	//			}
	//			if_devices[i].IPv4address = ntohl((uint32_t) inp.s_addr);
	//			mlogf(INFO, "Device %s has IP %s \n", options->if_names[i], htoa(
	//					if_devices[i].IPv4address));
	//			pclose(fp);

}

void open_socket_inet(device_dev_t* if_device, options_t *options) {
	mlogf(ALWAYS, "open_socket_inet():not yet implemented!\n");
}

void open_socket_unix(device_dev_t* if_device, options_t *options) {
	struct sockaddr_un socket_address;
	int socket_addressLength = 0;

	// create a socket to work with
	if_device->device_handle.socket = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (0 > if_device->device_handle.socket) {
		perror("socket: create");
		exit(1);
	}

	// create socket address
	socket_address.sun_family = AF_UNIX;
	strcpy(socket_address.sun_path, if_device->device_name);
	socket_addressLength = SUN_LEN(&socket_address);

	// connect the socket to the destination
	if (0 > connect(if_device->device_handle.socket,
			(__CONST_SOCKADDR_ARG) &socket_address, socket_addressLength)) {
		perror("socket: connect");
		exit(2);
	}

}

void open_device(device_dev_t* if_device, options_t *options) {
	// parameter check
	if (NULL == if_device || NULL == options) {
		mlogf(ALWAYS, "Parameter are NULL!\n");
		return;
	}

	switch (if_device->device_type) {
	// file as interface to listen
	case TYPE_FILE:
		mlogf(ALWAYS, "open_file(): not yet implemented!\n");
		break;

	case TYPE_PCAP_FILE:
		open_pcap_file(if_device, options);
		break;

	case TYPE_PCAP:
		open_pcap(if_device, options);
		break;

	case TYPE_SOCKET_INET:
		mlogf(ALWAYS, "open_socket_inet():not yet implemented!\n");
		//open_socket_inet(if_device, options);
		break;

	case TYPE_SOCKET_UNIX:
		open_socket_unix(if_device, options);
		break;

	case TYPE_UNKNOWN:
	default:
		mlogf(ALWAYS, "not yet implemented!\n");
		break;
	}

	/* set initial export time to 'now' */
	gettimeofday(&(if_device->last_export_time), NULL);

	return;
}

void init_libipfix() {
	if (ipfix_init() < 0) {
		mlogf(ALWAYS, "cannot init ipfix module: %s\n", strerror(errno));

	}
	if (ipfix_add_vendor_information_elements(ipfix_ft_fokus) < 0) {
		fprintf(stderr, "cannot add FOKUS IEs: %s\n", strerror(errno));
		exit(1);
	}
}


void open_libipfix(device_dev_t *if_device, options_t *options) {
	// set initial export packe count
	if_device->export_packet_count = 0;

	// use observationDomainID if explicitely given via
	// cmd line, else use interface IPv4address as oid
	// todo: alternative oID instead of IP address --> !!different device types!!
	uint32_t odid = (options->observationDomainID != 0)
					? options->observationDomainID
					: if_device->IPv4address;

	if( options->use_oid_first_interface ){
		odid = if_devices[0].IPv4address;
	}

	if (ipfix_open(&(if_device->ipfixhandle), odid, IPFIX_VERSION) < 0) {
		mlogf(ALWAYS, "ipfix_open() failed: %s\n", strerror(errno));

	}
	if (ipfix_add_collector(if_device->ipfixhandle,
			options->collectorIP, options->collectorPort, IPFIX_PROTO_TCP)
			< 0) {
		LOGGER_error("ipfix_add_collector(%s,%d) failed: %s\n",
				options->collectorIP, options->collectorPort, strerror(
						errno));
	}


	// create templates
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_min, export_fields_min) < 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_ts_ttl,
			export_fields_ts_ttl_proto) < 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_interface_stats, export_fields_interface_stats)
			< 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_probe_stats, export_fields_probe_stats) < 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_sync, export_fields_sync) < 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
}


//void handlePacket( packet_data_t* packet, device_dev_t* device )
//{
//	int i = 0; // loop counter
//
//	// DEBUG output
//	for( i = 0; i < packet->capture_length; ++i) {
//		fprintf(stderr, "%02X ", packet->packet[i]);
//	}
//	fprintf(stderr, "\n");
//
//	// selection of viable fields of the packet - depend on the selection function choosen
//	copiedbytes = options.selection_function(packet, export_data);
//
//	if (0 == copiedbytes) {
//		mlogf(ALWAYS, "Warning: packet does not contain Selection (%d)\n",
//				copiedbytes);
//		// todo: ?alternative selection function
//		// todo: ?for the whole configuration
//		// todo: ????drop????
//		//exit(1);
//	}
//
//	// hash the chosen packet data
//	hash_result = options.hash_function(export_data.buffer.ptr
//									, export_data.buffer.length);
//
//	// hash result must be in the chosen selection range to count
//	if ((options.sel_range_min < hash_result) && (options.sel_range_max
//			> hash_result)) {
//		if_device->export_packet_count++;
//
//		int pktid = 0;
//		if (options.hashAsPacketID == 1) { // in case we want to use the hashID as packet ID
//			pktid = hash_result;
//		} else {
//			pktid = options.pktid_function(if_device->outbuffer, copiedbytes);
//		}
//
//
//
//	return;
//}



void handle_packet(u_char *user_args, const struct pcap_pkthdr *header, const u_char * packet)
{
	device_dev_t* if_device = (device_dev_t*) user_args;
	//	int16_t headerOffset[4];
	uint8_t layers[4] = { 0 };
	uint32_t hash_result;
	uint32_t copiedbytes;
	uint8_t ttl;
	uint64_t timestamp;

	LOGGER_trace("handle packet");

	if_device->sampling_delta_count++;
	if_device->totalpacketcount++;

	if( INFO <= mlog_vlevel ) {
		int i = 0;
		for (i = 0; i < header->caplen; ++i) {
			mlogf(INFO, "%02x ", packet[i]);
			//fprintf(stderr, "%c", packet[i]);
		}
		mlogf(INFO, "\n");
	}

	// selection of viable fields of the packet - depend on the selection function choosen
	copiedbytes = g_options.selection_function(packet, header->caplen,
			if_device->outbuffer, if_device->outbufferLength,
			if_device->offset, layers);

	ttl = getTTL(packet, header->caplen, if_device->offset[L_NET],
			layers[L_NET]);

	if (0 == copiedbytes) {

		mlogf(WARNING, "Warning: packet does not contain Selection\n");
		// todo: ?alternative selection function
		// todo: ?for the whole configuration
		// todo: ????drop????
		return;
	}
	//	else {
	//		mlogf( WARNING, "Warnig: packet contain Selection (%d)\n", copiedbytes);
	//	}

	// hash the chosen packet data
	hash_result = g_options.hash_function(if_device->outbuffer, copiedbytes);
	mlogf( INFO, "hash result: 0x%04X\n", hash_result );

	// hash result must be in the chosen selection range to count
	if ((g_options.sel_range_min < hash_result)
			&& (g_options.sel_range_max > hash_result))
	{
		if_device->export_packet_count++;
		if_device->sampling_size++;

		// bypassing export if disabled by cmd line
		if (g_options.export_pktid_interval <= 0) {
			return;
		}

		int pktid = 0;
		// in case we want to use the hashID as packet ID
		if (g_options.hashAsPacketID == 1) {
			pktid = hash_result;
		} else {
			pktid = g_options.pktid_function(if_device->outbuffer, copiedbytes);
		}

		timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
				+ (uint64_t) header->ts.tv_usec;

		switch (g_options.templateID) {
		case MINT_ID: {
			void* fields[] = { &timestamp, &hash_result, &ttl };
			uint16_t lengths[] = { 8, 4, 1 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtemplate, 3, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		case TS_ID: {
			void* fields[] = { &timestamp, &hash_result };
			uint16_t lengths[] = { 8, 4 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtemplate, 2, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		case TS_TTL_PROTO_ID: {
			uint16_t length;

			if (layers[L_NET] == N_IP) {
				length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 2])));
			} else if (layers[L_NET] == N_IP6) {
				length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 4])));
			} else {
				mlogf(ALWAYS, "cannot parse packet length \n");
				length = 0;
			}

			void* fields[] = { &timestamp, &hash_result, &ttl, &length, &layers[L_TRANS], &layers[L_NET] };
			uint16_t lengths[6] = { 8, 4, 1, 2, 1, 1 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtemplate, 6, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		default:
			break;
		} // switch (options.templateID)

		// flush ipfix storage if max packetcount is reached
		if (if_device->export_packet_count >= g_options.export_packet_count) {
			export_flush_device( if_device );
		}

	} // if((options.sel_range_min < hash_result) && (options.sel_range_max > hash_result))
	else {
		mlogf(INFO, "INFO: drop packet; hash not in selection range\n");
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

void setNONBlocking( device_dev_t* pDevice )
{
	switch (pDevice->device_type) {
	case TYPE_PCAP_FILE:
	case TYPE_PCAP:
		if (pcap_setnonblock(pDevice->device_handle.pcap, 1,
				errbuf) < 0) {
			mlogf(ALWAYS, "pcap_setnonblock: %s: %s"
						, pDevice->device_name, errbuf);
		}
		break;

	case TYPE_SOCKET_INET:
	case TYPE_SOCKET_UNIX: {
		int flags = 0;
		if ((flags = fcntl(pDevice->device_handle.socket, F_GETFL, 0)) < 0) {
			// todo: handle error
			mlogf(ALWAYS, "fcntl (F_GETFL) fails\n");
		}

		if (fcntl(pDevice->device_handle.socket, F_SETFL, flags | O_NONBLOCK) < 0) {
			// todo: handle error
			mlogf(ALWAYS, "fcntl (F_SETFL - _NONBLOCK) fails\n");
		}

		break;
	}

	default:
		break;
	}
}

void capture_loop(device_dev_t* if_devices, options_t *options)
{
	int i = 0;
	int n = 0, err = 0, status = 0;
	int max_packet_count = -1; // infinity
	fd_set fds;
	FD_ZERO(&fds);

	// break if there are no interfaces to observe - should not happen here
	// handled before
	if (0 == options->number_interfaces) return;

	// todo: for different interface types
//	if (1 == options->number_interfaces) {
//		switch (if_devices[0].device_type) {
//		case TYPE_PCAP_FILE:
//		case TYPE_PCAP:
//			if (0 > pcap_loop(if_devices[0].device_handle.pcap, -1,
//					handle_packet, (u_char*) &if_devices[0])) {
//				mlogf(ALWAYS, "pcap_loop error: %s\n", pcap_geterr(
//						if_devices[0].device_handle.pcap));
//
//			}
//			break;
//
//		case TYPE_SOCKET_UNIX:
//			if (0 > socket_dispatch(if_devices[0].device_handle.socket, -1,
//					handle_packet, (u_char*) &if_devices[0])) {
//				mlogf(ALWAYS, "socket_loop error: \n");
//			}
//			break;
//
//		default:
//			break;
//		} //switch
//		return;
//	}

	// setup select handler if there are more than one devices to capture
	// set devices in NONBlocking mode
	if (1 < options->number_interfaces) {
		// Thanks to Guy Thornley http://www.mail-archive.com/tcpdump-workers@sandelman.ottawa.on.ca/msg03366.html

		// set all devices in non-blocking mode;
		// 'pcap_loop' and 'pcap_next' will not work --> use pcap_dispatch instead
		for (i = 0; i < options->number_interfaces; i++) {
			setNONBlocking( &if_devices[i] );
		}

		// setup file descriptors for select
		for (i = 0; i < options->number_interfaces; i++) {
			switch (if_devices[0].device_type) {
			case TYPE_testtype:
			case TYPE_PCAP_FILE:
			case TYPE_PCAP:
				FD_SET(pcap_fileno(if_devices[i].device_handle.pcap), &fds);
				break;

			case TYPE_SOCKET_INET:
			case TYPE_SOCKET_UNIX:
				FD_SET(if_devices[i].device_handle.socket, &fds);
				break;

			default:
				break;
			}
		}
		// to fairly balance between devices
		max_packet_count = 10;
	}

	// start processing
	do {
		//fprintf(stderr, "Loop 1\n");
		// block processing until data are available at any devices
		// or any error happens, or interrupts arrive
		if (1 < options->number_interfaces)
		{
			err = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
			if (err < 0) {
				if (errno == EINTR) {
					mlogf(INFO, "select interrupted by interrupt\n");
					continue;
				}
				else { /* err < 0 but not due to interrupt */
					mlogf(ALWAYS, "select: %s", strerror(errno));
					break;
				}
			}
		}

		/* Attempts to fairly balance between all devices with outstanding packets */
		do {
			//fprintf(stderr, "Loop 2\n");
			for (i = 0, n = 0
				; i < options->number_interfaces && 0 <= status // break if negative -> error
				; ++i)
			{
				switch (if_devices[i].device_type) {
				case TYPE_testtype:
				case TYPE_PCAP_FILE:
				case TYPE_PCAP:
					status = pcap_dispatch( if_devices[i].device_handle.pcap
										  , max_packet_count
										  , handle_packet
										  , (u_char*) &if_devices[i]);
					break;

				case TYPE_SOCKET_INET:
				case TYPE_SOCKET_UNIX:
					status = socket_dispatch( if_devices[0].device_handle.socket
										, max_packet_count
										, handle_packet
										, (u_char*) &if_devices[i]);
					break;

				default:
					break;
				}

				//  break for-loop if no device has data
				// wait at select
				if (status > 0)
					n++;
			} // for (each device)
		}
		// todo: is it necessary to loop here; why not just using select
		while (0 <= status && 0 < n);
	} while (0 <= status);

	mlogf(ALWAYS, "Error DeviceNo %d %s: pcap_loop: %s\n"
				, i
				, if_devices[i].device_name
				, pcap_geterr(if_devices[i].device_handle.pcap));

	return;
}

/*-----------------------------------------------------------------------------
 MAIN
 -----------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {
	int i;
	// initializing custom logger
	logger_init(LOGGER_LEVEL_WARN);

	// set defaults options
	options_set_defaults(&g_options);
	mlogf(INFO, "set_defaults() okay \n");

	// parse commandline; set global parameter options
	parse_cmdline(argc, argv);
	mlogf(INFO, "parse_cmdline() okay \n");

	logger_setlevel(g_options.verbosity);

	if (g_options.number_interfaces != 0) {
		// allocate memory for outbuffer; depend on cmd line options
		// just for the real amount of interfaces used
		for (i = 0; i < g_options.number_interfaces; ++i) {
			if_devices[i].outbuffer = calloc(g_options.snapLength, sizeof(uint8_t));
		}

		// init ipfix module
		init_libipfix();

		// open pcap interfaces with filter
		for (i = 0; i < g_options.number_interfaces; ++i) {
			open_device(&if_devices[i], &g_options);
		}
		mlogf(INFO, "open_device() okay (%d times) \n", i);

		// setup ipfix_exporter for each device
		for (i = 0; i < g_options.number_interfaces; ++i) {
			open_libipfix(&if_devices[i], &g_options);
		}
		mlogf(INFO, "open_ipfix_export() okay (%d times) \n", i);

//	// setup the signal handler
//	signal_setup();
//
//	// run capture_loop until program termination
//	capture_loop(if_devices, &options);

		/* ---- main event loop  ---- */
		event_loop(); // todo: refactoring
		// init event-loop
		// todo: loop = init_event_loop();
		// register export callback
		// todo: event_register_callback( loop, callback[] );
		// start event-loop
		// todo: start_event_loop( loop );

		/* -- normal shutdown --  */
		impd4e_shutdown();
		LOGGER_info("bye.");
	}
	else {
		print_help();
		exit(-1);
	}

	exit(0);
}

