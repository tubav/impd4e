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
#include <pcap.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "templates.h"
#include "main.h"
#include "hash.h"
#include "mlog.h"
#include "ipfix.h"
#include "ipfix_fields_fokus.h"

// Custom logger
#include "logger.h"
#include <ev.h> // event loop


/*----------------------------------------------------------------------------
  Globals
----------------------------------------------------------------------------- */

/**
 * Event and Signal handling via libev
 */
struct {
	struct ev_loop *loop;
	ev_signal sigint_watcher;
	ev_timer export_timer;
	ev_io *packet_watchers;
} events;


char errbuf[PCAP_ERRBUF_SIZE];
uint64_t old_cc_idle, old_cc_uptime, old_cpu_process_time;
options_t options;
pcap_dev_t *pcap_devices;
ipfix_template_t *resource_template;



int isFlushingFlag = 0; /* true during time in which main is invoking ipfix flush */

/*----------------------------------------------------------------------------
  Prototypes
----------------------------------------------------------------------------- */
static void export_flush();
static void export_timer_cb (EV_P_ ev_timer *w, int revents);
static void packet_watcher_cb(EV_P_ ev_io *w, int revents);
void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header,
		const u_char * packet);


void print_help() {
	printf( "impd4e - a libpcap based measuring probe which uses hash-based packet\n"
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
			"   -I  <export interval>          in seconds - (packetIDs are exported at \n"
			"                                  least once during this interval)\n"
			"   -i  <interface>                Interface(s) to listen on (can be used \n"
			"                                  multiple times)\n"
			"   -M  <maximum selection range>  integer - do not use in conjunction with -r \n"
			"   -m  <minimum selection range>  integer - do not use in conjunction with -r \n"
			"   -n                             export sampling Parameters n and N - \n"
			"                                  sample size and total packet count \n"
			"   -o  <observation domain id>    identification of the interface in\n"
			"                                  the IPFXI Header\n"
			"   -P  <collector port> \n"
			"   -p  <hash function>            use different hash_function for packetID\n"
			"                                  generation \"BOB\", \"OAAT\", \"TWMX\",\n"
			"                                  \"HSIEH\" \n"
			"   -r  <sampling ratio>           in %% (double)\n"
			"   -s  <selection function>       which parts of the header used for hashing\n"
			"                                  either \"IP+TP\", \"IP\", \"REC8\", \"PACKET\" \n"
			"   -t  <template>                 either \"min\" or \"lp\"\n"
			"   -v  verbose-level              can be used multiple times to increase output \n\n");

}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
	long msec;
	msec = (finishtime->tv_sec - starttime->tv_sec) * 1000;
	msec += (finishtime->tv_usec - starttime->tv_usec) / 1000;
	return msec;
}

static void impd4e_shutdown(){
	int i;
	LOGGER_info("Shutting down..");
	for (i = 0; i < options.number_interfaces; i++) {
		ipfix_export_flush(pcap_devices[i].ipfixhandle);
		ipfix_close(pcap_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	free(pcap_devices);

}

/* the signal handler for SIGINT == Ctrl-C --> shutdown program */

/**
 * Call back for SIGINT (Ctrl-C). It breaks all loops
 * and leads to shutdown.
 */
static void sigint_cb (EV_P_ ev_signal *w, int revents){
	LOGGER_info("SIGINT received");
	ev_unloop (events.loop, EVUNLOOP_ALL);

}

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
	options->export_interval = 3; /* seconds */
	options->hashAsPacketID = 1;
	options->file = NULL;
	options->samplingResultExport = false;
	options->export_sysinfo = false;
}

hashFunction parseFunction(char *arg_string, options_t *options) {
	int k;
	int j = 0;
	struct hashfunction {
		char *hstring;
		hashFunction function;
	} hashfunctions[] = { { HASH_FUNCTION_BOB, calcHashValue_BOB }, {
			HASH_FUNCTION_TWMX, calcHashValue_TWMXRSHash }, {
					HASH_FUNCTION_HSIEH, calcHashValue_Hsieh }, { HASH_FUNCTION_OAAT,
							calcHashValue_OAAT } };

	for (k = 0; k < (sizeof(hashfunctions) / sizeof(struct hashfunction)); k++) {
		if (strncasecmp(arg_string, hashfunctions[k].hstring, strlen(
				hashfunctions[k].hstring)) == 0) {
			j = k;
			LOGGER_info("using %s as hashFunction \n", hashfunctions[k].hstring);

		}
	}
	return hashfunctions[j].function;
}

void parseSelFunction(char *arg_string, options_t *options) {
	int k;
	struct selfunction {
		char *hstring;
		selectionFunction selfunction;
	} selfunctions[] = { { HASH_INPUT_REC8, copyFields_Rec }, { HASH_INPUT_IP,
			copyFields_Only_Net },
			{ HASH_INPUT_IPTP, copyFields_U_TCP_and_Net }, { HASH_INPUT_PACKET,
					copyFields_Packet } };

	for (k = 0; k < (sizeof(selfunctions) / sizeof(struct selfunction)); k++) {
		if (strncasecmp(arg_string, selfunctions[k].hstring, strlen(
				selfunctions[k].hstring)) == 0) {
			options->selection_function = selfunctions[k].selfunction;
		}
	}
}

void parseTemplate(char *arg_string, options_t *options) {
	int k;
	struct templateDef {
		char *hstring;
		int templateID;
	} templates[] = { { MIN_NAME, MINT_ID }, { TS_TTL_RROTO_NAME,
			TS_TTL_PROTO_ID }, };

	for (k = 0; k < (sizeof(templates) / sizeof(struct templateDef)); k++) {
		if (strncasecmp(arg_string, templates[k].hstring, strlen(
				templates[k].hstring)) == 0) {
			options->templateID = templates[k].templateID;
		}
	}
}

void parse_cmdline(options_t *options, int argc, char **argv) {

	int c;
	char par[] = "vi:I:o:r:t:f:m:M:hs:F:c:P:C:R:nS";
	char *endptr;
	errno = 0;
	double sampling_ratio;

	options->number_interfaces = 0;

	while ((c = getopt(argc, argv, par)) != -1) {
		switch (c) {
		case 'P':
			if ((options->collectorPort = atoi(optarg)) < 0) {
				mlogf(ALWAYS, "Invalid -p argument!\n");
				exit(1);
			}
			break;
		case 'C':
			strcpy(options->collectorIP, optarg);
			break;
		case 'c':
			options->export_packet_count = atoi(optarg);
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
			options->export_interval = atoi(optarg);
			break;
		case 'o':
			options->observationDomainID = atoi(optarg);
			break;
		case 't':
			parseTemplate(optarg, options);
			break;
		case 'f':
			options->bpf = strdup(optarg);
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
		case 'h':
			print_help();
			exit(0);
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
		case 'v':
			mlog_set_vlevel(options->verbosity++);
			break;
		case 'l':
			options->snapLength = atoi(optarg);
			break;
		case 'r':
			sscanf(optarg, "%lf", &sampling_ratio);

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
			break;
		case 'R':
			options->file = strdup(optarg);
			options->number_interfaces++;
			break;
		case 'n':
			options->samplingResultExport = true;
			break;
		case 'S':
			options->export_sysinfo = true;
			break;
		default:
			printf("unknown parameter: %d \n", c);
			break;
		}

	}

}

char *htoa(uint32_t ipaddr) {
	static char addrstr[16];
	ipaddr = htonl(ipaddr);
	uint8_t *p = (uint8_t*) &ipaddr;
	sprintf(addrstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return addrstr;
}

void determineLinkType(pcap_dev_t *pcap_device) {

	pcap_device->link_type = pcap_datalink(pcap_device->pcap_handle);
	switch (pcap_device->link_type) {
	case DLT_EN10MB:
		pcap_device->offset[L_NET] = 14;
		LOGGER_info( "dltype: DLT_EN10M");
		break;
	case DLT_ATM_RFC1483:
		pcap_device->offset[L_NET] = 8;
		LOGGER_info( "dltype: DLT_ATM_RFC1483");
		break;
	case DLT_LINUX_SLL:
		pcap_device->offset[L_NET] = 16;
		LOGGER_info( "dltype: DLT_LINUX_SLL");
		break;
	case DLT_RAW:
		pcap_device->offset[L_NET] = 0;
		LOGGER_info( "dltype: DLT_RAW");
		break;
	default:
		mlogf(ALWAYS, "Link Type (%d) not supported - default to DLT_RAW",
				pcap_device->link_type);
		pcap_device->offset[L_NET] = 0;
		break;
	}

}

void setFilter(pcap_dev_t *pcap_device) {
	/* apply filter */
	struct bpf_program fp;

	if (options.bpf) {
		if (pcap_compile(pcap_device->pcap_handle, &fp, options.bpf, 0, 0)
				== -1) {
			mlogf(ALWAYS, "Couldn't parse filter %s: %s\n", options.bpf,
					pcap_geterr(pcap_device->pcap_handle));
		}
		if (pcap_setfilter(pcap_device->pcap_handle, &fp) == -1) {
			mlogf(ALWAYS, "Couldn't install filter %s: %s\n", options.bpf,
					pcap_geterr(pcap_device->pcap_handle));
		}
	}

}
/**
 * Open packet capture devices
 */
void open_pcap(pcap_dev_t *pcap_devices, options_t *options) {

	if (options->file != NULL) {

		/* in case of file input */

		pcap_devices[0].pcap_handle = pcap_open_offline(options->file, errbuf);
		if (pcap_devices[0].pcap_handle == NULL) {
			fprintf(stderr, "%s \n", errbuf);
		}
		determineLinkType(&pcap_devices[0]);
		setFilter(&pcap_devices[0]);

	} else {

		int i;
		int fd;
		struct ifreq ifr;
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd == -1) {
			perror("cannot create socket: ");
			exit(1);
		}

		/* I want to get an IPv4 IP address */
		ifr.ifr_addr.sa_family = AF_INET;

		for (i = 0; i < (options->number_interfaces); i++) {
			pcap_devices[i].pcap_handle = pcap_open_live(options->if_names[i],
					options->snapLength, 1, 1000, errbuf);
			pcap_devices[i].ifname=options->if_names[i];
			if (pcap_devices[i].pcap_handle == NULL) {
				fprintf(stderr, "%s \n", errbuf);
				exit(1);
			}
			// if (pcap_lookupnet(options->if_names[i],
			//		&(pcap_devices[i].IPv4address), &(pcap_devices[i].mask), errbuf)
			//		< 0) {
			//	printf("could not determine netmask and Ip-Adrdess of device %s \n",
			//			options->if_names[i]);
			// }

			/* I want IP address attached to device */

			strncpy(ifr.ifr_name, options->if_names[i], IFNAMSIZ - 1);
			ioctl(fd, SIOCGIFADDR, &ifr);

			pcap_devices[i].IPv4address = ntohl(
					((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr);

			/* display result */
			LOGGER_info("Device %s has IP %s", options->if_names[i], htoa(
					pcap_devices[i].IPv4address));

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
			//			pcap_devices[i].IPv4address = ntohl((uint32_t) inp.s_addr);
			//			LOGGER_info( "Device %s has IP %s \n", options->if_names[i], htoa(
			//					pcap_devices[i].IPv4address));
			//			pclose(fp);

			determineLinkType(&pcap_devices[i]);
			setFilter(&pcap_devices[i]);

			/* set initial export time to 'now' */
			gettimeofday(&pcap_devices[i].last_export_time, NULL);
		}
		close(fd);
	}
}

void open_ipfix_export(pcap_dev_t *pcap_devices, options_t *options) {
	int i;

	if (ipfix_init() < 0) {
		mlogf(ALWAYS, "cannot init ipfix module: %s\n", strerror(errno));

	}

	if (ipfix_add_vendor_information_elements(ipfix_ft_fokus) < 0) {
		fprintf(stderr, "cannot add FOKUS IEs: %s\n", strerror(errno));
		exit(1);
	}

	// printf("in open_ipfix\n");
	for (i = 0; i < (options->number_interfaces); i++) {
		// printf("in loop: %i\n", i);

		pcap_devices[i].export_packet_count = 0;

		/* use observationDomainID if explicitely given via cmd line, else use interface IPv4address as oid */
		uint32_t
		odid =
				(options->observationDomainID != 0) ? options->observationDomainID
						: pcap_devices[i].IPv4address;
		if (ipfix_open(&(pcap_devices[i].ipfixhandle), odid, IPFIX_VERSION) < 0) {
			mlogf(ALWAYS, "ipfix_open() failed: %s\n", strerror(errno));

		}
		// printf("ipfix open\n");
		if (ipfix_add_collector(pcap_devices[i].ipfixhandle,
				options->collectorIP, options->collectorPort, IPFIX_PROTO_TCP)
				< 0) {
			mlogf(ALWAYS, "ipfix_add_collector(%s,%d) failed: %s\n",
					options->collectorIP, options->collectorPort, strerror(
							errno));

		}

		// printf("ipfix pre mint_id\n");
		if (ipfix_make_template(pcap_devices[i].ipfixhandle,
				&(pcap_devices[i].ipfixtemplate_min), export_fields_min, 3) < 0) {
			// printf("ipfix pre middle mint_id\n");
			mlogf(ALWAYS, "ipfix_make_template_min() failed: %s\n",
					strerror(errno));
			// printf("ipfix post middle mint_id\n");
			exit(1);
		}

//		export_flush();

		//		if (ipfix_make_template(pcap_devices[i].ipfixhandle,
//				&(pcap_devices[i].ipfixtemplate),
//				export_fields_ts_ttl_proto, 6) < 0) {
//			// printf("ipfix pre middle ts_ttl_proto_id\n");
//			mlogf(ALWAYS,
//					"ipfix_make_template_ts_ttl_proto_id() failed: %s\n",
//					strerror(errno));
//			// printf("ipfix post ts_ttl_proto_id\n");
//			exit(1);
//		}
//		if (ipfix_make_template(pcap_devices[i].ipfixhandle,
//				&(pcap_devices[i].sampling_export_template),
//				export_fields_sampling, 2) < 0) {
//			mlogf(
//					ALWAYS,
//					"ipfix_make_template_export_sampling_parameters() failed: %s\n",
//					strerror(errno));
//		}


	}

}

void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header,
		const u_char * packet) {
	pcap_dev_t *pcap_device = (pcap_dev_t*) user_args;
	//	int16_t headerOffset[4];
	uint8_t layers[4];
	uint32_t hash_result;
	uint32_t copiedbytes;
	uint8_t ttl;
	uint64_t timestamp;

	LOGGER_trace("handle packet");

	pcap_device->totalpacketcount++;

	findHeaders(packet, header->caplen, pcap_device->offset, layers, &ttl);

	//	LOGGER_debug("addr: %d",pcap_device->options==NULL );
	//	return;
	copiedbytes = pcap_device->options->selection_function(packet,
			header->caplen, pcap_device->outbuffer,
			pcap_device->outbufferLength, pcap_device->offset, layers);


	hash_result = pcap_device->options->hash_function(pcap_device->outbuffer,
			copiedbytes);
	// is packet selected?

	if ((pcap_device->options->sel_range_min < hash_result)
			&& (pcap_device->options->sel_range_max > hash_result)) {

		int pktid = 0;
		if (options.hashAsPacketID == 1) { // in case we want to use the hashID as packet ID
			pktid = hash_result;
		} else {
			pktid = options.pktid_function(pcap_device->outbuffer, copiedbytes);
		}

		switch (pcap_device->options->templateID) {
		case MINT_ID: {
			timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
					+ (uint64_t) header->ts.tv_usec;
			void *fields[] = { &timestamp, &hash_result, &ttl };
			uint16_t lengths[] = { 8, 4, 1 };

			if (ipfix_export_array(pcap_device->ipfixhandle,
					pcap_device->ipfixtemplate_min, 3, fields, lengths) < 0) {
				fprintf(stderr, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}
		case TS_TTL_PROTO_ID: {
			uint16_t length;
			timestamp = (unsigned long long) header->ts.tv_sec * 1000000ULL
					+ header->ts.tv_usec;
			if (layers[L_NET] == N_IP) {
				length
				= ntohs(
						*((uint16_t*) (&packet[pcap_device->offset[L_NET]
						                                           + 2])));
			} else if (layers[L_NET] == N_IP6) {
				length
				= ntohs(
						*((uint16_t*) (&packet[pcap_device->offset[L_NET]
						                                           + 4])));
			} else {
				mlogf(ALWAYS, "cannot parse packet length \n");
				length = 0;
			}

			void *fields[] = { &timestamp, &hash_result, &ttl, &length,
					&layers[L_TRANS], &layers[L_NET] };
			uint16_t lengths[6] = { 8, 4, 1, 2, 1, 1 };

			if (ipfix_export_array(pcap_device->ipfixhandle,
					pcap_device->ipfixtemplate_ttl, 6, fields, lengths) < 0) {
				fprintf(stderr, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}
		default:
			break;
		}

		pcap_device->export_packet_count++;
		if (pcap_device->export_packet_count
				>= pcap_device->options->export_packet_count) {
			isFlushingFlag = 1;


			/*
			if ((options.resourceConsumptionExport == true) && (pcap_device
					== &pcap_devices[0])) {
				printf("export triggered by packet count \n");
				export_resource_consumption(pcap_device);
			}
			 */
			ipfix_export_flush(pcap_device->ipfixhandle);
			isFlushingFlag = 0;
			pcap_device->export_packet_count = 0;
			pcap_device->totalpacketcount = 0;
			pcap_device->last_export_time = header->ts;
		}

	}

}

static void export_flush(){
	int i;
	LOGGER_trace("export_flush");
	for (i = 0; i < options.number_interfaces; i++) {
		if( ipfix_export_flush(pcap_devices[i].ipfixhandle) < 0 ){
			LOGGER_error("Could not export IPFIX, device: %d", i);
		}
	}
}

static void export_timer_cb (EV_P_ ev_timer *w, int revents){
	LOGGER_trace("export timer tick");
	export_flush();
}



/**
 * Called whenever a new packet is available
 */
static void packet_watcher_cb(EV_P_ ev_io *w, int revents){
	LOGGER_trace("packet");
	// retrieve respective device a new packet was seen
	pcap_dev_t *pcap_dev_ptr = (pcap_dev_t *) w->data;

	// dispatch packet callback
	if( pcap_dispatch(pcap_dev_ptr->pcap_handle,
			PCAP_DISPATCH_PACKET_COUNT ,
			packet_pcap_cb,
			(u_char*) pcap_dev_ptr)< 0 ){
			LOGGER_error( "Error DeviceNo  %s: %s\n",pcap_dev_ptr->ifname,
					pcap_geterr( pcap_dev_ptr->pcap_handle)  );
	}

}

static void event_setup_pcapdev(){
	int i;
	pcap_dev_t * pcap_dev_ptr;
	for (i = 0; i < options.number_interfaces; i++) {
		LOGGER_debug("Setting up interface: %s",options.if_names[i]);

		pcap_dev_ptr = &pcap_devices[i];
		// TODO review
		pcap_dev_ptr->options = &options;

		if (pcap_setnonblock((*pcap_dev_ptr).pcap_handle, 1, errbuf) < 0) {
			LOGGER_error( "pcap_setnonblock: %s: %s", options.if_names[i],
					errbuf);
		}
		// storing a reference of packet device to
		// be passed via watcher on a packet event
		events.packet_watchers[i].data = (pcap_dev_t *) pcap_dev_ptr;
		ev_io_init( &events.packet_watchers[i],
				packet_watcher_cb,
				pcap_fileno((*pcap_dev_ptr).pcap_handle),
				EV_READ);
		ev_io_start(events.loop, &events.packet_watchers[i]);
	}
}


static void event_loop(){
	//	struct ev_loop *loop = ev_default_loop (EVLOOP_ONESHOT);
	events.loop = ev_default_loop (0);
	if(!events.loop){
		LOGGER_fatal("Could not initialize loop!");
		exit(EXIT_FAILURE);
	}
	LOGGER_info("event_loop()");
	/*--- Setting up loop ---*/
	// sigint
	ev_signal_init (&events.sigint_watcher, sigint_cb, SIGINT);
	ev_signal_start (events.loop, &events.sigint_watcher);

	// export timer
	ev_init (&events.export_timer, export_timer_cb );
	events.export_timer.repeat  = 3.0;
	ev_timer_again (events.loop, &events.export_timer);

	// packet watcher
	event_setup_pcapdev();

	// Loop: to exit you unloop
	ev_loop(events.loop,0);
}

int main(int argc, char *argv[]) {
	int i;
	// initializing custom logger
	logger_init(LOGGER_LEVEL_DEBUG);
	LOGGER_info("== impd4e ==");

	// set defaults options
	options_set_defaults(&options);
	// parse commandline
	parse_cmdline(&options, argc, argv);

	logger_setlevel(options.verbosity);

	// --

	// allocate memory for pcap handles

	if (options.number_interfaces != 0) {
		pcap_devices = calloc((int) options.number_interfaces,
				sizeof(pcap_dev_t));
		events.packet_watchers = calloc((int) options.number_interfaces, sizeof(ev_io) );
		for (i = 0; i < options.number_interfaces; i++) {
			pcap_devices[i].outbuffer = calloc(options.snapLength,
					sizeof(uint8_t));
		}

		// open pcap interfaces with filter
		open_pcap(pcap_devices, &options);

		// setup ipfix_exporter for each device
		open_ipfix_export(pcap_devices, &options);


		// -- EVENT LOOP  --
		event_loop();
		// ----------------


		impd4e_shutdown();
		LOGGER_info("bye.");
	} else {
		print_help();
		exit(-1);
	}
	exit(0);

}

