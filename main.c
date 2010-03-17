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
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "templates.h"
#include "main.h"
#include "hash.h"
#include "mlog.h"
#include "ipfix.h"

// globals

#define LINE_LENGTH 80

char errbuf[PCAP_ERRBUF_SIZE];
options_t options;
pcap_dev_t *pcap_devices;
int alarmmm = 0;
int isFlushingFlag = 0; /* true during time in which main is invoking ipfix flush */

void print_help() {
	printf(
			"impd4e - a probe based on lib_pcap which applies hash-based selection and exports packetIDs via IPFIX to a collector"
				"\n"
				""
				"Available Parameters i:I:o:r:t:f:p:m:M:hs:F:c:P:C:v");
	printf(
			" \n \n"
				"-i <interface>  Interface(s) to listen on (can be used multiple times)\n"
				" \n"
				"-I <export interval> in seconds - (packetIDs are exported at least once during this interval)\n"
				" \n"
				"-o <observation domain id> - identification of the interface in the IPFXI Header\n"
				" \n"
				"-r <sampling ratio> in %% (double)\n"
				" \n"
				"-t <template> either \"min\" or \"lp\"\n"
				" \n"
				"-f <bpf> Berkley Packet Filter expression (e.g. tcp udp icmp)"
				" \n"
				"-m <minimum selection range> integer - do not use in conjunction with -r \n"
				" \n"
				"-M <maximum selection range> integer - do not use in conjunction with -r \n"
				" \n"
				"-h print this help \n"
				" \n"
				"-s <selection function> which parts of the header used for hashing either \"IP+TP\", \"IP\", \"REC8\", \"PACKET\" \n"
				" \n"
				"-F <hash_function> hash function to use \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\"\n"
				" \n"
				"-c <export_packet_count> size of export buffer after which packets are flushed (per device)\n"
				" \n"
				"-p <hash_function> use different hash_function for packetID generation \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\" \n  "
				" \n"
				"-P <CollectorPort> \n"
				" \n"
				"-C <CollectorIP> \n"
				" \n"
				"-v verbose-level - can be used multiple times to increase output");
}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
	long msec;
	msec = (finishtime->tv_sec - starttime->tv_sec) * 1000;
	msec += (finishtime->tv_usec - starttime->tv_usec) / 1000;
	return msec;
}

void flush_interfaces() {
	int j;
	struct timeval now;

	alarmmm = 0;
	gettimeofday(&now, NULL);

	mlogf(INFO, "select interrupted by interrupt == alarm \n");

	for (j = 0; j < options.number_interfaces; j++) {
		if (timevaldiff(&(pcap_devices[j].last_export_time), &now)
				> options.export_interval * 1000) {
			ipfix_export_flush(pcap_devices[j].ipfixhandle);
			pcap_devices[j].export_packet_count = 0;
			pcap_devices[j].last_export_time = now;
		}
	}
}

/* the signal handler for SIGINT == Ctrl-C --> shutdown program */
void catch_sigint(int sig_num) {
	int i;
	for (i = 0; i < options.number_interfaces; i++) {
		ipfix_export_flush(pcap_devices[i].ipfixhandle);
		ipfix_close(pcap_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	exit(0);
}

void catch_alarm(int sig_num) {

	alarmmm = 1;
	printf("caught alarm \n");
	if (options.number_interfaces == 1) {

		if ( isFlushingFlag == 0 ) {  /* skip flush if main is currently doing it */
			flush_interfaces();
			printf("interfaces flushed \n");
		}

	} else {
		/* flush_interfaces in case of multiple interfaces is handled directly run_pcap_loop */
	}
	signal(SIGALRM, catch_alarm);

}
void signal_setup() {
	printf("signal_setup start \n");
	struct itimerval tv;
	if (signal(SIGINT, catch_sigint) == SIG_ERR) {
		perror("signal: \n");
	}

	/* setup the signal handler for alarm timer */
	if (signal(SIGALRM, catch_alarm) == SIG_ERR) {
		perror("signal: \n");
	}

	/* an internal interval of options.export_interval / 2 results in an export at least every optarg seconds (per listened interface) ; exports will happen more often in case
	 *  of high packet rates.
	 */

	tv.it_value.tv_sec = options.export_interval / 2;
	tv.it_value.tv_usec = (options.export_interval % 2) * 500;
	tv.it_interval = tv.it_value;

	if (setitimer(ITIMER_REAL, &tv, NULL) != 0) {
		perror("setitimer: \n");
	}
	printf("signal_setup_done \n");

}

void set_defaults(options_t *options) {
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
			mlogf(INFO, "using %s as hashFunction \n", hashfunctions[k].hstring);

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
	char par[] = "i:I:o:r:t:f:m:M:hs:F:c:P:C:v:R:";
	char *endptr;
	errno = 0;
	double sampling_ratio;
	// options->basedir =  strdup(argv[0]);
	//	char *pos = strrchr( options->basedir, '/' );
	//	pos[1] = 0;


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
		default:
			printf("unknown parameter: %d \n", c);
			break;
		}

	}

}

char *htoa(uint32_t ipaddr) {
	static char addrstr[16]; /* ugh */
	uint8_t *p = (uint8_t*) &ipaddr;
	sprintf(addrstr, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	return addrstr;
}

void determineLinkType(pcap_dev_t *pcap_device) {

	pcap_device->link_type = pcap_datalink(pcap_device->pcap_handle);
	switch (pcap_device->link_type) {
	case DLT_EN10MB:
		pcap_device->offset[L_NET] = 14;
		mlogf(INFO, "dltype: DLT_EN10M \n");
		break;
	case DLT_ATM_RFC1483:
		pcap_device->offset[L_NET] = 8;
		mlogf(INFO, "dltype: DLT_ATM_RFC1483\n");
		break;
	case DLT_LINUX_SLL:
		pcap_device->offset[L_NET] = 16;
		mlogf(INFO, "dltype: DLT_LINUX_SLL\n");
		break;
	case DLT_RAW:
		pcap_device->offset[L_NET] = 0;
		mlogf(INFO, "dltype: DLT_RAW\n");
		break;
	default:
		mlogf(ALWAYS, "Link Type (%d) not supported - default to DLT_RAW \n",
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

void open_pcap(pcap_dev_t *pcap_devices, options_t *options) {

	if (options->file != NULL) {

		/* in case of file input */

		pcap_devices[0].pcap_handle = pcap_open_offline(options->file, errbuf);
		if (pcap_devices[0].pcap_handle == NULL) {
			printf("%s \n", errbuf);
		}
		determineLinkType(&pcap_devices[0]);
		setFilter(&pcap_devices[0]);

	} else {

		int i;
		int fd;
		struct ifreq ifr;
		fd = socket(AF_INET, SOCK_DGRAM, 0);

		/* I want to get an IPv4 IP address */
		ifr.ifr_addr.sa_family = AF_INET;

		for (i = 0; i < (options->number_interfaces); i++) {
			pcap_devices[i].pcap_handle = pcap_open_live(options->if_names[i],
					options->snapLength, 1, 1000, errbuf);
			if (pcap_devices[i].pcap_handle == NULL) {
				printf("%s \n", errbuf);
				continue;
			}
			// if (pcap_lookupnet(options->if_names[i],
			//		&(pcap_devices[i].IPv4address), &(pcap_devices[i].mask), errbuf)
			//		< 0) {
			//	printf("could not determine netmask and Ip-Adress of device %s \n",
			//			options->if_names[i]);
			// }

			/* I want IP address attached to device */
			//		strncpy(ifr.ifr_name, options->if_names[i], IFNAMSIZ-1);
			//		ioctl(fd, SIOCGIFADDR, &ifr);
			//
			//		pcap_devices[i].IPv4address = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
			//
			//		 /* display result */
			//
			//		mlogf(ALWAYS, "Device %s has IP %s \n", options->if_names[i], htoa(pcap_devices[i].IPv4address));


			// dirty IP read hack - but socket problem with embedded interfaces

			FILE *fp;
			char *script = "getIPAddress.sh ";
			char *cmdLine;
			cmdLine = (char *) malloc((strlen(script) + strlen(
					options->if_names[i]) + 1) * sizeof(char));
			strcpy(cmdLine, script);
			strcat(cmdLine, options->if_names[i]);
			fp = popen(cmdLine, "r");

			char IPAddress[LINE_LENGTH];
			fgets(IPAddress, LINE_LENGTH, fp);
			struct in_addr inp;
			if (inet_aton(IPAddress, &inp) < 0) {
				mlogf(ALWAYS, "read wrong IP format of Interface %s \n",
						options->if_names[i]);
				exit(1);
			}
			pcap_devices[i].IPv4address = ntohl((uint32_t) inp.s_addr);
			mlogf(INFO, "Device %s has IP %s \n", options->if_names[i], htoa(
					pcap_devices[i].IPv4address));
			pclose(fp);

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
    printf("in open_ipfix\n");
	for (i = 0; i < (options->number_interfaces); i++) {
        printf("in loop: %i\n", i);
		pcap_devices[i].export_packet_count = 0;

		/* use observationDomainID if explicitely given via cmd line, else use interface IPv4address as oid */
		uint32_t
				odid =
						(options->observationDomainID != 0) ? options->observationDomainID
								: pcap_devices[i].IPv4address;
		if (ipfix_open(&(pcap_devices[i].ipfixhandle), odid, IPFIX_VERSION) < 0) {
			mlogf(ALWAYS, "ipfix_open() failed: %s\n", strerror(errno));

		}
        printf("ipfix open\n");
		if (ipfix_add_collector(pcap_devices[i].ipfixhandle,
				options->collectorIP, options->collectorPort, IPFIX_PROTO_TCP)
				< 0) {
			mlogf(ALWAYS, "ipfix_add_collector(%s,%d) failed: %s\n",
					options->collectorIP, options->collectorPort, strerror(
							errno));

		}
        printf("ipfix added collector\n");
		switch (options->templateID) {
		case MINT_ID:
            printf("ipfix pre mint_id\n");
			if (ipfix_make_template(pcap_devices[i].ipfixhandle,
					&(pcap_devices[i].ipfixtemplate), export_fields_min, 3) < 0) {
                printf("ipfix pre middle mint_id\n");
				mlogf(ALWAYS, "ipfix_make_template_min() failed: %s\n",
						strerror(errno));
                printf("ipfix post middle mint_id\n");
				exit(1);
			}
            printf("ipfix post mint_id\n");
			break;
		case TS_TTL_PROTO_ID:
            printf("ipfix pre ts_ttl_proto_id\n");
			if (ipfix_make_template(pcap_devices[i].ipfixhandle,
					&(pcap_devices[i].ipfixtemplate),
					export_fields_ts_ttl_proto, 6) < 0) {
                printf("ipfix pre middle ts_ttl_proto_id\n");
				mlogf(ALWAYS,
						"ipfix_make_template_ts_ttl_proto_id() failed: %s\n",
						strerror(errno));
                printf("ipfix post ts_ttl_proto_id\n");
				exit(1);
			}
            printf("ipfix post ts_ttl_proto_id\n");
		default:
            printf("ipfix default break\n");
			break;
		}
        printf("ipfix after switch\n");
	}

}

void handle_packet(u_char *user_args, const struct pcap_pkthdr *header,
		const u_char * packet) {
	pcap_dev_t *pcap_device = (pcap_dev_t*) user_args;
	//	int16_t headerOffset[4];
	uint8_t layers[4];
	uint32_t hash_result;
	uint32_t copiedbytes;
	uint8_t ttl;
	uint64_t timestamp;
	findHeaders(packet, header->caplen, pcap_device->offset, layers, &ttl);
	copiedbytes = pcap_device->options->selection_function(packet,
			header->caplen, pcap_device->outbuffer,
			pcap_device->outbufferLength, pcap_device->offset, layers);

//	for (i = 0; i < copiedbytes; i++) {
//		printf("%x ", pcap_device->outbuffer[i]);
//	}
//	printf("\n");

	hash_result = pcap_device->options->hash_function(pcap_device->outbuffer,
			copiedbytes);

	// is packet selected?

	if ((pcap_device->options->sel_range_min < hash_result)
			&& (pcap_device->options->sel_range_max > hash_result)) {

		int pktid = 0;
		if (options.hashAsPacketID == 1) {
			pktid = hash_result;
		} else {
			pktid = options.pktid_function(pcap_device->outbuffer, copiedbytes);
		}

		switch (pcap_device->options->templateID) {
		case MINT_ID: {
			timestamp = (unsigned long long) header->ts.tv_sec * 1000000ULL
					+ header->ts.tv_usec;
            
            printf("timestamp: %d\n", timestamp);
            printf("sec: %d\n", (unsigned long long) header->ts.tv_sec);
            printf("usec: %d\n", (unsigned long long) header->ts.tv_usec);

			void *fields[] = { &timestamp, &hash_result, &ttl };
			uint16_t lengths[] = { 8, 4, 1 };

			if (ipfix_export_array(pcap_device->ipfixhandle,
					pcap_device->ipfixtemplate, 3, fields, lengths) < 0) {
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
					pcap_device->ipfixtemplate, 6, fields, lengths) < 0) {
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
			ipfix_export_flush(pcap_device->ipfixhandle);
			isFlushingFlag = 0;
			pcap_device->export_packet_count = 0;
			pcap_device->last_export_time = header->ts;
		}

	}

}

void run_pcap_loop(pcap_dev_t *pcap_devices, options_t *options) {
	int i = 0;
	for (i = 0; i < options->number_interfaces; ++i) {
		pcap_devices[i].options = options;
	}

	if (options->number_interfaces == 0)
		return;

	if (options->number_interfaces == 1) {
		signal_setup();
		if (pcap_loop(pcap_devices[0].pcap_handle, -1, handle_packet,
				(u_char*) &pcap_devices[0]) < 0) {
			mlogf(ALWAYS, "pcap_loop error: %s\n", pcap_geterr(
					pcap_devices[0].pcap_handle));

		}
	} else {

		// Thanks to Guy Thornley http://www.mail-archive.com/tcpdump-workers@sandelman.ottawa.on.ca/msg03366.html


		fd_set fds;
		int n = 0, cnt = -1, err = 0, status = 0, errdev = 0;
		FD_ZERO(&fds);
		for (i = 0; i < options->number_interfaces; i++) {
			if (pcap_setnonblock(pcap_devices[i].pcap_handle, 1, errbuf) < 0) {
				mlogf(ALWAYS, "pcap_setnonblock: %s: %s", options->if_names[i],
						errbuf);
			}
		}
		signal_setup();
		while (cnt != 0 && status >= 0) {
			for (i = 0; i < options->number_interfaces; i++) {
				FD_SET(pcap_fileno(pcap_devices[i].pcap_handle), &fds);
			}
			err = select(FD_SETSIZE, &fds, NULL, NULL, NULL);
			if (err < 0) {
				if (errno == EINTR) {

					if (alarmmm == 1) { /* did we got a timer alarm? */
						flush_interfaces();
						continue;
					} else { /* other interrupt */
						mlogf(ALWAYS,
								"select interrupted by interrupt != alarm");
						continue;
					}
				} else { /* err < 0 but not due to interrupt */
					mlogf(ALWAYS, "select: %s", strerror(errno));
					break;
				}
			}
			/* Attempts to fairly balance between all devices with outstanding packets */
			while (cnt != 0 && status >= 0) {
				for (i = 0, n = 0; i < options->number_interfaces; i++) {
					status = pcap_dispatch(pcap_devices[i].pcap_handle, (cnt
							> 0 && cnt < 10 ? cnt : 10), handle_packet,
							(u_char*) &pcap_devices[i]);
					if (status < 0) {
						errdev = i;
						break;
					}
					if (status > 0) {
						n++;
						if (cnt > 0)
							cnt -= status;
					}
				}
				if (n == 0)
					break;
			}
		}
		mlogf(ALWAYS, "Error DeviceNo %d %s: pcap_loop: %s\n", errdev,
				options->if_names[errdev], pcap_geterr(
						pcap_devices[errdev].pcap_handle));

	}

}

int main(int argc, char *argv[]) {
	int i;

	// set defaults options

	set_defaults(&options);
	printf("set_default_okay \n");
	// parse commandline

	parse_cmdline(&options, argc, argv);
	// allocate memory for pcap handles
	printf("parse_cmdLine_okay \n");

	if (options.number_interfaces != 0) {
		pcap_devices = calloc((int) options.number_interfaces,
				sizeof(pcap_dev_t));
		for (i = 0; i < options.number_interfaces; i++) {
			// pcap_devices[i].pcap_handle = calloc(1, sizeof(pcap_t *));
			// pcap_devices[i].ipfixhandle = calloc(1, sizeof(ipfix_t *));
			// pcap_devices[i].ipfixtemplate = calloc(1,sizeof(ipfix_template_t *));
			pcap_devices[i].outbuffer = calloc(options.snapLength,
					sizeof(uint8_t));
			// pcap_devices[i].options = calloc(1, sizeof(options_t *));
		}


		/* setup the signal handler for Ctrl-C */

		// open pcap interfaces with filter


		open_pcap(pcap_devices, &options);
		printf("open_pcap_okay \n");
		// setup ipfix_exporter for each device

		open_ipfix_export(pcap_devices, &options);
		// run pcap_loop until program termination
		printf("open_ipfix _okay \n");

		run_pcap_loop(pcap_devices, &options);

		// free memory

		free(pcap_devices);

	} else {
		mlogf(ALWAYS,
				"Please specify an interface with -i option e.g. -i eth0 \n");
	}

	return 0;

}

