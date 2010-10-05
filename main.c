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
#include <sys/un.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <proc.h>
#include <fcntl.h>

#include "templates.h"
#include "constants.h"
#include "main.h"
#include "hash.h"
#include "mlog.h"
#include "ipfix.h"

// globals

#define LINE_LENGTH 80

char errbuf[PCAP_ERRBUF_SIZE];
uint64_t old_cc_idle;
uint64_t old_cc_uptime;

options_t     options;
device_dev_t  if_devices[MAX_INTERFACES]; // array
export_data_t export_data;

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
			"-i <i,f,p,s,u>:<interface>  Interface(s) to listen on (can be used multiple times (max=%d)\n"
			"\t i - ethernet adapter;             -i i:eth0\n"
			"\t p - pcap file;                    -i p:traffic.pcap\n"
			"\t f - plain text file;              -i f:data.txt\n"
			"\t s - inet socket (AF_INET);        -i s:192.168.0.42:4711\n"
			"\t u - unix domain socket (AF_UNIX); -i u:/tmp/socket.AF_UNIX\n"
			" (default: i:any)"
			" \n"
			"-o <observation domain id> - identification of the interface in the IPFIX Header\n"
			" (default: depend on device)\n\n"
			"-f <bpf> Berkley Packet Filter expression (e.g. tcp udp icmp)\n"
			" (default: not set)\n\n"
			"-m <minimum selection range> integer - do not use in conjunction with -r \n"
			" (default: 0x19999999)\n"
			"-M <maximum selection range> integer - do not use in conjunction with -r \n"
			" (default: 0x33333333)\n"
			"-r <sampling ratio> in %% (double)\n"
			" (default: 10%%)\n"
			" default: (see '-m' and '-M')\n\n"
			"-s <selection function> which parts of the header used for hashing either \"IP+TP\", \"IP\", \"REC8\", \"PACKET\", \"RAWx\", \"SELECT\" \n"
			" (default: IP+TP)\n"
			"-F <hash_function> hash function to use \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\"\n"
			" (default: BOB)\n"
			"-p <hash_function> use different hash_function for packetID generation \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\" \n"
			" (default: same as '-F')\n\n"
			" -- IPFIX Configuration --\n"
			"-P <CollectorPort> \n"
			" (default: 4739)\n"
			"-C <CollectorIP> \n"
			" (default: localhost)\n"
			"-t <template> either \"min\" or \"lp\" or \"ts\"\n"
			" (default: ts)\n"
			"-I <export interval> in seconds - (packetIDs are exported at least once during this interval)\n"
			" (default: 3)\n"
			"-c <export_packet_count> size of export buffer after which packets are flushed (per device)\n"
			" (default: 1000)\n"
			"\n"
			" -- any --\n"
			"-v verbose-level - can be used multiple times to increase output\n"
			"-h print this help \n"
			" \n", MAX_INTERFACES);
}

long timevaldiff(struct timeval *starttime, struct timeval *finishtime) {
	long msec;
	msec = (finishtime->tv_sec - starttime->tv_sec) * 1000;
	msec += (finishtime->tv_usec - starttime->tv_usec) / 1000;
	return msec;
}

void export_resource_consumption() {
	uint64_t cc_user, cc_nice, cc_system, cc_hardirq, cc_softirq;
	uint64_t cc_idle, cc_iowait, cc_steal, cc_uptime;
	uint64_t delta_cc_idle, delta_cc_uptime;
	uint16_t cpu_promille_idle;
	//	proc_t P;

	static const char *cpu_info = "/proc/stat";
	static const char *process_info = "/proc/self/stat";
	FILE *fp;

	if ((fp = fopen(cpu_info, "r")) == NULL) {
		mlogf(CRITICAL, "fopen() failed to gain /proc/stat access \n");
		return;
	}
	char line[80];
	if (fgets(line, 80, fp) != NULL) {
		if (!strncmp(line, "cpu ", 4)) {
			cc_hardirq = cc_softirq = cc_steal = 0;
			/* CPU counters became unsigned long long with kernel 2.6.5 */
			sscanf(line + 5, "%llu %llu %llu %llu %llu %llu %llu %llu",
					&cc_user, &cc_nice, &cc_system, &cc_idle, &cc_iowait,
					&cc_hardirq, &cc_softirq, &cc_steal);
			cc_uptime = cc_user + cc_nice + cc_system + cc_idle + cc_iowait
					+ cc_hardirq + cc_softirq + cc_steal;
		}
	}

	fclose(fp);
	// printf("%llu %llu %llu %llu %llu %llu %llu %llu \n", cc_user, cc_nice, cc_system, cc_idle, cc_iowait, cc_hardirq, cc_softirq, cc_steal );

	FILE *fp2;
	if ((fp2 = fopen(process_info, "r")) == NULL) {
		mlogf(CRITICAL, "fopen() failed to gain /proc/self/stat access \n");
		return;
	}
	char *tmp;
	char *line2;
	line2 = (char *) malloc(800);
	tmp = (char *) malloc(800);
	if (fgets(line2, 800, fp2) != NULL) {
		line2 = strchr(line2, '(') + 1;
		tmp = strrchr(line2, ')');
		line2 = tmp + 2;
		printf("%s", line2);
		//		 sscanf(line2, "%c %d %d %d %d %d %lu %lu %lu %lu %lu "
		//		       "%Lu %Lu %Lu %Lu ",  /* utime stime cutime cstime */
		//		       &P.state, &P.ppid, &P.pgrp, &P.session, &P.tty, &P.tpgid,
		//		       &P.flags, &P.min_flt, &P.cmin_flt, &P.maj_flt, &P.cmaj_flt,
		//		       &P.utime, &P.stime, &P.cutime, &P.cstime    );
		//		 printf("state %c ppid %d pgrp %d session %d tty %d tpgid %d %Lu %Lu %Lu %Lu \n", P.state, P.ppid, P.pgrp, P.session, P.tty, P.tpgid, P.utime, P.stime, P.cutime, P.cstime);

	}

	delta_cc_uptime = cc_uptime - old_cc_uptime;
	delta_cc_idle = cc_idle - old_cc_idle;
	cpu_promille_idle = (delta_cc_idle * 1000) / delta_cc_uptime;
	old_cc_uptime = cc_uptime;
	old_cc_idle = cc_idle;
	fclose(fp2);

	printf("%d \n", cpu_promille_idle);
}

void export_array_sampling_parameters(device_dev_t* if_dev) {

	void* fields[] = { &(if_dev->export_packet_count),
			&(if_dev->totalpacketcount) };
	uint16_t lengths[] = { 4, 8 };
	if (0 > ipfix_export_array(if_dev->ipfixhandle,
			if_dev->sampling_export_template, 2, fields, lengths)) {
		fprintf(stderr, "ipfix_export() failed: %s\n", strerror(errno));
		exit(1);
	}

}

void flush_interface(device_dev_t* if_device, struct timeval ts) {
	if (NULL != if_device) {
		isFlushingFlag = 1; // prevent race condition with alarm handling !! todo: kinda bad way

		if (options.samplingResultExport == true) {
			export_array_sampling_parameters(if_device);
		}
		if (options.resourceConsumptionExport == true) {
			export_resource_consumption();
		}

		ipfix_export_flush(if_device->ipfixhandle);

		// reset with new timestamp
		if_device->totalpacketcount    = 0;
		if_device->export_packet_count = 0;
		if_device->last_export_time    = ts;

		// reset after flush
		isFlushingFlag = 0;
	}
}

void flush_interfaces() {
	int j;
	struct timeval now;

	alarmmm = 0;
	gettimeofday(&now, NULL);

	mlogf(DEBUG, "flush interfaces due to 'alarm'\n");

	for (j = 0; j < options.number_interfaces; j++) {
		if (timevaldiff(&(if_devices[j].last_export_time), &now)
				> options.export_interval * 1000) {
			flush_interface(&if_devices[j], now);
		}
	}
}

/* the signal handler for SIGINT == Ctrl-C --> shutdown program */
void catch_sigint(int sig_num) {
	int i;
	for (i = 0; i < options.number_interfaces; i++) {
		ipfix_export_flush(if_devices[i].ipfixhandle);
		ipfix_close(if_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	exit(0);
}

void catch_alarm(int sig_num) {

	alarmmm = 1;
	// printf("caught alarm \n");
	if ((1 == options.number_interfaces) && (0 != isFlushingFlag)) {
		/* skip flush if main is currently doing it */
		flush_interfaces();
	} else {
		/* flush_interfaces in case of multiple interfaces is handled directly run_pcap_loop */
		flush_interfaces();
		// printf("interfaces flushed \n");
	}
	signal(SIGALRM, catch_alarm);

}

void signal_setup() {
	// printf("signal_setup start \n");
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
	// printf("signal_setup_done \n");

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
	options->samplingResultExport = false;
	options->resourceConsumptionExport = false;
}

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
		}
	}

	mlogf(INFO, "using %s as hashFunction \n", hashfunctions[j].hstring);
	return hashfunctions[j].function;
}

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

void parse_cmdline(int argc, char **argv) {

	int c;
	char par[] = "hvnSi:I:o:r:t:f:m:M:s:F:c:P:C:R:";
	char *endptr;
	errno = 0;
	double sampling_ratio;
	// options->basedir =  strdup(argv[0]);
	//	char *pos = strrchr( options->basedir, '/' );
	//	pos[1] = 0;

	while (-1 != (c = getopt(argc, argv, par))) {
		//fprintf( stderr, "%c\n", c );
		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'v': {
			mlog_set_vlevel(++options.verbosity);
			//mlogf(ALWAYS, "%d\n\n", options.verbosity);
			break;
		}
		case 'P':
			if ((options.collectorPort = atoi(optarg)) < 0) {
				mlogf(ALWAYS, "Invalid -p argument!\n");
				exit(1);
			}
			break;
		case 'C':
			strcpy(options.collectorIP, optarg);
			break;
		case 'c':
			options.export_packet_count = atoi(optarg);
			break;
		case 'i':
			if (MAX_INTERFACES == options.number_interfaces) {
				mlogf(ALWAYS, "specify at most %d interfaces with -i\n", MAX_INTERFACES);
				break;
			}
			if (':' != optarg[1]) {
				mlogf(ALWAYS, "specify interface type with -i\n");
				mlogf(ALWAYS, "use [i,f,p,s,u]: as prefix - see help\n");
				mlogf(ALWAYS, "for compatibility reason, assume ethernet as 'i:' is given!\n");
				if_devices[options.number_interfaces].device_type = TYPE_PCAP;
				if_devices[options.number_interfaces].device_name = strdup(optarg);
				++options.number_interfaces;
				break;
			}
			switch (optarg[0]) {
			case 'i': // ethernet adapter
				if_devices[options.number_interfaces].device_type = TYPE_PCAP;
				break;
			case 'p': // pcap-file
				if_devices[options.number_interfaces].device_type
				= TYPE_PCAP_FILE;
				break;
			case 'f': // file
				if_devices[options.number_interfaces].device_type = TYPE_FILE;
				break;
			case 's': // inet socket
				if_devices[options.number_interfaces].device_type
				= TYPE_SOCKET_INET;
				break;
			case 'u': // unix domain socket
				if_devices[options.number_interfaces].device_type
				= TYPE_SOCKET_UNIX;
				break;
			case 'x': // unknown option
				if_devices[options.number_interfaces].device_type
				= TYPE_UNKNOWN;
				break;
			default:
				mlogf(ALWAYS, "unknown interface type with -i");
				mlogf(ALWAYS, "use [i,f,p,s,u]: as prefix - see help");
				break;
			}
			// skip prefix
			if_devices[options.number_interfaces].device_name = strdup(optarg
					+ 2);
			++options.number_interfaces;
			break;
			case 'I':
				options.export_interval = atoi(optarg);
				break;
			case 'o':
				options.observationDomainID = atoi(optarg);
				break;
			case 't':
				parseTemplate(optarg, &options);
				break;
			case 'f':
				options.bpf = strdup(optarg);
				break;
			case 'm':
				options.sel_range_min = strtoll(optarg, &endptr, 0);
				if ((*endptr != '\0') || (errno == ERANGE && (options.sel_range_min
						== LONG_MAX || options.sel_range_min == LONG_MIN))
						|| (errno != 0 && options.sel_range_min == 0)) {
					mlogf(ALWAYS, "error parsing selection_miminum_range - "
							"needs to be (uint32_t) \n");
					exit(1);
				}
				break;
			case 'M':
				options.sel_range_max = strtoll(optarg, NULL, 0);
				if ((*endptr != '\0') || (errno == ERANGE && (options.sel_range_max
						== LONG_MAX || options.sel_range_max == LONG_MIN))
						|| (errno != 0 && options.sel_range_max == 0)) {
					mlogf(ALWAYS, "error parsing selection_maximum_range - "
							"needs to be (uint32_t) \n");
					exit(1);
				}
				break;
			case 'r':
				sscanf(optarg, "%lf", &sampling_ratio);

				/*
				 * for the sampling ratio we do not like values at the edge, therefore we use values beginning at the 10% slice.
				 */

				options.sel_range_min = 0x19999999;
				options.sel_range_max = (double) UINT32_MAX / 100 * sampling_ratio;

				if (UINT32_MAX - options.sel_range_max > options.sel_range_min) {
					options.sel_range_min = 0x19999999;
					options.sel_range_max += options.sel_range_min;
				} else {
					/* more than 90% therefore use also values from first 10% slice */

					options.sel_range_min = UINT32_MAX - options.sel_range_max;
					options.sel_range_max = UINT32_MAX;
				}
				break;
			case 's':
				parseSelFunction(optarg, &options);
				break;
			case 'F':
				options.hash_function = parseFunction(optarg, &options);
				break;
			case 'p':
				options.pktid_function = parseFunction(optarg, &options);
				options.hashAsPacketID = 0;
				break;
			case 'l':
				options.snapLength = atoi(optarg);
				break;
			case 'n':
				options.samplingResultExport = true;
				break;
			case 'S':
				options.resourceConsumptionExport = true;
				break;
			case '?':
			default:
				printf("unknown parameter: %d (ignore)\n", c);
				break;
		} // switch( option )
	} // while (getopt())

	// set default interface if non is specified
	if ( 0 >= options.number_interfaces ) {
		options.number_interfaces = 0; // just to be sure
		if_devices[options.number_interfaces].device_type = TYPE_PCAP;
		if_devices[options.number_interfaces].device_name = "any";
		options.number_interfaces = 1;
		mlogf(ALWAYS, "no interface specified (default used)\n");
		mlogf(ALWAYS, "type -h for help\n");
	}

	return;
}

char *htoa(uint32_t ipaddr) {
	static char addrstr[16];
	uint8_t* p;

	ipaddr = htonl(ipaddr);
	p = (uint8_t*) &ipaddr;
	sprintf(addrstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	return addrstr;
}

void determineLinkType(device_dev_t* pcap_device) {

	pcap_device->link_type = pcap_datalink(pcap_device->device_handle.pcap);
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

void setFilter(device_dev_t* pcap_device) {
	/* apply filter */
	struct bpf_program fp;

	if (options.bpf) {
		if (-1 == pcap_compile(pcap_device->device_handle.pcap, &fp,
				options.bpf, 0, 0)) {
			mlogf(ALWAYS, "Couldn't parse filter %s: %s\n", options.bpf,
					pcap_geterr(pcap_device->device_handle.pcap));
		}
		if (-1 == pcap_setfilter(pcap_device->device_handle.pcap, &fp)) {
			mlogf(ALWAYS, "Couldn't install filter %s: %s\n", options.bpf,
					pcap_geterr(pcap_device->device_handle.pcap));
		}
	}
}

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
	//		&(pcap_devices[i].IPv4address), &(pcap_devices[i].mask), errbuf)
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
	//			pcap_devices[i].IPv4address = ntohl((uint32_t) inp.s_addr);
	//			mlogf(INFO, "Device %s has IP %s \n", options->if_names[i], htoa(
	//					pcap_devices[i].IPv4address));
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

void open_ipfix_export(device_dev_t *if_device, options_t *options) {

	// set initial export packe count
	if_device->export_packet_count = 0;

	// use observationDomainID if explicitely given via
	// cmd line, else use interface IPv4address as oid
	// todo: alternative oID instead of IP address --> !!different device types!!
	uint32_t odid =
			(options->observationDomainID != 0) ? options->observationDomainID
					: if_device->IPv4address;

	// open ipfix handle
	if (0 > ipfix_open(&(if_device->ipfixhandle), odid, IPFIX_VERSION)) {
		mlogf(ALWAYS, "ipfix_open() failed: %s\n", strerror(errno));
	}

	// open ipfix connection
	if (0 > ipfix_add_collector(if_device->ipfixhandle, options->collectorIP,
			options->collectorPort, IPFIX_PROTO_TCP)) {
		mlogf(ALWAYS, "ipfix_add_collector(%s,%d) failed: %s\n",
				options->collectorIP, options->collectorPort, strerror(errno));
	}

	// create ipfix export template as defined at cmd line
	switch (options->templateID) {
	case TS_ID:
		if (0 > ipfix_make_template(if_device->ipfixhandle,
				&(if_device->ipfixtemplate), export_fields_ts, 2)) {
			mlogf(ALWAYS, "ipfix_make_template( ts ) failed: %s\n", strerror(
					errno));
			exit(1);
		}
		break;

	case MINT_ID:
		if (0 > ipfix_make_template(if_device->ipfixhandle,
				&(if_device->ipfixtemplate), export_fields_ts_ttl, 3)) {
			mlogf(ALWAYS, "ipfix_make_template( ts_ttl ) failed: %s\n",
					strerror(errno));
			exit(1);
		}
		break;

	case TS_TTL_PROTO_ID:
		if (0 > ipfix_make_template(if_device->ipfixhandle,
				&(if_device->ipfixtemplate), export_fields_ts_ttl_proto, 6)) {
			mlogf(ALWAYS, "ipfix_make_template( ts_ttl_proto ) failed: %s\n",
					strerror(errno));
			exit(1);
		}
		break;

	default:
		break;
	}

	// create export sampling result template, if set
	if (options->samplingResultExport == true) {
		if (0 > ipfix_make_template(if_device->ipfixhandle,
				&(if_device->sampling_export_template),
				export_sampling_parameters, 2)) {
			mlogf(
					ALWAYS,
					"ipfix_make_template_export_sampling_parameters() failed: %s\n",
					strerror(errno));
		}
	}

	return;
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
	copiedbytes = options.selection_function(packet, header->caplen,
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
	hash_result = options.hash_function(if_device->outbuffer, copiedbytes);
	mlogf( INFO, "hash result: 0x%04X\n", hash_result );

	// hash result must be in the chosen selection range to count
	if ((options.sel_range_min < hash_result)
			&& (options.sel_range_max > hash_result))
	{
		if_device->export_packet_count++;

		int pktid = 0;
		if (options.hashAsPacketID == 1) { // in case we want to use the hashID as packet ID
			pktid = hash_result;
		} else {
			pktid = options.pktid_function(if_device->outbuffer, copiedbytes);
		}

		timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
				+ (uint64_t) header->ts.tv_usec;

		switch (options.templateID) {
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
		if (if_device->export_packet_count >= options.export_packet_count) {
			flush_interface(if_device, header->ts);
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
		if( BUFFER_SIZE > options.snapLength )
		{
			caplen = options.snapLength;
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

int main(int argc, char *argv[]) {
	int i; // loop counter

	// set defaults options
	set_defaults(&options);
	mlogf(INFO, "set_defaults() okay \n");

	// parse commandline; set global parameter options
	parse_cmdline(argc, argv);
	mlogf(INFO, "parse_cmdline() okay \n");

	// allocate memory for outbuffer; depend on cmd line options
	// just for the real amount of interfaces used
	for (i = 0; i < options.number_interfaces; ++i) {
		if_devices[i].outbuffer = calloc(options.snapLength, sizeof(uint8_t));
	}

	// init ipfix module
	if (ipfix_init() < 0) {
		mlogf(ALWAYS, "cannot init ipfix module: %s\n", strerror(errno));
	}
	mlogf(INFO, "ipfix_init() okay (%d times) \n", i);

	// open pcap interfaces with filter
	for (i = 0; i < options.number_interfaces; ++i) {
		open_device(&if_devices[i], &options);
	}
	mlogf(INFO, "open_device() okay (%d times) \n", i);

	// setup ipfix_exporter for each device
	for (i = 0; i < options.number_interfaces; ++i) {
		open_ipfix_export(&if_devices[i], &options);
	}
	mlogf(INFO, "open_ipfix_export() okay (%d times) \n", i);

	// setup the signal handler
	signal_setup();

	// run capture_loop until program termination
	capture_loop(if_devices, &options);

	return 0;
}

