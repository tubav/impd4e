/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll, Ramon Massek) &
 *                     TU-Berlin (Christian Henke)
 * Copyright (c) 2010, Robert Wuttke <flash@jpod.cc>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation either version 3 of the License, or (at your option) any
 * later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <unistd.h> // getopt()
#include <string.h>
//#include <inttypes.h>
//#include <ctype.h>
//#include <limits.h>
//#include <stdio.h>
//#include <errno.h>
//#include <signal.h>
//#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h> /* TODO review: sysinfo is Linux only */
#include <sys/times.h>

#include <netinet/in.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <arpa/inet.h>
#ifndef PFRING
#include <pcap.h>
#endif

//// event loop
//#include <ev.h>
#include "ev_handler.h"
//
#include "main.h"

//#include "constants.h"
//#include "hash.h"
#include "mlog.h"

// ipfix staff
#include "ipfix.h"
#include "ipfix_def.h"
#include "ipfix_def_fokus.h"
#include "ipfix_fields_fokus.h"
#include "templates.h"

//#include "stats.h"

// Custom logger
#include "logger.h"
#include "helper.h"
//#include "netcon.h"

#include "settings.h"

// Are we building impd4e for Openwrt
#ifdef OPENWRT_BUILD
	#ifndef _GNU_SOURCE
		#define _GNU_SOURCE
	#endif
	#ifndef PFRING
		#define PFRING
	#endif
#endif

#ifdef PFRING
#include "pfring_filter.h"
#include <pf_plugin_impd4e.h>
#endif

/*----------------------------------------------------------------------------
 Globals
 ----------------------------------------------------------------------------- */

#ifndef PFRING
char pcap_errbuf[PCAP_ERRBUF_SIZE];
char errbuf[PCAP_ERRBUF_SIZE];
#endif

device_dev_t  if_devices[MAX_INTERFACES];

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
	#ifdef PFRING
	uint8_t i = 0;
	#endif
	printf(
			"impd4e - a libpcap based measuring probe which uses hash-based packet\n"
				"         selection and exports packetIDs via IPFIX to a collector.\n\n"
				"USAGE: impd4e -i interface [options] \n"
				"\n");

	printf(
            #ifndef PFRING
			"   -i  <i,f,p,s,u>:<interface>    interface(s) to listen on. It can be used multiple times.\n"
			"\t i - ethernet adapter;             -i i:eth0\n"
			"\t p - pcap file;                    -i p:traffic.pcap\n"
			"\t f - plain text file;              -i f:data.txt\n"
			"\t s - inet socket (AF_INET);        -i s:192.168.0.42:4711\n"
			"\t u - unix domain socket (AF_UNIX); -i u:/tmp/socket.AF_UNIX\n"
			#else
            "   -i  <r>:<interface>    interface(s) to listen on. It can be used multiple times.\n"
			"\t r - ethernet adapter using pfring;-i r:eth0\n"
			#endif
			"\n"
			"options: \n"
            #ifdef PFRING
            "   -a <filter keyword>:<value>    Filtering if using PF_RING\n"
				"\t\t\t\t  Specify an packet filter and/or the default\n"
                "\t\t\t\t  filtering policy (valid for all filters).\n"
                "\t\t\t\t  It can be used multiple times.\n"
            #endif // PFRING
			"   -l  <snaplength>               setup max capturing size in bytes\n"
			"                                  Default: 80 \n"
            #ifndef PFRING
			"   -f  <bpf>                      Berkeley Packet Filter expression (e.g. \n"
			"                                  tcp udp icmp)\n"
            #endif
			"   -I  <interval>                 pktid export interval in seconds. Use 0 for \n"
			"                                  disabling pkid export. Ex. -I 1.5  \n"
			"   -J  <interval>                 probe stats export interval in seconds. \n"
			"                                  Measurement is done at each elapsed interval. \n"
			"                                  Use -J 0 for disabling this export.\n"
			"                                  Default: 30.0 \n"
			"\n"
			"   -K  <interval>                 interface stats export interval in seconds. \n"
			"                                  Measurement is done at each elapsed interval. \n"
			"                                  Use -K 0 for disabling this export.\n"
			"                                  Default: 10.0 \n"
			"\n"
			"   -M  <maximum selection range>  integer - do not use in conjunction with -r \n"
			"   -m  <minimum selection range>  integer - do not use in conjunction with -r \n"
			"   -r  <sampling ratio>           in %% (double)\n"
			"\n"
			"   -s  <selection function>       which parts of the packet used for hashing (presets)\n"
			"                                  either: \"IP+TP\", \"IP\", \"REC8\", \"PACKET\"\n"
			"                                  Default: \"IP+TP\"\n"
			"   -S  <selection function>       which parts of the packet used for hashing (byte selection)\n"
			"                                  <keyword><offset list>\n"
			"                                  keywords: \"RAW\", \"LINK\", \"NET\", \"TRANS\", \"PAYLOAD\"\n"
			"                                  offset list: comma seperated list with byte offsets and offset ranges\n"
			"                                      , add another offset/offset range\n"
			"                                      - range modifier (include borders)\n"
			"                                      ^ range modifier (exclude borders)\n"
			"                                      < range modifier (exclude right border)\n"
			"                                      > range modifier (exclude left border)\n"
			"                                      + range modifier (offset length)\n"
			"                                      : range modifier (offset length)\n"
			"                                    < and > have to be escaped \n"
			"                                  Example: RAW20,34-45,14+4,4\n"
			"\n"
			"   -F  <hash_function>            hash function to use:\n"
			"                                  \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\"\n"
			"   -p  <hash function>            use different hash_function for packetID generation:\n"
			"                                  \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\" \n"
			"\n"
			"   -o  <observation domain id>    identification of the interface in the IPFIX Header\n"
			"   -C  <Collector IP>             an IPFIX collector address\n"
			"                                  Default: localhost\n"
			"   -P  <Collector Port>           an IPFIX Collector Port\n"
			"                                  Default: 4739\n"
			"   -c  <export packet count>      size of export buffer after which packets\n"
			"                                  are flushed (per device)\n"
			"   -t  <template>                 either \"min\" or \"lp\" or \"ts\"\n"
			"                                  Default: \"min\"\n"
			"   -u                             use only one oid from the first interface \n"
			"\n"
			"   -v                             verbose-level; use multiple times to increase output \n"
			"   -h                             print this help \n"
			"\n");

	#ifdef PFRING
		printf("Possible PF_RING filter keywords include: ");
		for ( i = 0; i < last_pfring_filter_keyword; i++ )
			printf("%s, ", pfring_filter_keywords[i]);
		printf("%s\n\n", pfring_filter_keywords[last_pfring_filter_keyword]);
		printf("Possible PF_RING ip protocols include: ");
        print_all_ip_prot_str();
        printf("\n\n");
	#endif
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
}

/**
 * Set default options
 */
void set_defaults_options(options_t *options) {
	options->verbosity           = 0;
	options->number_interfaces   = 0;
	options->bpf                 = NULL;
	options->templateID          = MINT_ID;
	options->collectorPort       = 4739;
	strcpy(options->collectorIP, "localhost");
	options->observationDomainID = 0;
	options->hash_function       = calcHashValue_BOB;
	options->selection_function  = copyFields_U_TCP_and_Net;
	options->sel_range_min       = 0x19999999; // (2^32 / 10)
	options->sel_range_max       = 0x33333333; // (2^32 / 5)
	options->snapLength          = 80;

	options->export_packet_count      = 1000;
	options->export_pktid_interval    =  3.0; /* seconds */
	options->export_sampling_interval = 10.0; /* seconds */
	options->export_stats_interval    = 30.0; /* seconds */

	options->hashAsPacketID          = 1;
	options->use_oid_first_interface = 0;

	//	options->samplingResultExport = false;
	//	options->export_sysinfo = false;
}


void set_defaults_device(device_dev_t* dev) {

	// allocate memory for outbuffer; depend on cmd line options
	// just for the real amount of interfaces used
	dev->outbufferLength = g_options.snapLength;
	dev->outbuffer       = calloc( g_options.snapLength, sizeof(uint8_t) );

}


#ifdef PFRING
/**
 * Parse one pfring filter arg
 */
void parse_pfring_filter_arg(char* arg_string, options_t* options,
								filtering_rule* rule) {
	uint8_t i = 0;
	uint8_t k = 0;
	char* arg = NULL;
	char* value = NULL;
	char* savePtr = NULL;

	arg = strtok_r(arg_string, ":", &savePtr);

	for (i = 0; i <= last_pfring_filter_keyword; i++) {
		if (strncasecmp(arg_string, pfring_filter_keywords[i],
                strlen(pfring_filter_keywords[i])) == 0) {
			printf("parse_pfring_filter_arg: found keyword: %s\n", arg);
			value = strtok_r(NULL, ":", &savePtr);
			printf("parse_pfring_filter_arg: value        : %s\n", value);

			switch(i) {
				// prot
				case 0:
					for( k = 0; k <= last_ip_prot; k++ ) {
						if (strncasecmp(value, ip_protocols[k],
								strlen(ip_protocols[k])) == 0) {
							if (rule->core_fields.proto == 0) {
								rule->core_fields.proto = k;
								printf("parse_pfring_filter_arg: set proto to : 0x%02x\n", k);
							}
							else {
								printf("parse_pfring_filter_arg: proto was already set by a previous declaration\n");
							}
						}
					}
				break;
	            // ipl
				// TODO: add v6 support
    	        case 1:
					if(rule->core_fields.host_low.v4 == ntohl(inet_addr("0"))){
						rule->core_fields.host_low.v4 = ntohl(inet_addr(value));
						printf("parse_pfring_filter_arg: added ip\n");
					}
					else {
						printf("parse_pfring_filter_arg: ip_low was already set by a previous declaration\n");
					}
				break;
				// iph
				// TODO: add v6 support
        	    case 2:
					if(rule->core_fields.host_high.v4 == ntohl(inet_addr("0"))){
						rule->core_fields.host_high.v4 =ntohl(inet_addr(value));
						printf("parse_pfring_filter_arg: added ip\n");
					}
					else {
						printf("parse_pfring_filter_arg: ip_high was already set by a previous declaration\n");
					}
				break;
				// ip
				// TODO: add v6 support
            	case 3:
					if(rule->core_fields.host_high.v4 == ntohl(inet_addr("0"))&&
							rule->core_fields.host_low.v4 == ntohl(inet_addr("0"))) {
						rule->core_fields.host_low.v4 = ntohl(inet_addr(value));
						rule->core_fields.host_high.v4=ntohl(inet_addr(value));
						printf("parse_pfring_filter_arg: added ip\n");
					}
					else {
						printf("parse_pfring_filter_arg: ip was already set by a previous declaration\n");
					}
				break;
				// portl
	            case 4:
					if (rule->core_fields.port_low == 0) {
						// TODO: add check to prevent integer-overflow
						rule->core_fields.port_low = atoi(value);
						printf("parse_pfring_filter_arg: added port_low: %d\n", rule->core_fields.port_low);
					}
					else {
						printf("parse_pfring_filter_arg: port_low was already set by a previous declaration\n");
					}
				break;
				// porth
    	        case 5:
					if (rule->core_fields.port_high == 0) {
						// TODO: add check to prevent integer-overflow
						rule->core_fields.port_high = atoi(value);
						printf("parse_pfring_filter_arg: added port_high: %d\n", rule->core_fields.port_high);
					}
					else {
						printf("parse_pfring_filter_arg: port_high was already set by a previous declaration\n");
					}
				break;
				// port
        	    case 6:
					if (rule->core_fields.port_low == 0 &&
							rule->core_fields.port_high == 0) {
						// TODO: add check to prevent integer-overflow
						rule->core_fields.port_low = atoi(value);
						rule->core_fields.port_high = atoi(value);
						printf("parse_pfring_filter_arg: added port: %d\n", rule->core_fields.port_low);
					}
					else {
						printf("parse_pfring_filter_arg: port was already set by a previous declaration\n");
					}
				break;
				// macl
            	case 7:
					printf("MAC address filtering is not yet implemented\n");
				break;
				// mach
    	        case 8:
					printf("MAC address filtering is not yet implemented\n");
				break;
				// mac
	            case 9:
					printf("MAC address filtering is not yet implemented\n");
				break;
				// vlan
        	    case 10:
					if (rule->core_fields.vlan_id == 0) {
						// TODO: add check to prevent integer-overflow
						rule->core_fields.vlan_id = atoi(value);
                        printf("parse_pfring_filter_arg: added vlan: %d\n", rule->core_fields.vlan_id);
                    }
                    else {
                        printf("parse_pfring_filter_arg: vlan was already set by a previous declaration\n");
                    }
				break;
				// prio
				/* Rules are processed in order from lowest to higest id */
            	case 11:
					if (rule->rule_id == 0 ) {
						// TODO: add check to prevent integer-overflow
						rule->rule_id = atoi(value);
						printf("parse_pfring_filter_arg: added prio: %d\n", rule->rule_id);
					}
					else {
						printf("parse_pfring_filter_arg: prio was already set by a previous declaration\n");
					}
				break;
                /* this breaks with the selection plugin.
                 * if user has supplied at least 1 filtering rule then
                 * action is set to accept and policy to drop
				// action
				case 12:
					if (strncasecmp(value, "ACCEPT", 6) == 0) {
						rule->rule_action = forward_packet_and_stop_rule_evaluation;
						printf("parse_pfring_filter_arg: added action: ACCEPT\n");
					}
					else if (strncasecmp(value, "DROP", 4) == 0) {
						 rule->rule_action = dont_forward_packet_and_stop_rule_evaluation;
						printf("parse_pfring_filter_arg: added action: DROP\n");
					}
					else {
						printf("parse_pfring_filter_arg: UNKNOWN action: %s\n", value);
					}
				break;
                */
                /* this breaks with the selection plugin (at least policy accept
                 * with drop-rules does)
				// set default policy for ALL rules
				case 13:
					if (options->filter_policy == -1) {
						if (strncasecmp(value, "ACCEPT", 6) == 0) {
							options->filter_policy = 1;
							printf("parse_pfring_filter_arg: set policy: ACCEPT\n");
						}
						else if (strncasecmp(value, "DROP", 4) == 0) {
							options->filter_policy = 0;
							printf("parse_pfring_filter_arg: set policy: DROP\n");
						}
						else {
							printf("parse_pfring_filter_arg: UNKNOWN policy: %s\n", value);
						}
					}
					else {
						printf("parse_pfring_filter_arg: policy was already set by a previous declaration\n");
					}
				break;
                */
			}
			break;
        }
	}
	printf("\n");
}

/**
 * Parse pfring filter expressions
 */
void parse_pfring_filter(char* arg_string, options_t* options) {
	//int i = 0;
	char* arg = NULL;
	char* savePtr = NULL;
	filtering_rule rule;
    memset(&rule, 0, sizeof(rule));

	printf("===============================================================\n");
	printf("parse_pfring_filter: arg_string       : %s\n\n", arg_string);
	/* steps:
	 * split at whitespaces
	 * for whitespace do
	 *   split at colons
	 *   check split[0] == known keyword
     *   check split[0] == valid value
	 *   apply setting / save
	 */

	// split at spaces
	arg = strtok_r(arg_string, " ", &savePtr);
	//printf("parse_pfring_filter: first arg        : %s\n", arg);
	parse_pfring_filter_arg(arg, options, &rule);
	while( (arg = strtok_r(NULL, " ", &savePtr)) != NULL ) {
		//printf("parse_pfring_filter: next arg         : %s\n", arg);
		parse_pfring_filter_arg(arg, options, &rule);
	}

	// check if any rule-field is set
	if (	rule.core_fields.proto != 0     ||
			rule.core_fields.port_low != 0  ||
			rule.core_fields.port_high != 0 ||
			// TODO: add v6 support
			rule.core_fields.host_low.v4 != ntohl(inet_addr("0"))  ||
			rule.core_fields.host_high.v4 != ntohl(inet_addr("0")) ||
			rule.core_fields.vlan_id != 0   ) {

		if (options->rules_in_list < MAX_RULES) {
			options->rules[options->rules_in_list] = rule;
			printf("parse_pfring_filter: added rule in slot: %d\n",options->rules_in_list);
			options->rules_in_list++;
		}
		else {
			printf("parse_pfring_filter: maximum number of rules reached. cannot add rule\n");
		}
	}
}
#endif

/**
 * Process command line arguments
 */
void parse_cmdline(int argc, char **argv) {

	options_t* options = &g_options;
	int c;
    #ifdef PFRING
   	char par[] = "hvnyua:J:K:i:I:o:r:t:f:F:m:M:s:S:F:c:P:C:l:";
    #else
    char par[] = "hvnyuJ:K:i:I:o:r:t:f:F:m:M:s:S:F:c:P:C:l:";
    #endif
	errno = 0;

	options->number_interfaces = 0;
	#ifdef PFRING
	options->rules_in_list = 0;
	options->filter_policy = -1;
	#endif

	while (-1 != (c = getopt(argc, argv, par))) {
		switch (c) {
        #ifdef PFRING
        case 'a':
            /* pf_ring filter */
            parse_pfring_filter(optarg, options);
            break;
        #endif
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
		case 'i': {
			uint8_t if_idx = options->number_interfaces; // shorter for better reading
			if (MAX_INTERFACES == options->number_interfaces) {
				mlogf(ALWAYS, "specify at most %d interfaces with -i\n", MAX_INTERFACES);
				break;
			}
			if (':' != optarg[1]) {
				mlogf(ALWAYS, "specify interface type with -i\n");
				mlogf(ALWAYS, "use [i,f,p,s,u]: as prefix - see help\n");
				mlogf(ALWAYS, "for compatibility reason, assume ethernet as 'i:' is given!\n");
				if_devices[if_idx].device_type = TYPE_PCAP;
				if_devices[if_idx].device_name = strdup(optarg);
			}
			else {
				switch (optarg[0]) {
				case 'i': // ethernet adapter
					if_devices[if_idx].device_type = TYPE_PCAP;
					break;
				case 'p': // pcap-file
					if_devices[if_idx].device_type = TYPE_PCAP_FILE;
					break;
				case 'f': // file
					if_devices[if_idx].device_type = TYPE_FILE;
					break;
				case 's': // inet socket
					if_devices[if_idx].device_type = TYPE_SOCKET_INET;
					break;
				case 'u': // unix domain socket
					if_devices[if_idx].device_type = TYPE_SOCKET_UNIX;
					break;
				#ifdef PFRING
				case 'r': // use pfring instead of libpcap
					if_devices[if_idx].device_type = TYPE_PFRING;
				break;
				#endif
				case 'x': // unknown option
					if_devices[if_idx].device_type = TYPE_UNKNOWN;
					break;
				default:
					mlogf(ALWAYS, "unknown interface type with -i\n");
					mlogf(ALWAYS, "use [i,f,p,s,u]: as prefix - see help\n");
					break;
				}
				// skip prefix
				if_devices[if_idx].device_name=strdup(optarg+2);
			}
			// increment the number of interfaces
			++options->number_interfaces;
			break;
		}
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
			set_sampling_lowerbound(options, optarg);
			break;
		case 'M':
			set_sampling_upperbound(options, optarg);
			break;
		case 'r':
			set_sampling_ratio(options, optarg);
			break;
		case 's':
		case 'S':
			parseSelFunction(optarg, options);
			break;
		case 'F':
			options->hash_function = parseFunction(optarg);
			break;
		case 'p':
			options->pktid_function = parseFunction(optarg);
			options->hashAsPacketID = 0;
			break;
		case 'P':
			if ((options->collectorPort = atoi(optarg)) < 0) {
				mlogf(ALWAYS, "Invalid -p argument!\n");
				exit(1);
			}
			break;
		case 'v':
			mlog_set_vlevel(++options->verbosity);
			break;
		case 'l':
			options->snapLength = atoi(optarg);
			break;
		case 'u':
			options->use_oid_first_interface=1;
			break;
		case 'n':
			// TODO parse enable export sampling
			break;
		case 'y':
			// TODO
			//			options->export_sysinfo = true;
			break;
		default:
			printf("unknown parameter: %d \n", c);
			break;
		}

	}

}

#ifndef PFRING
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
	// FIXME: this won't build on OpenWrt
	#ifndef OPENWRT_BUILD
	if (0 > connect(if_device->device_handle.socket,
			(__CONST_SOCKADDR_ARG) &socket_address, socket_addressLength)) {
		perror("socket: connect");
		exit(2);
	}
    #endif

}
#endif

#ifdef PFRING
void open_pfring(device_dev_t* if_dev, options_t *options) {
	mlogf(ALWAYS, "selected PF_RING\n");
	mlogf(ALWAYS, "device_name: %s\n", if_dev->device_name);
	if_dev->device_handle.pfring = pfring_open(if_dev->device_name, 1,
			options->snapLength, 0);
	if (NULL == if_dev->device_handle.pfring) {
		mlogf(ALWAYS, "Failed to set up PF_RING-device\n");
		exit(1);
	}

	if_dev->IPv4address = getIPv4AddressFromDevice(if_dev->device_name);
	mlogf(ALWAYS, "Device %s has IP %s \n", if_dev->device_name, htoa(
			if_dev->IPv4address));

	// pfring only supports ethernet
    if_dev->link_type = DLT_EN10MB;
    if_dev->offset[L_NET] = 14;

	setPFRingFilter(if_dev);
    setPFRingFilterPolicy(if_dev);
}
#endif

void open_device(device_dev_t* if_device, options_t *options) {
	// parameter check
	if (NULL == if_device || NULL == options) {
		mlogf(ALWAYS, "Parameter are NULL!\n");
		return;
	}

	switch (if_device->device_type) {
    #ifndef PFRING
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
    #endif
	#ifdef PFRING
	case TYPE_PFRING:
		open_pfring(if_device, options);
		break;
	#endif

	case TYPE_UNKNOWN:
	default:
		mlogf(ALWAYS, "not yet implemented!\n");
		break;
	}

	/* set initial export time to 'now' */
	gettimeofday(&(if_device->last_export_time), NULL);

	return;
}

void libipfix_init() {
	if (ipfix_init() < 0) {
		mlogf(ALWAYS, "cannot init ipfix module: %s\n", strerror(errno));

	}
	if (ipfix_add_vendor_information_elements(ipfix_ft_fokus) < 0) {
		fprintf(stderr, "cannot add FOKUS IEs: %s\n", strerror(errno));
		exit(1);
	}
}


void libipfix_open(device_dev_t *if_device, options_t *options) {
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

	// create templates
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_min, export_fields_min) < 0) {
		LOGGER_fatal("template initialization failed: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
			if_device->ipfixtmpl_ts,
			export_fields_ts) < 0) {
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

	if (ipfix_add_collector(if_device->ipfixhandle,
			options->collectorIP, options->collectorPort, IPFIX_PROTO_TCP)
			< 0) {
		LOGGER_error("ipfix_add_collector(%s,%d) failed: %s\n",
				options->collectorIP, options->collectorPort, strerror(
						errno));
	}

//	LOGGER_info("device:      %p", if_device);
//	LOGGER_info("ipfixhandle: %p", if_device->ipfixhandle);
//	LOGGER_info("collectors:  %p", if_device->ipfixhandle->collectors);
//	LOGGER_info("fd:          %d", ((ipfix_collector_sync_t*) if_device->ipfixhandle->collectors)->fd);
//	LOGGER_info("&fd:         %p", &((ipfix_collector_sync_t*) if_device->ipfixhandle->collectors)->fd);

	return;
}

void libipfix_reconnect() {
	int i;
	LOGGER_info("trying to reconnect ");
	for (i = 0; i < g_options.number_interfaces; i++) {
		ipfix_export_flush(if_devices[i].ipfixhandle);
		ipfix_close(if_devices[i].ipfixhandle);
	}
	ipfix_cleanup();
	libipfix_init(if_devices, &g_options);

}


//------------------------------------------------------------------------------
//  MAIN
//------------------------------------------------------------------------------
int main(int argc, char *argv[]) {
	int i;
	// initializing custom logger
	logger_init(LOGGER_LEVEL_WARN);

	// set defaults options
	set_defaults_options(&g_options);
	mlogf(INFO, "set_defaults() okay \n");

	// parse commandline; set global parameter options
	parse_cmdline(argc, argv);
	mlogf(INFO, "parse_cmdline() okay \n");

	logger_setlevel(g_options.verbosity);

	if (g_options.number_interfaces == 0) {
		print_help();
		exit(-1);
	}

	// init ipfix module
	libipfix_init();

	for (i = 0; i < g_options.number_interfaces; ++i) {
		set_defaults_device( &if_devices[i] );

		// open pcap interfaces with filter
		open_device(&if_devices[i], &g_options);
		mlogf(INFO, "open_device(%d)\n", i);

		// setup ipfix_exporter for each device
		libipfix_open(&if_devices[i], &g_options);
		mlogf(INFO, "open_ipfix_export(%d)\n", i);
	}

	/* ---- main event loop  ---- */
	event_loop(); // todo: refactoring?

	// init event-loop
	// todo: loop = init_event_loop();
	// register export callback
	// todo: event_register_callback( loop, callback[] );
	// start event-loop
	// todo: start_event_loop( loop );

	/* -- normal shutdown --  */
	impd4e_shutdown();
	LOGGER_info("bye.");

	exit(0);
}

