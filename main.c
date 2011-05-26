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
 * Robert Wuttke <flash@jpod.cc>
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

#include <stdlib.h>
#include <unistd.h> // getopt()
#include <string.h>
#include <ctype.h>
//#include <inttypes.h>
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

#include "main.h"

//// event loop
//#include <ev.h>
#include "ev_handler.h"
#include "ipfix_handler.h"
#include "pcap_handler.h"
#include "socket_handler.h"

//#include "constants.h"
//#include "hash.h"

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

	printf(		"   -c  <configfile>               read parameters from config file\n"
                        "                                  (parameters on command line have precedence over the same\n"
                        "                                  parameters in config file, or are supplemental, e.g. for -i)\n"
                        "\n"
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
			"   -N  <snaplength>               setup max capturing size in bytes\n"
			"                                  Default: 80 \n"
			"\n"
            #ifndef PFRING
			"   -f  <bpf>                      Berkeley Packet Filter expression (e.g. tcp udp icmp)\n"
			"\n"
            #endif
			"   -I  <interval>                 pktid export interval in seconds. (e.g. 1.5)\n"
			"                                  Use -I 0 for disabling this export.\n"
			"                                  Default: 3.0 \n"
			"   -J  <interval>                 probe stats export interval in seconds. \n"
			"                                  Measurement is done at each elapsed interval. \n"
			"                                  Use -J 0 for disabling this export.\n"
			"                                  Default: 30.0 \n"
			"\n"
			"   -K  <interval>                 interface stats export interval in seconds. \n"
			"                                  Use -K 0 for disabling this export.\n"
			"                                  Default: 10.0 \n"
			"   -G  <interval>                 location export interval in seconds. \n"
			"                                  Use -G 0 for exporting once at startup.\n"
			"                                  Default: 60.0 \n"
			"\n"
			"   -m  <minimum selection range>  integer - do not use in conjunction with -r \n"
			"   -M  <maximum selection range>  integer - do not use in conjunction with -r \n"
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
			"   -o  <observation domain id>    unique identifier for probe \n"
			"                                  Default: IP address of the interface\n"
			"\n"
			"   -C  <Collector IP>             an IPFIX collector address\n"
			"                                  Default: localhost\n"
			"   -P  <Collector Port>           an IPFIX Collector Port\n"
			"                                  Default: 4739\n"
			"   -e  <export packet count>      size of export buffer after which packets\n"
			"                                  are flushed (per device)\n"
			"   -t  <template>                 either \"min\" or \"lp\" or \"ts\"\n"
			"                                  Default: \"min\"\n"
			"   -u                             use only one oid from the first interface \n"
			"\n"
			"   -d <probe name>                a probe name\n"
			"                                  Default: <hostname>\n"
			"   -D <location name>             a location name\n"
			"   -l <latitude>                  geo location (double): latitude\n"
			"   -l <lat>:<long>:<interval>     short form\n"
			"   -L <longitude>                 geo location (double): longitude\n"
			"   -L <long>:<lat>:<interval>     short form\n"
			"\n"
			"   -v[expression]                 verbose-level; use multiple times to increase output \n"
			"                                  filter by function names in comma-separated list at a certain \n"
			"                                  log level\n"
			"                                  * matches anything; can be combined at start/end of expressions\n"
			"                                  - exclude expression\n"
			"                                  Example: '-vv*,-main' matches anything but main-function (level 2)\n"
			"                                  Example: '-vvv*export*,-*flush, \n"
			"                                           matches all functions containing export, but not ending of flush\n"
			"\n"
			"   -h                             print this help \n"
			"\n"
			"EXAMPLES for usage: \n"
			"sudo impd4e -i i:eth0 -C 172.20.0.1 -r 1 -t min \n"
			"sudo impd4e -i i:lo   -C 172.20.0.1 -o <somethingyoulike> -S 20,34-45\n");

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
	options->verbosity_filter_string = "";
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

	options->s_probe_name     = NULL; // will be set to host name if not given by cmd line
	options->s_location_name  = "unknown";
	options->s_latitude       = "unknown";
	options->s_longitude      = "unknown";
	options->ipAddress        = 0x00000000; //0.0.0.0

	options->export_packet_count      = 1000;
	options->export_pktid_interval    =  3.0; /* seconds */
	options->export_sampling_interval = 10.0; /* seconds */
	options->export_stats_interval    = 30.0; /* seconds */
	options->export_location_interval = 60.0; /* seconds */

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


void make_lower(char *s) {
	if (!s) return;
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

struct config_map_t {
	char *cfg_item;
	char opt_letter;
};

struct config_map_t cfg_opt_list[] = {
	{ "general.verbosity", 'v'},
	{ "general.help", 'h'},
	{ "capture.interface", 'i'},
	{ "filter.bpfilter", 'f'},
	{ "filter.snaplength", 'N'},
	{ "interval.data_export", 'I'},
	{ "interval.probe_stats", 'J'},
	{ "interval.interface_stats", 'K'},
	{ "interval.location", 'G'},
	{ "selection.min_hash_range", 'm'},
	{ "selection.max_hash_range", 'M'},
	{ "selection.hash_selection_ratio", 'r'},
	{ "selection.selection_preset", 's'},
	{ "selection.selection_parts", 'S'},
	{ "selection.hash_function", 'F'},
	{ "selection.pktid_function", 'p'},
	{ "ipfix.observation_domain_id", 'o'},
	{ "ipfix.one_odid", 'u'},
	{ "ipfix.collector_ip_address", 'C'},
	{ "ipfix.collector_port", 'P'},
	{ "ipfix.export_flush_count", 'e'},
	{ "template.used_template", 't'},
	{ "geotags.probe_name", 'd'},
	{ "geotags.location_name", 'D'},
	{ "geotags.latitude", 'l'},
	{ "geotags.longitude", 'L'},
	{ NULL, '\0' }
};

/* 'mapped' config item read from file, e.g. {'i', "eth0"} */
struct config_option_t {
	char opt_letter;
	char *value;
};

/* table of 'mapped' config items read from file, e.g. {{'i', "eth0", {'o', "1234"}} */
struct config_option_t g_config_file_options[200];


char find_opt_letter( char *option ) {
	struct config_map_t *c = cfg_opt_list;
	
	while (c->cfg_item != NULL) {
		if (strcmp( option, c->cfg_item) == 0) {
			/* printf("~~~~ %c ~~~~\n", c->opt_letter); */
			return c->opt_letter;
		}
		c++;
	}
	return '\0';
}

char ** read_options_file( FILE *file ) {

	char line[2000];
	char *pos = NULL;
	int  llen = 0;
	struct config_option_t *cfg_ptr = g_config_file_options;
	
	while (NULL != fgets(line, sizeof(line), file)) {

		/* cut off any in-line comments */
		{
			char *hpos = strchr(line, '#');
			if (hpos != NULL) {
				hpos[0] = '\0';
			}
			if (line[0]=='\0') continue; /* optimization for comment-only lines */
		}

		/* do an rtrim and on the remaining 'line' */
		llen = strlen(line);
		pos = line + llen - 1;
		while (pos>=line && (*pos==' ' || *pos=='\t' || *pos=='\n' || *pos=='\r')) {
			pos--;
		}
		pos[1] = '\0';

		/* do an ltrim and on 'line' */
		pos = line;
		while (*pos==' ' || *pos=='\t') {
			pos++;
		}

		/* skip lines that are empty after trim */
		if (pos[0]=='\0') {
			continue;
		}

		char heading[100+1];

		/* check for [section headings] */
		if (pos[0]=='[') {
			sscanf(pos+1, "%[^]]]", heading);
			make_lower(heading);
			continue;
		}

		/* check if we have a 'key = value' pair or just a flag ( 'enable_xyz' ) */
		{
			char *pos2 = strchr(pos, '=');
			char key[100+1], value[100+1], fullkey[200];
			char letter;
			if (pos2 != NULL) {  /* key-value feature */
				pos2[0] = '\0';
				sscanf(pos,    "%s", key);
				sscanf(pos2+1, "%s", value);
				make_lower(key);
				/* printf( "%s.%s = '%s'\n", heading, key, value ); */
			} else { /* found feature flag */
				sscanf(pos, "%s", key);
				value[0] = '\0';
				make_lower(key);
				/* printf( "%s.%s = TRUE\n", heading, key ); */
			}

			sprintf( fullkey, "%s.%s", heading, key );
			letter = find_opt_letter(fullkey);
			
			if (letter != '\0') {
				/* we have read a config option from file for which a config letter exists */
				cfg_ptr->opt_letter = letter;
				cfg_ptr->value = strdup(value);
				cfg_ptr++;
			}
		}

	}

	cfg_ptr->opt_letter = '\0';
	cfg_ptr->value = NULL;
	
	return NULL;
}


/**
 * Process command line arguments
 */
void parse_cmdline(int argc, char **argv) {

	options_t* options = &g_options;
	int c;
    #ifdef PFRING
	char par[] = "c:hv::nyua:J:K:i:I:o:r:t:f:F:m:M:s:S:F:e:P:C:l:L:G:N:p:d:D:";
    #else
	char par[] = "c:hv::nyuJ:K:i:I:o:r:t:f:F:m:M:s:S:F:e:P:C:l:L:G:N:p:d:D:";
    #endif
	errno = 0;

	options->number_interfaces = 0;
    #ifdef PFRING
	options->rules_in_list = 0;
	options->filter_policy = -1;
    #endif

	/* check if we have a config file given at first */
	while (-1 != (c = getopt(argc, argv, par))) {
		if (c == 'c') { 
			FILE *cfile = fopen(optarg, "rt");
			if (!cfile) {
				char err_string[500];
				snprintf(err_string, sizeof(err_string)-1, "cannot open config file '%s'", optarg);
				perror(err_string);
				exit(1);
			}
			read_options_file(cfile);
			fclose(cfile);
		}
	}	    

	struct config_option_t *cfg_ptr;

/*
	cfg_ptr = g_config_file_options;
	while (cfg_ptr->opt_letter != '\0') {
		printf("FOUND '%c' -> \"%s\"\n", cfg_ptr->opt_letter, cfg_ptr->value);
		cfg_ptr++;
	}
*/
	cfg_ptr = g_config_file_options;

	optind = 1; /* reset getopt to start of parameter list ; from unistd.h */
	while ( (cfg_ptr->opt_letter != '\0') || (-1 != (c = getopt(argc, argv, par)))) {
		
		if (cfg_ptr->opt_letter != '\0') {
			c = cfg_ptr->opt_letter;
			optarg = cfg_ptr->value;
			cfg_ptr++;
		}
		
		switch (c) {
        #ifdef PFRING
		case 'a':
			/* pf_ring filter */
			parse_pfring_filter(optarg, options);
			break;
        #endif
		case 'c': /* config file */
			/* ignore config file parameter in this second pass over args */
			break;
		case 'C':
			/* collector port */
			strcpy(options->collectorIP, optarg);
			break;
		case 'e': /* export flush count */
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
				fprintf( stderr, "specify at most %d interfaces with -i\n", MAX_INTERFACES);
				break;
			}
			if (':' != optarg[1]) {
				fprintf( stderr, "specify interface type with -i\n");
				fprintf( stderr, "use [i,f,p,s,u]: as prefix - see help\n");
				fprintf( stderr, "for compatibility reason, assume ethernet as 'i:' is given!\n");
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
					LOGGER_fatal( "unknown interface type with -i");
					LOGGER_fatal( "use [i,f,p,s,u]: as prefix - see help");
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
		case 'G':
			options->export_location_interval = atof(optarg);
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
				LOGGER_fatal( "Invalid -P argument!");
				exit(1);
			}
			break;
		case 'v':
         if( (NULL != optarg) && (isdigit(*optarg)) ) {
            options->verbosity = atoi(optarg);
         }
         else {
            ++options->verbosity;
            // workaround to use -v as normal (e.g. -vvv) which do not work
            // with optional parameter
            if( NULL != optarg ) {
               while( 'v' == optarg[0] ) {
                  ++options->verbosity;
                  ++optarg;
               }
               options->verbosity_filter_string = optarg;
            }
            //fprintf( stderr, "filter string: '%s'\n", options->verbosity_filter_string);
         }
			break;
		case 'd':
			options->s_probe_name = optarg;
			break;
		case 'D':
			options->s_location_name = optarg;
			break;
		case 'l':{
			char* tok = strtok(optarg, ":");
			if( NULL != tok ) {
				options->s_latitude = tok;
				tok = strtok(NULL, ":");
				if( NULL != tok ) {
					options->s_longitude = tok;
					tok = strtok(NULL, ":");
					if( NULL != tok && isdigit(*tok) ) {
						options->export_location_interval = atof(tok);
					}
				}
			}
		}break;
		case 'L':{
			char* tok = strtok(optarg, ":");
			if( NULL != tok ) {
				options->s_longitude = tok;
				tok = strtok(NULL, ":");
				if( NULL != tok ) {
					options->s_latitude = tok;
					tok = strtok(NULL, ":");
					if( NULL != tok && isdigit(*tok) ) {
						options->export_location_interval = atof(tok);
					}
				}
			}
		}break;
		case 'N':
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

#ifdef PFRING
void open_pfring(device_dev_t* if_dev, options_t *options) {
	LOGGER_fatal( "selected PF_RING");
	LOGGER_fatal( "device_name: %s", if_dev->device_name);
	if_dev->device_handle.pfring = pfring_open(if_dev->device_name, 1,
			options->snapLength, 0);
	if (NULL == if_dev->device_handle.pfring) {
		LOGGER_fatal( "Failed to set up PF_RING-device");
		exit(1);
	}

	if_dev->IPv4address = getIPv4AddressFromDevice(if_dev->device_name);
	LOGGER_fatal( "Device %s has IP %s", if_dev->device_name, htoa(
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
		LOGGER_fatal( "Parameter are NULL!");
		return;
	}

	switch (if_device->device_type) {
    #ifndef PFRING
	// file as interface to listen
	case TYPE_FILE:
		LOGGER_fatal( "open_file(): not yet implemented!");
		break;

	case TYPE_PCAP_FILE:
		open_pcap_file(if_device, options);
		break;

	case TYPE_PCAP:
		open_pcap(if_device, options);
		break;

	case TYPE_SOCKET_INET:
      // TODO: remove if test is over
		LOGGER_fatal( "open_socket_inet(): TESTING!!");
		open_socket_inet(if_device, options);
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
		LOGGER_fatal( "not yet implemented!");
		break;
	}

	/* set initial export time to 'now' */
	gettimeofday(&(if_device->last_export_time), NULL);

	return;
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
	LOGGER_info( "set_defaults() okay");

	// parse commandline; set global parameter options
	parse_cmdline(argc, argv);
	LOGGER_info( "parse_cmdline() okay");

	logger_set_level(g_options.verbosity);
	logger_set_filter(g_options.verbosity_filter_string);

	if (g_options.number_interfaces == 0) {
		print_help();
		exit(-1);
	}

	// set probe name to host name if not set
	if( NULL == g_options.s_probe_name )
	{
		g_options.s_probe_name = (char*) malloc(64);
		if( gethostname( g_options.s_probe_name
				, sizeof(g_options.s_probe_name)) ) {
			g_options.s_probe_name = "";
		}
	}

	// init ipfix module
	libipfix_init();

	for (i = 0; i < g_options.number_interfaces; ++i) {
		set_defaults_device( &if_devices[i] );

		// open pcap interfaces with filter
		open_device(&if_devices[i], &g_options);
		LOGGER_info( "open_device(%d)", i);

		// setup ipfix_exporter for each device
		libipfix_open(&if_devices[i], &g_options);
		LOGGER_info( "open_ipfix_export(%d)", i);
	}

	// set ipAddress with ipaddress of first device
	g_options.ipAddress = if_devices[0].IPv4address;

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

