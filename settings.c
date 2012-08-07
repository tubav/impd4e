/**
 * @file settings.c
 * 
 * impd4e - configuration and getter/setter functions
 * 
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
 * Robert Wuttke <flash@jpod.cc>
 * Ramon Masek <ramon.masek@fokus.fraunhofer.de>
 * Christian Henke <c.henke@tu-berlin.de>
 * Carsten Schmoll <carsten.schmoll@fokus.fraunhofer.de>
 *
 * For questions/comments contact packettracking@fokus.fraunhofer.de
 *
 *
 * Code within #ifdef verbose [..] #endif:
 *                                   (c) 2005-10 - Luca Deri <deri@ntop.org>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
//#include <stdint.h>
#include <unistd.h> // getopt()
#include <netdb.h> // AF_INET

//#ifndef PFRING
//#include <pcap.h>
//#endif

//#ifdef PFRING
//#include <netinet/ip.h>
//#include <net/ethernet.h>     /* the L2 protocols */
//#include <pf_plugin_impd4e.h>
//#endif

#include "version.h"
#include "logger.h"
#include "settings.h"
#include "hash.h"
#include "helper.h"
#include "ipfix_handler.h"

#ifdef PFRING
#include "pfring_filter.h"
#include <pf_plugin_impd4e.h>
#endif


// -----------------------------------------------------------------------------
// Global Variables
// -----------------------------------------------------------------------------
options_t g_options;

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------
char ** read_options_file( FILE *file );
char ** read_options_file_v2( FILE *file, options_t* options );

// -----------------------------------------------------------------------------
// Structures, Typedefs
// -----------------------------------------------------------------------------
/* 'mapped' config item read from file, e.g. {'i', "eth0"} */
struct config_option_t {
   char opt_letter;
   char *value;
};

/* table of 'mapped' config items read from file, e.g. {{'i', "eth0", {'o', "1234"}} */
struct config_option_t g_config_file_options[200];

typedef int (*cmd_par_fct_t)(char*, options_t*);

struct config_map_t {
   char          opt_letter;
   char*         opt_need_param;
   cmd_par_fct_t opt_fct;
   char*         cfg_item;
};


// -----------------------------------------------------------------------------
// Functions
// -----------------------------------------------------------------------------

/**
 * return a pointer to the global options variable
 * returns: pointer g_options
 */
options_t* getOptions() {
   return &g_options;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_lowerbound(options_t *options, char* s) {
  errno = 0;
  long long int value = strtoll(s, NULL, 0);

  if ( UINT32_MAX < value )
  {
    LOGGER_warn("selection range minimum 'out of range (UINT32_MAX)' used to be (uint32_t)");
    options->sel_range_min = UINT32_MAX;
  }
  else if ( 0 > value )
  {
    LOGGER_warn("selection range minimum 'out of range (ZERO)' used to be (uint32_t)");
    options->sel_range_min = 0;
  }
  else
  {
    options->sel_range_min = (uint32_t) value;
  }
  LOGGER_debug("selection range (lowerbound): %#08x (%d)", options->sel_range_min, options->sel_range_min);

  // check if upper bound is greater than lowerbound
  if(options->sel_range_max < options->sel_range_min)
  {
    LOGGER_warn( "lower bound (%#08x) > upper bound (%#08x); adjust upper bound"
               , options->sel_range_min
          , options->sel_range_max );
    options->sel_range_max = options->sel_range_min;
  }

  return options->sel_range_min;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_upperbound(options_t *options, char* s) {
  errno = 0;
  long long int value = strtoll(s, NULL, 0);

  if ( UINT32_MAX < value )
  {
    LOGGER_warn("selection range maximum 'out of range (UINT32_MAX)' used to be (uint32_t)");
    options->sel_range_max = UINT32_MAX;
  }
  else if ( 0 > value )
  {
    LOGGER_warn("selection range maximum 'out of range (ZERO)' used to be (uint32_t)");
    options->sel_range_max = 0;
  }
  else
  {
    options->sel_range_max = (uint32_t) value;
  }
  LOGGER_debug("selection range (uppperbound): %#08x (%d)", options->sel_range_max, options->sel_range_max);

  // check if upper bound is greater than lowerbound
  if(options->sel_range_max < options->sel_range_min)
  {
    LOGGER_warn( "lower bound (%#08x) > upper bound (%#08x); adjust lower bound"
               , options->sel_range_min
          , options->sel_range_max );
    options->sel_range_min = options->sel_range_max;
  }

  return options->sel_range_max;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_ratio(options_t *options, char* value) {
   double sampling_ratio = strtod( value, NULL);
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

// =============================================================================

/**
 * Parse command line template
 */
int parse_template(char *arg_string) {
   int k;
   struct templateDef {
      char *hstring;
      int templateID;
   } templates[] = {   { MIN_NAME, MINT_ID }   
                     , { TS_ID_EPC, TS_ID_EPC_ID }
                     , { TS_TTL_RROTO_NAME, TS_TTL_PROTO_ID }
                     , { TS_TTL_RROTO_IP_NAME, TS_TTL_PROTO_IP_ID }
                     , { TS_NAME, TS_ID } 
                     , { TS_OPEN_EPC, TS_OPEN_EPC_ID }};

   // remove any leading whitespaces
   while( isspace(*arg_string) ) ++arg_string;

   for (k = 0; k < (sizeof(templates) / sizeof(struct templateDef)); k++) {
      if ( 0== strcasecmp(arg_string, templates[k].hstring) ) {
          return templates[k].templateID;
      }
   }
   return -1;
}

// =============================================================================

/**
 * Parse command line selection function
 */
void parseSelFunction(char *arg_string, options_t *options) {
   int k;
   struct selfunction {
      char *hstring;
      selectionFunction selfunction;
   } selfunctions[] = {   { HASH_INPUT_REC8,   copyFields_Rec }
                        , { HASH_INPUT_IP,     copyFields_Only_Net }
                        , { HASH_INPUT_IPTP,   copyFields_U_TCP_and_Net }
                        , { HASH_INPUT_PACKET, copyFields_Packet }
                        , { HASH_INPUT_RAW,    copyFields_Raw }
                        , { HASH_INPUT_LAST,   copyFields_Last }
                        , { HASH_INPUT_LINK,   copyFields_Link }
                        , { HASH_INPUT_NET,    copyFields_Net }
                        , { HASH_INPUT_TRANS,  copyFields_Trans }
                        , { HASH_INPUT_PAYLOAD,copyFields_Payload }
                        , { HASH_INPUT_SELECT, copyFields_Raw } };

   for (k = 0; k < (sizeof(selfunctions) / sizeof(struct selfunction)); k++) {
      if (strncasecmp(arg_string, selfunctions[k].hstring
            , strlen(selfunctions[k].hstring)) == 0)
      {
         options->selection_function = selfunctions[k].selfunction;

         // needed for RAW, LINK, NET, TRANS, PAYLOAD
         // set in hash.c
         parseRange( arg_string+strlen(selfunctions[k].hstring) );
      }
   }
}

// =============================================================================

/**
 * Parse command line hash function
 */
hashFunction parseFunction(char *arg_string) {
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
         LOGGER_info("using %s as hashFunction", hashfunctions[k].hstring);
      }
   }
   return hashfunctions[j].function;
}

// =============================================================================
/**
 * Print out command usage
 */
void print_version_information() {
#ifdef HAVE_CONFIG_H
   printf( "version:       " PACKAGE_VERSION "\n");
   printf( "build version: " BUILD_VERSION "\n");
   printf( "build date:    " BUILD_DATE "\n");
   if (strlen(GIT_BRANCH)>0)
      printf( "git branch:    " GIT_BRANCH "\n");
   if (strlen(GIT_HASH)>0)
      printf( "git version:   " GIT_HASH "\n");
#else
#endif
}

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
                        "                                  (parameters have precedence by order of the same parameters \n"
                        "                                  (last comes last serves), or are supplemental, e.g. for -i)\n"
                        "                                  (config file at last will overwrite cmd line (vice versa))\n"
                        "\n"
            #ifndef PFRING
			"   -i  <i,f,p,s,u>:<interface>    interface(s) to listen on. It can be used multiple times.\n"
			"\t i - ethernet adapter;             -i i:eth0\n"
			"\t p - pcap file;                    -i p:traffic.pcap\n"
			"\t f - plain text file;              -i f:data.txt\n"
			"\t s - inet udp socket (AF_INET);    -i s:192.168.0.42:4711\n"
			"\t u - unix domain socket (AF_UNIX); -i u:/tmp/socket.AF_UNIX\n"
			#else
			"   -i  <r>:<interface>    interface(s) to listen on. It can be used multiple times.\n"
			"\t r - ethernet adapter using pfring;-i r:eth0\n"
			#endif
			"\n"
			"   -4                             use IPv4 socket interfaces\n"
			"   -6                             use IPv6 socket interfaces (default)\n"
			"\n"
			"options: \n"
            #ifdef PFRING
			"   -a <filter keyword>:<value>    Filtering if using PF_RING\n"
			"\t\t\t\t  Specify an packet filter and/or the default\n"
			"\t\t\t\t  filtering policy (valid for all filters).\n"
			"\t\t\t\t  It can be used multiple times.\n"
            #endif // PFRING
			"   -C  <Collector IP>             an IPFIX collector address\n"
			"                                  Default: localhost\n"
			"   -d <probe name>                a probe name\n"
			"                                  Default: <hostname>\n"
			"   -D <location name>             a location name\n"
			"   -e  <export packet count>      size of export buffer after which packets\n"
						"                                  are flushed (per device)\n"
			#ifndef PFRING
			"   -f  <bpf>                      Berkeley Packet Filter expression (e.g. tcp udp icmp)\n"
			"\n"
           #endif
			"   -F  <hash_function>            hash function to use:\n"
			"                                  \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\"\n"
			"\n"
			"   -G  <interval>                 location export interval in seconds. \n"
			"                                  Use -G 0 for exporting once at startup.\n"
			"                                  Default: 60.0 \n"
			"\n"
			"   -I  <interval>                 pktid export interval in sec. (Default: 3.0)\n"
			"                                  Use -I 0 for disabling this export.\n"
			"\n"
			"   -J  <interval>                 probe stats export interval in sec (Default: 30.0).\n"
			"                                  Use -J 0 for disabling this export.\n"
			"\n"
			"   -K  <interval>                 interface stats export interval in sec (Default: 10.0). \n"
			"                                  Use -K 0 for disabling this export.\n"
			"\n"
			"   -l <latitude>                  geo location (double): latitude\n"
			"   -l <lat>:<long>:<interval>     short form\n"
			"   -L <longitude>                 geo location (double): longitude\n"
			"   -L <long>:<lat>:<interval>     short form\n"
			"\n"
			"   -m  <minimum selection range>  integer - do not use in conjunction with -r \n"
			"   -M  <maximum selection range>  integer - do not use in conjunction with -r \n"
			"\n"
			"   -N  <snaplength>               max capturing size in bytes (Default: 80) \n"
			"\n"
			"   -o  <observation domain id>    unique identifier for probe \n"
			"                                  Default: IP address of the interface\n"
			"\n"
			"   -O <offset>                    offset in bytes pointing to the start of the packet \n"
			"                                  used for tunneled or crooked packets\n"
			"                                  !!! the offset is applied after the link layer (e.g. ethernet header)\n"
			"   -p  <hash function>            use different hash_function for packetID generation:\n"
			"                                  \"BOB\", \"OAAT\", \"TWMX\", \"HSIEH\" \n"
			"\n"
			"   -P  <Collector Port>           an IPFIX Collector Port\n"
			"                                  Default: 4739\n"
			"   -r  <sampling ratio>           in %% (double)\n"
			"\n"
			"   -s  <selection function>       which parts of the packet used for hashing (presets)\n"
			"                                  either: \"IP+TP\", \"IP\", \"REC8\", \"PACKET\"\n"
			"                                  Default: \"IP+TP\"\n"
			"   -S  <selection function>       which parts of the packet used for hashing (byte selection)\n"
			"                                  <keyword><offset list>\n"
			"                                  keywords: \"RAW\", \"LAST\", \"LINK\", \"NET\", \"TRANS\", \"PAYLOAD\"\n"
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
			"   -t  <template>                 either \"min\" or \"lp\" or \"ts\" or \"ls\"\n"
			"                                  Default: \"min\"\n"
			"   -u                             use only one oid from the first interface \n"
			"\n"
			"   -v[expression]                 verbose-level; use multiple times to increase output \n"
			"                                  filter by function names in comma-separated list at a certain \n"
			"                                  log level\n"
			"                                  * matches anything; can be combined at start/end of expressions\n"
			"                                  - exclude expression\n"
			"                                  Example: '-vv*,-main' matches anything but main-function (level 2)\n"
			"                                  Example: '-vvv*export*,-*flush, \n"
			"                                           matches all functions containing export, but not ending of flush\n"
			"                                  (PS: for all verbosity output this parameter must be the first)\n"
			"\n"
			"   -h                             print this help \n"
			"   -V                             print version information \n"
			"\n"
			"EXAMPLES for usage: \n"
			"sudo impd4e -i i:eth0 -C 172.20.0.1 -r 1 -t min \n"
			"sudo impd4e -i i:lo   -C 172.20.0.1 -o <id> -S 20,34-45\n");

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


// =============================================================================
// =============================================================================
// config file parsing
// =============================================================================

void make_lower(char *s) {
   if (!s) return;
   while (*s) {
      *s = tolower(*s);
      s++;
   }
}

bool check_file_name( char* arg ) {
   //TODO: need implementation
   return true;
}

int opt_unknown_parameter( char* arg, options_t* options ) {
//   LOGGER_warn( "unkown parameter" );
   LOGGER_info("[CONF] unknown parameter");
   return -1;
}

#ifdef PFRING
int opt_a( char* arg, options_t* options ) {
   parse_pfring_filter(arg, options);
   return 0;
}
#endif

int opt_c( char* arg, options_t* options ) {
   // TODO: prevent cascading config files to loop

   if( check_file_name( arg ) ) {
      // TODO: create template file
      //if( "create_template" == arg ) {
      //   create_template_config_file( arg );
      //}
      //else {
         FILE *cfile = fopen(arg, "rt");
         if (!cfile) {
            char err_string[500];
            snprintf(err_string, sizeof(err_string)-1, "cannot open config file '%s'", arg);
            perror(err_string);
            exit(1);
         }
         LOGGER_info("[CONF] read configuration file: %s ", arg);
         read_options_file_v2(cfile, options);
         fclose(cfile);
      //}
   }
   return 0;
}

int opt_C( char* arg, options_t* options ) {
   strcpy(options->collectorIP, arg);
   return 0;
}

int opt_e( char* arg, options_t* options ) {
   options->export_packet_count = atoi(arg);
   return 0;
}

int opt_f( char* arg, options_t* options ) {
   options->bpf = arg;
   return 0;
}

int opt_h( char* arg, options_t* options ) {
   print_help();
   exit(0);
   return 0;
}

int opt_i( char* arg, options_t* options ) {
   uint8_t if_idx = options->number_interfaces; // shorter for better reading
   if (MAX_INTERFACES == options->number_interfaces) {
      fprintf( stderr, "specify at most %d interfaces with -i\n", MAX_INTERFACES);
   }
   else {
      set_defaults_device( &if_devices[if_idx] );

      if (':' != arg[1]) {
         fprintf( stderr, "specify interface type with -i\n");
         fprintf( stderr, "use [i,f,p,s,u]: as prefix - see help\n");
         fprintf( stderr, "for compatibility reason, assume ethernet as 'i:' is given!\n");
         if_devices[if_idx].device_type = TYPE_PCAP;
         if_devices[if_idx].device_name = arg;
      }
      else {
         switch (arg[0]) {
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
         if_devices[if_idx].device_name = arg+2;
      }
      // increment the number of interfaces
      ++options->number_interfaces;
   }
   return 0;
}

int opt_I( char* arg, options_t* options ) {
   options->export_pktid_interval = atof(arg);
   return 0;
}

int opt_J( char* arg, options_t* options ) {
   options->export_stats_interval = atof(arg);
   return 0;
}

int opt_K( char* arg, options_t* options ) {
   options->export_sampling_interval = atof(arg);
   return 0;
}

int opt_G( char* arg, options_t* options ) {
   options->export_location_interval = atof(arg);
   return 0;
}


int opt_o( char* arg, options_t* options ) {
   options->observationDomainID = atoi(arg);
   return 0;
}

int opt_O( char* arg, options_t* options ) {
   options->offset = atoi(arg);
   return 0;
}

int opt_t( char* arg, options_t* options ) {
   static uint32_t t_idx = 0;

   uint32_t tid = parse_template(arg);
   options->templateID = (-1==tid)?options->templateID:tid;
   if (MAX_INTERFACES == t_idx) {
      fprintf( stderr, "specify at most %d templates with -t\n", MAX_INTERFACES);
   }
   else {
      if_devices[t_idx].template_id = tid;
      LOGGER_debug("template %2d: [%d]", t_idx, if_devices[t_idx].template_id);
      ++t_idx;
   }
   return 0;
}

int opt_4( char* arg, options_t* options ) {
   options->ai_family = AF_INET;
   LOGGER_debug("ai_family [%d]", options->ai_family);
   return 0;
}

int opt_6( char* arg, options_t* options ) {
   options->ai_family = AF_INET6;
   LOGGER_debug("ai_family [%d]", options->ai_family);
   return 0;
}

int opt_m( char* arg, options_t* options ) {
   set_sampling_lowerbound(options, arg);
   return 0;
}

int opt_M( char* arg, options_t* options ) {
   set_sampling_upperbound(options, arg);
   return 0;
}

int opt_r( char* arg, options_t* options ) {
   set_sampling_ratio(options, arg);
   return 0;
}

int opt_S( char* arg, options_t* options ) {
   parseSelFunction(arg, options);
   return 0;
}
inline int opt_s( char* arg, options_t* options ) {
   return opt_S(arg, options);
}

int opt_F( char* arg, options_t* options ) {
   options->hash_function = parseFunction(arg);
   return 0;
}

int opt_p( char* arg, options_t* options ) {
   options->pktid_function = parseFunction(arg);
   options->hashAsPacketID = 0;
   return 0;
}

int opt_P( char* arg, options_t* options ) {
   if ((options->collectorPort = atoi(arg)) < 0) {
      LOGGER_fatal( "Invalid -P argument!");
      exit(1);
   }
   return 0;
}

int opt_v( char* arg, options_t* options ) {
   if( (NULL != arg) && (isdigit(*arg)) ) {
      options->verbosity = atoi(arg);
   }
   else {
      ++options->verbosity;
      // workaround to use -v as normal (e.g. -vvv) which do not work
      // with optional parameter
      if( NULL != arg ) {
         while( 'v' == arg[0] ) {
            ++options->verbosity;
            ++arg;
         }
         options->verbosity_filter_string = arg;
      }
      //fprintf( stderr, "filter string: '%s'\n", options->verbosity_filter_string);
   }

   // set log level directly during evaluation
   logger_set_level(options->verbosity);
   logger_set_filter(options->verbosity_filter_string);

   return 0;
}

int opt_V() {
   print_version_information();
   exit(0);
}

int opt_d( char* arg, options_t* options ) {
   options->s_probe_name = arg;
   return 0;
}

int opt_D( char* arg, options_t* options ) {
   options->s_location_name = arg;
   return 0;
}

int opt_l( char* arg, options_t* options ) {
   char* tok = strtok(arg, ":");
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
   return 0;
}

int opt_L( char* arg, options_t* options ) {
   char* tok = strtok(arg, ":");
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
   return 0;
}

int opt_N( char* arg, options_t* options ) {
   options->snapLength = atoi(arg);
   return 0;
}

int opt_u( char* arg, options_t* options ) {
   options->use_oid_first_interface=1;
   return 0;
}

int opt_n( char* arg, options_t* options ) {
   // TODO parse enable export sampling
   return 0;
}

int opt_X( char* arg, options_t* options ) {
   // hash the given value with the selectet hash-function

   buffer_t b;
   b.ptr = (uint8_t*) arg;
   b.len = strlen(arg);
   b.size = b.len;
   int hash = options->hash_function(&b);
   printf( "hash=%04x for '%s'\n", hash, b.ptr);

   exit(0);
}

int opt_y( char* arg, options_t* options ) {
   // TODO
   //			options->export_sysinfo = true;
   return 0;
}

#define ADD_OPTION( opt, full_opt ) { '##opt##', &##opt_##opt, full_opt }

// parameter list for get opt
// "c:hv::nyuJ:K:i:I:o:r:t:f:F:m:M:s:S:F:e:P:C:l:L:G:N:p:d:D:O:46";
struct config_map_t cfg_opt_list[] = {
	{ 'v',"::", &opt_v, "general.verbosity"              },
	{ 'V',""  , &opt_V, ""},
	{ 'h',""  , &opt_h, "general.help"                   },
	{ 'i',":" , &opt_i, "capture.interface"              },
	{ '4',""  , &opt_4, "capture.ipv4"                   },
	{ '6',""  , &opt_6, "capture.ipv6"                   },
	{ 'O',":" , &opt_O, "capture.offset"                 },
	{ 'f',":" , &opt_f, "filter.bpfilter"                },
	{ 'N',":" , &opt_N, "filter.snaplength"              },
	{ 'I',":" , &opt_I, "interval.data_export"           },
	{ 'J',":" , &opt_J, "interval.probe_stats"           },
	{ 'K',":" , &opt_K, "interval.interface_stats"       },
	{ 'G',":" , &opt_G, "interval.location"              },
	{ 'm',":" , &opt_m, "selection.min_hash_range"       },
	{ 'M',":" , &opt_M, "selection.max_hash_range"       },
	{ 'r',":" , &opt_r, "selection.hash_selection_ratio" },
	{ 's',":" , &opt_s, "selection.selection_preset"     },
	{ 'S',":" , &opt_S, "selection.selection_parts"      },
	{ 'F',":" , &opt_F, "selection.hash_function"        },
	{ 'p',":" , &opt_p, "selection.pktid_function"       },
	{ 'o',":" , &opt_o, "ipfix.observation_domain_id"    },
	{ 'u',""  , &opt_u, "ipfix.one_odid"                 },
	{ 'C',":" , &opt_C, "ipfix.collector_ip_address"     },
	{ 'P',":" , &opt_P, "ipfix.collector_port"           },
	{ 'e',":" , &opt_e, "ipfix.export_flush_count"       },
	{ 't',":" , &opt_t, "template.used_template"         },
	{ 'd',":" , &opt_d, "geotags.probe_name"             },
	{ 'D',":" , &opt_D, "geotags.location_name"          },
	{ 'l',":" , &opt_l, "geotags.latitude"               },
	{ 'L',":" , &opt_L, "geotags.longitude"              },
	{ 'c',":" , &opt_c, "general.configfile" }, // TODO:something
	{ 'n',""  , &opt_n, "" },
	{ 'X',":" , &opt_X, "" },
	{ 'y',""  , &opt_y, "" },
#ifdef PFRING
	{ 'a',":" , &opt_a, "" },
#endif
//	{ '\0', NULL, NULL }
};

cmd_par_fct_t find_opt_function_char( const char c ) {
   int size = sizeof(cfg_opt_list) / sizeof(struct config_map_t);
   int i    = 0;

   for (i = 0; i < size; ++i) {
      if( c == cfg_opt_list[i].opt_letter ) {
         //printf("1~~~~ %c ~~~~\n", cfg_opt_list[i].opt_letter);
         return cfg_opt_list[i].opt_fct;
      }
   }
   return &opt_unknown_parameter;
}

cmd_par_fct_t find_opt_function_key( char* key ) {
   int size = sizeof(cfg_opt_list) / sizeof(struct config_map_t);
   int i    = 0;

   for (i = 0; i < size; ++i) {
      if( 0 == strcmp(key, cfg_opt_list[i].cfg_item) ) {
         //printf("2~~~~ %c ~~~~\n", cfg_opt_list[i].opt_letter);
         return cfg_opt_list[i].opt_fct;
      }
   }
   return &opt_unknown_parameter;
}

char find_opt_letter( char* key ) {
   int size = sizeof(cfg_opt_list) / sizeof(struct config_map_t);
   int i    = 0;

   for (i = 0; i < size; ++i) {
      if( 0 == strcmp(key, cfg_opt_list[i].cfg_item) ) {
         //printf("3~~~~ %c ~~~~\n", cfg_opt_list[i].opt_letter);
         return cfg_opt_list[i].opt_letter;
      }
   }

   return '\0';
}

void remove_comment( char* s ) {
   // character string is NULL terminated
   if( NULL != s) {
      while( '\0' != *s && '#' != *s ) ++s;
      *s = '\0';
   }
}

char ** read_options_file_v2( FILE *file, options_t* options ) {
   char line[2000];
   
   // process each line of config file
   while (NULL != fgets(line, sizeof(line), file)) {
      char heading[100+1];

      // print line for debugging
      //printf( "line: %s", line );

      // trim line of comments
      remove_comment( line );
      // trim trailing whitespaces
      r_trim( line );

      // skip empty lines
      if( 1 < strlen(line) )
      {
         /* check for [section headings] */
         if( 0 != sscanf(line, "[%[a-zA-Z0-9 _+-]]", heading) ) {
            make_lower( heading );
            //printf( "heading: %s\n", heading );
         }
         else {
            /* check if we have a 'key = value' pair or just a flag ( 'enable_xyz' ) */

            char  fullkey[200];

            char* key   = line;
            char* value = strchr( line, '=');

            // cut line at '=' and trim value of white-spaces
            if( NULL != value ) *(value++) = '\0';
            else value = "";
            value = l_trim( value );

            // trim key of white-spaces -> to lower case
            r_trim( key );
            key = l_trim(key);
            make_lower( key );

            // TODO: logger_DEBUG
            //printf( "%s.%s = '%s'\n", heading, key, value );

            sprintf( fullkey, "%s.%s", heading, key );
            // TODO: is strdup nessesary here
            if( 0 > find_opt_function_key(fullkey)( strdup(value), options) ) {
                LOGGER_info("[CONF] %s: %s (failed)", fullkey, value);
            }
            else  {
                LOGGER_info("[CONF] %s: %s (succeed)", fullkey, value);
            }
         }
      }
   }

   return NULL;
}

char ** read_options_file( FILE *file ) {
   char line[2000];
   //int  llen = 0;
   struct config_option_t *cfg_ptr = g_config_file_options;
   
   while (NULL != fgets(line, sizeof(line), file)) {
      char heading[100+1];

      // print line for debugging
      //printf( "line: %s", line );

      // trim line of comments
      remove_comment( line );
      // trim trailing whitespaces
      r_trim( line );

      // skip empty lines
      if( 1 < strlen(line) )
      {

         /* check for [section headings] */
         if( 0 != sscanf(line, "[%[a-zA-Z0-9 _+-]]", heading) ) {
            make_lower( heading );
            //printf( "heading: %s\n", heading );
         }
         else {
            /* check if we have a 'key = value' pair or just a flag ( 'enable_xyz' ) */

            char fullkey[200];
            char letter;

            char* key   = line;
            char* value = strchr( line, '=');

            // cut line at '=' and trim value of white-spaces
            if( NULL != value ) *(value++) = '\0';
            else value = "";
            value = l_trim( value );

            // trim key of white-spaces -> to lower case
            r_trim( key );
            key = l_trim(key);
            make_lower( key );

            // TODO: logger_DEBUG
            //printf( "%s.%s = '%s'\n", heading, key, value );

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
   }

   cfg_ptr->opt_letter = '\0';
   cfg_ptr->value = NULL;
   
   return NULL;
}

// =============================================================================
// =============================================================================

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

// ============================================================================
// ============================================================================

/**
 * Process command line arguments
 */
void parse_cmdline_v2(int argc, char **argv) {

   int  i;
   char c;

   // create parameter string from option array
   //char par[] = "c:hv::nyuJ:K:i:I:o:r:t:f:F:m:M:s:S:F:e:P:C:l:L:G:N:p:d:D:O:46";
   int  len = sizeof(cfg_opt_list)/sizeof(struct config_map_t);
   char par[3*len];
   char *tmp = par;

   for(i = 0; i < len; ++i) {
      // check double options in option list
      // only on debug level
      //if( LOGGER_LEVEL_DEBUG <= logger_get_level() ){
      //   if(NULL != strchr(par, cfg_opt_list[i].opt_letter)){
      //      LOGGER_warn( "option letter: '%c' already used", cfg_opt_list[i].opt_letter);
      //      printf( "option letter: '%c' already used\n", cfg_opt_list[i].opt_letter);
      //   }
      //}

      tmp += sprintf(tmp, "%c%s", cfg_opt_list[i].opt_letter, cfg_opt_list[i].opt_need_param );
   }
   //fprintf(stderr, "%s\n", par);

   while (-1 != (c = getopt(argc, argv, par))) {
      LOGGER_info("[CONF] set %c: %s", c, optarg);
      if( -1 == find_opt_function_char( c )(optarg, &g_options) ) {
         exit(-1);
      }
   }
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
          options->templateID = parse_template(optarg);
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
          //       options->export_sysinfo = true;
          break;
       default:
          printf("unknown parameter: %d \n", c);
          break;
       }
  
    }

}
// ============================================================================
// ============================================================================

/**
 * Set default options
 */
void set_defaults_options(options_t *options) {
	options->verbosity_filter_string = "";
	options->ai_family           = AF_INET6; // default IPv4
	options->verbosity           = 0;
	options->number_interfaces   = 0;
	options->offset              = 0;
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

   // set initial export packet count
   dev->packets_dropped = 0;
   dev->export_packet_count = 0;

   // allocate memory for outbuffer; depend on cmd line options
   // just for the real amount of interfaces used
   dev->hash_buffer.size = g_options.snapLength;
   dev->hash_buffer.ptr  = calloc( g_options.snapLength, sizeof(uint8_t) );
   dev->hash_buffer.len  = 0;

   dev->template_id      = -1;
}


// -----------------------------------------------------------------------------
// end of file
// -----------------------------------------------------------------------------

