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
#include <string.h>
#include <ctype.h>
#include <unistd.h> // gethostname()
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
#include <sys/param.h>
//#include <sys/sysinfo.h> /* TODO review: sysinfo is Linux only */
#include <sys/times.h>

#include <netinet/in.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "main.h"

//// event loop
#include "ev_handler.h" // -> #include <ev.h>

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
 * Shutdown impd4e
 */
void impd4e_shutdown() {
   LOGGER_info("Shutting down..");
   ipfix_export_flush( ipfix() );
   ipfix_close( ipfix() );
   ipfix_cleanup();
}


#ifdef PFRING
void open_pfring(device_dev_t* if_dev, options_t *options) {
   LOGGER_fatal( "selected PF_RING");
   LOGGER_fatal( "device_name: %s", if_dev->device_name);
   pfring* pfring = NULL;
   pfring = pfring_open(if_dev->device_name, 1, options->snapLength, 0);
   if (NULL == pfring) {
      LOGGER_fatal( "Failed to set up PF_RING-device");
      exit(1);
   }

   if_dev->device_handle.pfring = pfring;
   if_dev->dh.pfring = pfring;
   if_dev->dispatch = pfring_dispatch_wrapper;

   if_dev->IPv4address = getIPv4AddressFromDevice(if_dev->device_name);
   LOGGER_fatal( "Device %s has IP %s", if_dev->device_name, htoa(
         if_dev->IPv4address));

   // pfring only supports ethernet
   if_dev->link_type  = DLT_EN10MB;
   if_dev->pkt_offset = 14;

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

   /* 
      copy command line parameters in order not to destroy the
      original parameters during later use of strtok on them
   */
   for( i=0; i<argc; i++ )
      argv[i] = strdup(argv[i]);
 
   // initializing custom logger
   logger_init(LOGGER_LEVEL_WARN);

   // set defaults options
   set_defaults_options(&g_options);
   LOGGER_info( "set_defaults() okay");

   // parse commandline; set global parameter options
   // see settings.c
   parse_cmdline_v2(argc, argv);
   //parse_cmdline(argc, argv);
   LOGGER_info( "parse_cmdline() okay");

   logger_set_level(g_options.verbosity);
   logger_set_filter(g_options.verbosity_filter_string);

   // set probe name to host name if not set
   if( NULL == g_options.s_probe_name )
   {
      g_options.s_probe_name = (char*) malloc(MAXHOSTNAMELEN);
      if( gethostname( g_options.s_probe_name
            , sizeof(g_options.s_probe_name)) ) {
         g_options.s_probe_name = "";
      }
   }

   // open devices if given via command line
   if( 0 < g_options.number_interfaces ) {
      for (i = 0; i < g_options.number_interfaces; ++i) {
         // open pcap interfaces with filter
         open_device(&if_devices[i], &g_options);
         LOGGER_info( "open_device(%d)", i);
      }

      // TODO: get ip address of the system
      // set ipAddress with ipaddress of first device
      g_options.ipAddress = if_devices[0].IPv4address;

      // determine observation id if it is not given via cmd line
      // use observationDomainID if explicitely given via
      // cmd line, else use interface IPv4address as oid
      // TODO: alternative oID instead of IP address --> !!different device types!!
      if( 0 == g_options.observationDomainID ) {
         // there is only one observation id needed
         // if non is given via cmd line: use g_options.ipAddress
         // which is detemined of the first device
         g_options.observationDomainID = ntohl( g_options.ipAddress );
      }
   }

   // setup ipfix_exporter
   libipfix_init( g_options.observationDomainID );
   libipfix_register_templates();
   libipfix_connect( &g_options );
   LOGGER_info( "Setup IPFIX Exporter" );

   /* ---- main event loop  ---- */
   event_loop( EV_DEFAULT ); // TODO: refactoring?

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

