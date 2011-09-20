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

#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef PFRING
#include <sys/time.h>
#include <time.h>
#endif

#include "ev_handler.h"
#include "socket_handler.h"
#include "logger.h"
#include "netcon.h"

//#include "templates.h"
#include "hash.h"
#include "ipfix.h"
#include "ipfix_def.h"
#include "ipfix_def_fokus.h"
#include "stats.h"

// Custom logger
#include "logger.h"
#include "netcon.h"
#include "ev_handler.h"

#include "helper.h"
#include "constants.h"

#include "settings.h"

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------*/
#define RESYNC_PERIOD 1.5 /* seconds */

/**
 * Event and Signal handling via libev
 */
struct {
   struct ev_loop *loop;
   ev_signal sigint_watcher;
   ev_signal sigalrm_watcher;
   ev_signal sigpipe_watcher;
   ev_timer export_timer_pkid;
   ev_timer export_timer_sampling;
   ev_timer export_timer_stats;
   ev_timer export_timer_location;
   ev_timer resync_timer;
   ev_io packet_watchers[MAX_INTERFACES];
} events;

#define CONFIG_FCT_SIZE 10
cfg_fct_t configuration_fct[CONFIG_FCT_SIZE];
int config_fct_length = 0;

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------
#ifndef PFRING
void handle_packet(u_char *user_args, const struct pcap_pkthdr *header,
      const u_char * packet);
#else
void packet_pfring_cb(u_char *user_args, const struct pfring_pkthdr *header,
        const u_char *packet);
#endif

void register_configuration_fct(char cmd, set_cfg_fct_t fct, const char* desc) {
   if (CONFIG_FCT_SIZE > config_fct_length) {
      configuration_fct[config_fct_length].cmd = cmd;
      configuration_fct[config_fct_length].fct = fct;
      configuration_fct[config_fct_length].desc = desc;
      configuration_fct[config_fct_length].desc_length = strlen(desc);
      ++config_fct_length;
   } else {
      LOGGER_warn(
            "configuration function table is full - check size - should not happen");
   }
}

// dummy function to prevent segmentation fault
int unknown_cmd_fct(unsigned long id, char* msg) {
   LOGGER_warn("unknown command received: id=%lu, msg=%s", id, msg);
   return NETCON_CMD_UNKNOWN;
}

set_cfg_fct_t getFunction(char cmd) {
   int i = 0;
   for (i = 0; i < config_fct_length; ++i) {
      if (cmd == configuration_fct[i].cmd) {
         return configuration_fct[i].fct;
      }
   }
   LOGGER_warn("unknown command received: cmd=%c", cmd);
   return unknown_cmd_fct;
}

/**
 * Call back for SIGINT (Ctrl-C).
 * It breaks all loops and leads to shutdown.
 */
void sigint_cb (EV_P_ ev_signal *w, int revents) {
   LOGGER_info("Signal INT received");
   ev_unloop (loop, EVUNLOOP_ALL);
}

/**
 * SIGPIPE call back, currently not used.
 */
void sigpipe_cb (EV_P_ ev_signal *w, int revents) {
   LOGGER_info("Ignoring SIGPIPE, libipfix should indefinitely try to reconnect to collector.");
}

/**
 * SIGALRM call back, currently not used.
 */
void sigalrm_cb (EV_P_ ev_signal *w, int revents) {
   LOGGER_info("Signal ALRM received");
}

/**
 * Setups and starts main event loop.
 */
void event_loop() {
   //   struct ev_loop *loop = ev_default_loop (EVLOOP_ONESHOT);
   struct ev_loop *loop = ev_default_loop(0);
   if (!loop) {
      LOGGER_fatal("Could not initialize loop!");
      exit(EXIT_FAILURE);
   }
   LOGGER_info("event_loop()");

   /*=== Setting up event loop ==*/

   /* signals */
   ev_signal_init(&events.sigint_watcher, sigint_cb, SIGINT);
   ev_signal_start(loop, &events.sigint_watcher);
   ev_signal_init(&events.sigalrm_watcher, sigalrm_cb, SIGALRM);
   ev_signal_start(loop, &events.sigalrm_watcher);
   ev_signal_init(&events.sigpipe_watcher, sigpipe_cb, SIGPIPE);
   ev_signal_start(loop, &events.sigpipe_watcher);

   /* resync   */
   ev_timer_init(&events.resync_timer, resync_timer_cb, 0, RESYNC_PERIOD);
   ev_timer_again(loop, &events.resync_timer);

   /* export timers */
   /* export device measurements */
   ev_timer_init(&events.export_timer_pkid, export_timer_pktid_cb //callback
         , 0 // after
         , g_options.export_pktid_interval // repeat
   );
   // trigger first after 'repeat'
   ev_timer_again(loop, &events.export_timer_pkid);

   /* export device sampling stats */
   ev_timer_init(&events.export_timer_sampling, export_timer_sampling_cb // callback
         , 0 // after, not used for ev_timer_again
         , g_options.export_sampling_interval // repeat
   );
   // trigger first after 'repeat'
   ev_timer_again(loop, &events.export_timer_sampling);

   /* export system stats - with at least one export*/
   ev_timer_init(&events.export_timer_stats, export_timer_stats_cb // callback
         , 0 // after
         , g_options.export_stats_interval // repeat
   );
   // trigger first after 'after' then after 'repeat'
   ev_timer_start(loop, &events.export_timer_stats);

   /* export system location - with at least one export*/
   ev_timer_init(&events.export_timer_location, export_timer_location_cb // callback
         , 0 // after
         , g_options.export_location_interval // repeat
   );
   // trigger first after 'after' then after 'repeat'
   ev_timer_start(loop, &events.export_timer_location);

   /*   packet watchers */
   event_setup_pcapdev(loop);

   /* setup network console */
   event_setup_netcon(loop);

   /* Enter main event loop; call unloop to exit.
    *
    * Everything is going to be handled within this call
    * accordingly to callbacks defined above.
    * */
   events.loop = loop;
   ev_loop(loop, 0);
}

/**
 * Setup network console
 */
void event_setup_netcon(struct ev_loop *loop) {
   char *host = "localhost";
   int port = 5000;

   if (netcon_init(loop, host, port) < 0) {
      LOGGER_error("could not initialize netcon: host: %s, port: %d ", host,
            port);
   }

   // register available configuration functions
   // to the config function array
   register_configuration_fct('?', configuration_help, "INFO: -? this help\n");
   register_configuration_fct('h', configuration_help, "INFO: -h this help\n");
   register_configuration_fct('r', configuration_set_ratio,
         "INFO: -r capturing ratio in %\n");
   register_configuration_fct('m', configuration_set_min_selection,
         "INFO: -m capturing selection range min (hex|int)\n");
   register_configuration_fct('M', configuration_set_max_selection,
         "INFO: -M capturing selection range max (hex|int)\n");
   register_configuration_fct('f', configuration_set_filter,
         "INFO: -f bpf filter expression\n");
   register_configuration_fct('t', configuration_set_template,
         "INFO: -t template (ts|min|lp)\n");
   register_configuration_fct('I', configuration_set_export_to_pktid,
         "INFO: -I pktid export interval (s)\n");
   register_configuration_fct('J', configuration_set_export_to_probestats,
         "INFO: -J porbe stats export interval (s)\n");
   register_configuration_fct('K', configuration_set_export_to_ifstats,
         "INFO: -K interface stats export interval (s)\n");

   // register runtime configuration callback to netcon
   netcon_register(runtime_configuration_cb);
}

/**
 * Here we setup a pcap device in non block mode and configure libev to read
 * a packet as soon it is available.
 */
void event_setup_pcapdev(struct ev_loop *loop) {
   int i;
   device_dev_t * pcap_dev_ptr;
   for (i = 0; i < g_options.number_interfaces; i++) {
      LOGGER_debug("Setting up interface: %s", if_devices[i].device_name);

      pcap_dev_ptr = &if_devices[i];
      // TODO review

#ifndef PFRING
      setNONBlocking(pcap_dev_ptr);
#endif

      /* storing a reference of packet device to
       be passed via watcher on a packet event so
       we know which device to read the packet from */
      // todo: review; where is the memory allocated
      events.packet_watchers[i].data = (device_dev_t *) pcap_dev_ptr;
      ev_io_init(&events.packet_watchers[i], packet_watcher_cb,
            get_file_desc(pcap_dev_ptr), EV_READ);
      ev_io_start(loop, &events.packet_watchers[i]);
   }
}

/**
 * Called whenever a new packet is available. Note that packet_pcap_cb is
 * responsible for reading the packet.
 */
void packet_watcher_cb(EV_P_ ev_io *w, int revents) {
   int error_number = 0;

   LOGGER_trace("Enter");

   // retrieve respective device a new packet was seen
   device_dev_t *pcap_dev_ptr = (device_dev_t *) w->data;

   switch (pcap_dev_ptr->device_type) {
      case TYPE_testtype:
#ifndef PFRING
      case TYPE_PCAP_FILE:
      case TYPE_PCAP: {
         // dispatch packet
         LOGGER_trace("pcap");
         if( 0 > (error_number = pcap_dispatch(pcap_dev_ptr->device_handle.pcap
                     , PCAP_DISPATCH_PACKET_COUNT
                     , handle_packet
                     , (u_char*) pcap_dev_ptr)) )
         {
            LOGGER_error( "Error DeviceNo   %s: %s"
                  , pcap_dev_ptr->device_name
                  , pcap_geterr( pcap_dev_ptr->device_handle.pcap) );
            LOGGER_error( "Error No.: %d", error_number );
            LOGGER_error( "Error No.: %d", errno );
            //exit(1);
         }
         LOGGER_trace( "Packets read: %d", error_number );
      }
      break;

      case TYPE_SOCKET_INET: {
         LOGGER_trace("socket - inet");
         if( 0 > socket_dispatch_inet( if_devices[0].device_handle.socket
                     , PCAP_DISPATCH_PACKET_COUNT
                     , handle_packet
                     , (u_char*) pcap_dev_ptr) )
         {
            LOGGER_error( "Error DeviceNo   %s: %s"
                  , pcap_dev_ptr->device_name, "" );

         }
      }
      break;

      case TYPE_SOCKET_UNIX: {
         LOGGER_trace("socket - unix");
         if( 0 > socket_dispatch( if_devices[0].device_handle.socket
                     , PCAP_DISPATCH_PACKET_COUNT
                     , handle_packet
                     , (u_char*) pcap_dev_ptr) )
         {
            LOGGER_error( "Error DeviceNo   %s: %s"
                  , pcap_dev_ptr->device_name, "" );

         }
      }
      break;
#else
      case TYPE_PFRING: {
         LOGGER_trace("pfring");
         if( 0 > pfring_dispatch( if_devices[0].device_handle.pfring
                     , PCAP_DISPATCH_PACKET_COUNT
                     , packet_pfring_cb
                     , (u_char*) pcap_dev_ptr) )
         {
            LOGGER_error( "Error DeviceNo   %s: %s"
                  , pcap_dev_ptr->device_name, "" );
         }
      }
      break;
#endif

      default:
      break;
   }
   LOGGER_trace("Return");
}

#ifdef PFRING
void packet_pfring_cb(u_char *user_args, const struct pfring_pkthdr *header,
      const u_char *packet) {
   device_dev_t* if_device = (device_dev_t*) user_args;
   uint8_t layers[4] = {0};
   uint32_t hash_result = 0;
   uint32_t copiedbytes = 0;
   uint8_t ttl = 0;
   uint64_t timestamp = 0;
   int pktid = 0;

   LOGGER_trace("packet_pfring_cb");

   if_device->sampling_delta_count++;
   if_device->totalpacketcount++;

   layers[L_NET] = header->extended_hdr.parsed_pkt.ip_version;
   layers[L_TRANS] = header->extended_hdr.parsed_pkt.l3_proto;

   // hash was already calculated in-kernel. use it
   hash_result = header->extended_hdr.parsed_pkt.pkt_detail.aggregation.num_pkts;
   /*
    printf("offsets@t0 l(3,4,5): %d, %d, %d\n",
    header->extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset + if_device->offset[L_NET],
    header->extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset + if_device->offset[L_NET],
    header->extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset + if_device->offset[L_NET]);
    */
   //if_device->offset[L_NET]       = header->extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset;
   if_device->offset[L_TRANS] = header->extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset + if_device->offset[L_NET];
   if_device->offset[L_PAYLOAD] = header->extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset + if_device->offset[L_NET];

   //printf("pre getTTL: caplen: %02d, offset_net: %02d, ipv: %d\n",
   //            header->caplen, if_device->offset[L_NET], layers[L_NET]);
   ttl = getTTL(packet, header->caplen, if_device->offset[L_NET],
         layers[L_NET]);

   if_device->export_packet_count++;
   if_device->sampling_size++;

   // bypassing export if disabled by cmd line
   if (g_options.export_pktid_interval <= 0) {
      return;
   }

   // in case we want to use the hashID as packet ID
   if (g_options.hashAsPacketID == 1) {
      pktid = hash_result;
   } else {
      // selection of viable fields of the packet - depend on the selection function choosen
      copiedbytes = g_options.selection_function(packet, header->caplen,
            if_device->outbuffer, if_device->outbufferLength,
            if_device->offset, layers);
      pktid = g_options.pktid_function(if_device->outbuffer, copiedbytes);
   }

   /*
    printf("offsets@t1 l(3,4,5): %d, %d, %d\n",
    if_device->offset[L_NET],
    if_device->offset[L_TRANS],
    if_device->offset[L_PAYLOAD]);
    */

   //printf("pktid: 0d%d\n", pktid);

   timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
   + (uint64_t) header->ts.tv_usec;

   switch (g_options.templateID) {
      case MINT_ID: {
         void* fields[] = {&timestamp, &hash_result, &ttl};
         uint16_t lengths[] = {8, 4, 1};

         if (0 > ipfix_export_array(if_device->ipfixhandle,
                     if_device->ipfixtmpl_min, 3, fields, lengths)) {
            LOGGER_fatal( "ipfix_export() failed: %s", strerror(errno));
            exit(1);
         }
         break;
      }

      case TS_ID: {
         void* fields[] = {&timestamp, &hash_result};
         uint16_t lengths[] = {8, 4};

         if (0 > ipfix_export_array(if_device->ipfixhandle,
                     if_device->ipfixtmpl_ts, 2, fields, lengths)) {
            LOGGER_fatal( "ipfix_export() failed: %s", strerror(errno));
            exit(1);
         }
         break;
      }

      case TS_TTL_PROTO_ID: {
         uint16_t length;

         if (layers[L_NET] == N_IP) {
            length = ntohs(*((uint16_t*)
                        (&packet[if_device->offset[L_NET] + 2])));
         } else if (layers[L_NET] == N_IP6) {
            length = ntohs(*((uint16_t*)
                        (&packet[if_device->offset[L_NET] + 4])));
         } else {
            LOGGER_fatal( "cannot parse packet length");
            length = 0;
         }

         void* fields[] = {&timestamp,
            &hash_result,
            &ttl,
            &length,
            &layers[L_TRANS],
            &layers[L_NET]
         };
         uint16_t lengths[6] = {8, 4, 1, 2, 1, 1};

         if (0 > ipfix_export_array(if_device->ipfixhandle,
                     if_device->ipfixtmpl_ts_ttl, 6, fields, lengths)) {
            LOGGER_fatal( "ipfix_export() failed: %s", strerror(errno));
            exit(1);
         }
         break;
      }
      default:
      break;
   } // switch (options.templateID)

   // flush ipfix storage if max packetcount is reached
   if (if_device->export_packet_count >= g_options.export_packet_count) {
      if_device->export_packet_count = 0;
      export_flush();
   }
}
#endif

#ifndef PFRING
inline int set_value(void** field, uint16_t* length, void* value, uint16_t size) {
   *field = value;
   *length = size;
   return 1;
}

static void print_array( const u_char *p, int l ) {
   int i = 0;
   for( i=0; i < l; ++i ) {
      fprintf( stderr,  "%02x ", p[i]);
      //LOGGER_debug( "%02x ", packet[i]);
   }
   fprintf( stderr,  "\n");
}

static void print_ip4( const u_char *p, int l ) {
   if( 0x40 != (p[0]&0xf0) ){
      print_array(p,l);
      return;
   }
   int i = 0;
   for( i=0; i < l && i < 12; ++i ) {
      fprintf( stderr,  "%02x ", p[i]);
   }
   fprintf(stderr, "\b [");
   for( ; i < l && i < 16; ++i ) {
      fprintf( stderr,  "%3d.", p[i]);
   }
   fprintf(stderr, "\b] [");
   for( ; i < l && i < 20; ++i ) {
      fprintf( stderr,  "%3d.", p[i]);
   }
   fprintf(stderr, "\b] ");
   for( ; i < l; ++i ) {
      fprintf( stderr,  "%02x ", p[i]);
   }
   fprintf( stderr,  "\n");
}

inline uint8_t get_ttl( const uint8_t *packet, uint16_t packetLength, int16_t offset, netProt_t nettype )
{
   return (N_IP==nettype)?packet[offset + 8]:0;
}

// return the packet protocol beyond the link layer (defined by rfc )
// !! the raw packet is expected (include link layer)
// return 0 if unknown
inline uint16_t get_nettype( packet_t *packet, int linktype ) {
   switch (linktype) {
   case DLT_EN10MB: // 14 octets
      // Ethernet
      return ntohs(*((uint16_t*) (&packet->ptr[12])));
      break;
   case DLT_ATM_RFC1483: // 8 octets
      return ntohs(*((uint16_t*) (&packet->ptr[6])));
      break;
   case DLT_LINUX_SLL: // 16 octets
      // TODO: either the first 2 octets or the last 2 octets
      return ntohs(*((uint16_t*) (&packet->ptr[0])));
      break;
   case DLT_RAW:
      break;
   default:
      break;
   }
   return 0;
}

inline uint64_t get_timestamp(struct timeval ts) {
   return     (uint64_t) ts.tv_sec * 1000000ULL
            + (uint64_t) ts.tv_usec;
}

inline void apply_offset( packet_t *pkt, uint32_t offset ) {
   LOGGER_trace( "Offset: %d", offset );
   if( offset < pkt->len ) {
      pkt->ptr += offset;
      pkt->len -= offset;
   }
   else {
      pkt->len = 0;
   }
}

void handle_default_packet( packet_t *packet, packet_info_t *packet_info ) {
   LOGGER_warn( "packet type: 0x%04X (not supported)", packet_info->nettype );
}

void handle_ip_packet( packet_t *packet, packet_info_t *packet_info ) {
   uint32_t hash_id = 0;
   uint32_t pkt_id  = 0;
   uint32_t offsets[4] = {0}; // layer offsets for: link, net, transport, payload
   uint8_t  layers[4]  = {0}; // layer protocol types for: link, net, transport, payload

   LOGGER_trace(" ");

   // reset hash buffer
   packet_info->device->hash_buffer.len = 0;

   // selection of viable fields of the packet - depend on the selection function choosen
   // locate protocolsections of ip-stack --> findHeaders() in hash.c
   g_options.selection_function(packet,
         &packet_info->device->hash_buffer,
         offsets, layers);

   if (0 == packet_info->device->hash_buffer.len) {
      LOGGER_trace( "Warning: packet does not contain Selection");
      return;
   }

   // hash the chosen packet data
   hash_id = g_options.hash_function(&packet_info->device->hash_buffer);
   LOGGER_trace( "hash id: 0x%08X", hash_id );

   // hash id must be in the chosen selection range to count
   if ((g_options.sel_range_min <= hash_id) &&
       (g_options.sel_range_max >= hash_id))
   {
      packet_info->device->export_packet_count++;
      packet_info->device->sampling_size++;

      // bypassing export if disabled by cmd line
      if (g_options.export_pktid_interval <= 0) { return; }

      // in case we want to use the hashID as packet ID
      if( g_options.hashAsPacketID ) {
         pkt_id = hash_id;
      }
      else {
         pkt_id = g_options.pktid_function(&packet_info->device->hash_buffer);
      }

      ipfix_template_t* template = packet_info->device->ipfixtmpl_min;
      switch (g_options.templateID) {
      case MINT_ID:
         template = packet_info->device->ipfixtmpl_min;
         break;
      case TS_ID:
         template = packet_info->device->ipfixtmpl_ts;
         break;
      case TS_TTL_PROTO_ID:
         template = packet_info->device->ipfixtmpl_ts_ttl;
         break;
      case TS_TTL_PROTO_IP_ID:
         template = packet_info->device->ipfixtmpl_ts_ttl_ip;
         break;
      default:
         LOGGER_info( "!!!no template specified!!!" );
         return;
         break;
      }
      int               size     = template->nfields;
      void*             fields[size];
      uint16_t          lengths[size];

      uint8_t  ttl       = 0;
      uint64_t timestamp = 0;
      uint16_t length    = 0; // dummy for TS_TTL_PROTO template id
      uint16_t src_port  = 0;
      uint16_t dst_port  = 0;

      ttl       = get_ttl(packet->ptr, packet->len, offsets[L_NET], layers[L_NET]);
      timestamp = get_timestamp(packet_info->ts);

//      set_hash( );
//      set_timestamp();
//      set_ip_ttl();
//      set_ip_version();
//      set_ip_length();
//      set_ip_id();
      
      switch (g_options.templateID) {
      case TS_ID: {
         int index = 0;
         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
         index += set_value( &fields[index], &lengths[index], &hash_id, 4);
         break;
      }

      case MINT_ID: {
         int index = 0;
         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
         index += set_value( &fields[index], &lengths[index], &hash_id, 4);
         index += set_value( &fields[index], &lengths[index], &ttl, 1);
         break;
      }

      case TS_TTL_PROTO_ID: {
         if (layers[L_NET] == N_IP) {
            length = ntohs(*((uint16_t*) (&packet->ptr[offsets[L_NET] + 2])));
         } else if (layers[L_NET] == N_IP6) {
            length = ntohs(*((uint16_t*) (&packet->ptr[offsets[L_NET] + 4])));
         } else {
            LOGGER_fatal( "cannot parse packet length" );
            length = 0;
         }

         int index = 0;
         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
         index += set_value( &fields[index], &lengths[index], &hash_id, 4);
         index += set_value( &fields[index], &lengths[index], &ttl, 1);
         index += set_value( &fields[index], &lengths[index], &length, 2);
         index += set_value( &fields[index], &lengths[index], &layers[L_TRANS], 1);
         index += set_value( &fields[index], &lengths[index], &layers[L_NET], 1);
         break;
      }

      case TS_TTL_PROTO_IP_ID: {          
          if (layers[L_NET] == N_IP) {
              length = ntohs(*((uint16_t*) (&packet->ptr[offsets[L_NET] + 2])));  
          } else if (layers[L_NET] == N_IP6) {
              length = ntohs(*((uint16_t*) (&packet->ptr[offsets[L_NET] + 4])));
          } else {
              LOGGER_fatal( "cannot parse packet length" );
              length = 0;
          }
          
          int index = 0;
          index += set_value( &fields[index], &lengths[index], &timestamp, 8);
          index += set_value( &fields[index], &lengths[index], &hash_id, 4);
          index += set_value( &fields[index], &lengths[index], &ttl, 1);
          index += set_value( &fields[index], &lengths[index], &length, 2);
          index += set_value( &fields[index], &lengths[index], &layers[L_TRANS], 1);
          index += set_value( &fields[index], &lengths[index], &layers[L_NET], 1);
          // this needs to be IPv4 and UDP or TCP or SCTP (not yet supported)
          // TODO: switch template members
          uint32_t ipa = 0;
          if( N_IP == layers[L_NET] ) {
             index += set_value( &fields[index], &lengths[index], 
                   (uint32_t*) &packet->ptr[offsets[L_NET] + 12], 4);
          }
          else {
             index += set_value( &fields[index], &lengths[index], &ipa, 4);
          }
          switch( layers[L_TRANS] ) {
             case T_TCP:
             case T_UDP:
             //case T_SCTP:
                src_port = ntohs(*((uint16_t*) &packet->ptr[offsets[L_TRANS]]));
                break;
             default:
                src_port = 0;
          }
          index += set_value( &fields[index], &lengths[index], &src_port, 2);
          if( N_IP == layers[L_NET] ) {
             index += set_value( &fields[index], &lengths[index], 
                   (uint32_t*) &packet->ptr[offsets[L_NET] + 16], 4);
          }
          else {
             index += set_value( &fields[index], &lengths[index], &ipa, 4);
          }
          switch( layers[L_TRANS] ) {
             case T_TCP:
             case T_UDP:
             //case T_SCTP:
                dst_port = ntohs(*((uint16_t*) &packet->ptr[offsets[L_TRANS] + 2]));
                break;
             default:
                dst_port = 0;
          }
          index += set_value( &fields[index], &lengths[index], &dst_port, 2);
          break;
      }

      default:
         LOGGER_info( "!!!no template specified!!!" );
         return;
      } // switch (options.templateID)

      //LOGGER_debug( "%d", size);
      //int i = 0;
      //for( i = 0; i < size; ++i ) {
      //   LOGGER_debug( "%p: %d: %d", fields[i], lengths[i], *( (int*)fields[i]));
      //}

      // send ipfix packet 
      if (0 > ipfix_export_array(packet_info->device->ipfixhandle, template, size, fields, lengths)) {
         LOGGER_fatal( "ipfix_export() failed: %s", strerror(errno));
      }

      // flush ipfix storage if max packetcount is reached
      if (packet_info->device->export_packet_count >= g_options.export_packet_count) {
         //todo: export_flush_device( packet_info->device );
         packet_info->device->export_packet_count = 0;
         export_flush();
      }


   } // if (hash in selection range)
}

void handle_packet(u_char *user_args, const struct pcap_pkthdr *header, const u_char * packet) {
   packet_t      pkt  = {(uint8_t*)packet, header->caplen};
   packet_info_t info = {header->ts, header->len, (device_dev_t*)user_args};

   LOGGER_trace(" ");
   
   info.device->sampling_delta_count++;
   info.device->totalpacketcount++;

   // debug output
   if (0) print_array( pkt.ptr, pkt.len );

   // get packet type from link layer header
   info.nettype = get_nettype( &pkt, info.device->link_type );
   LOGGER_trace( "nettype: 0x%04X", info.nettype );

   // apply net offset - skip link layer header for further processing
   apply_offset( &pkt, info.device->pkt_offset );

   // apply user offset
   apply_offset( &pkt, g_options.offset );

   // debug output
   if (0) print_array( pkt.ptr, pkt.len );

   if( 0x0800 == info.nettype || // IPv4
       0x86DD == info.nettype )  // IPv6
   {
      if (1) print_ip4( pkt.ptr, pkt.len );
      handle_ip_packet(&pkt, &info);
      //LOGGER_trace( "drop" );
   }
   else {
      handle_default_packet(&pkt, &info);
   }
}


// formaly known as handle_packet()
//void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header, const u_char * packet) {
//   device_dev_t* if_device = (device_dev_t*) user_args;
//   uint8_t  layers[4] = { 0 };
//   uint32_t hash_result;
//   int packet_len = header->caplen;
//   
//   LOGGER_trace("handle packet");
//   
//   if_device->sampling_delta_count++;
//   if_device->totalpacketcount++;
//
//   // debug output
//   if (0) print_array( packet, packet_len );
//   if (0) print_array( packet+if_device->offset[L_NET], packet_len-if_device->offset[L_NET] );
//
//   // selection of viable fields of the packet - depend on the selection function choosen
//   // locate protocolsections of ip-stack --> findHeaders() in hash.c
//   g_options.selection_function(packet, packet_len,
//         &if_device->hash_buffer,
//         if_device->offset, layers);
//
//   // !!!! no ip-stack found !!!!
//   if (0 == if_device->hash_buffer.len) {
//      LOGGER_trace( "Warning: packet does not contain Selection");
//      // todo: ?alternative selection function
//      // todo: ?for the whole configuration
//      // todo: ????drop????
//      return;
//   }
//   //   else {
//   //      LOGGER_warn( "Warnig: packet contain Selection (%d)", copiedbytes);
//   //   }
//
//   // hash the chosen packet data
//   hash_result = g_options.hash_function(&if_device->hash_buffer);
//   //LOGGER_trace( "hash result: 0x%04X", hash_result );
//
//   // hash result must be in the chosen selection range to count
//   if ((g_options.sel_range_min <= hash_result)
//         && (g_options.sel_range_max >= hash_result))
//   {
//      uint8_t  ttl;
//      uint64_t timestamp;
//
//      if_device->export_packet_count++;
//      if_device->sampling_size++;
//
//      // bypassing export if disabled by cmd line
//      if (g_options.export_pktid_interval <= 0) {
//         return;
//      }
//
//      int pktid = 0;
//      // in case we want to use the hashID as packet ID
//      if (g_options.hashAsPacketID == 1) {
//         pktid = hash_result;
//      } else {
//         pktid = g_options.pktid_function(&if_device->hash_buffer);
//      }
//
//      ttl       = get_ttl(packet, packet_len, if_device->offset[L_NET], layers[L_NET]);
//      timestamp = get_timestamp(header->ts);
//
//      ipfix_template_t* template = if_device->ipfixtmpl_min;
//      switch (g_options.templateID) {
//      case MINT_ID:
//         template = if_device->ipfixtmpl_min;
//         break;
//      case TS_ID:
//         template = if_device->ipfixtmpl_ts;
//         break;
//      case TS_TTL_PROTO_ID:
//         template = if_device->ipfixtmpl_ts_ttl;
//         break;
//      case TS_TTL_PROTO_IP_ID:
//         template = if_device->ipfixtmpl_ts_ttl_ip;
//         break;
//      default:
//         LOGGER_info( "!!!no template specified!!!" );
//         return;
//         break;
//      }
//      int               size     = template->nfields;
//      void*             fields[size];
//      uint16_t          lengths[size];
//
//      uint16_t length; // dummy for TS_TTL_PROTO template id
//
////      set_hash( );
////      set_timestamp();
////      set_ip_ttl();
////      set_ip_version();
////      set_ip_length();
////      set_ip_id();
//      
//      switch (g_options.templateID) {
//      case TS_ID: {
//         int index = 0;
//         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
//         index += set_value( &fields[index], &lengths[index], &hash_result, 4);
//         break;
//      }
//
//      case MINT_ID: {
//         int index = 0;
//         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
//         index += set_value( &fields[index], &lengths[index], &hash_result, 4);
//         index += set_value( &fields[index], &lengths[index], &ttl, 1);
//         break;
//      }
//
//      case TS_TTL_PROTO_ID: {
//         if (layers[L_NET] == N_IP) {
//            length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 2])));
//         } else if (layers[L_NET] == N_IP6) {
//            length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 4])));
//         } else {
//            LOGGER_fatal( "cannot parse packet length" );
//            length = 0;
//         }
//
//         int index = 0;
//         index += set_value( &fields[index], &lengths[index], &timestamp, 8);
//         index += set_value( &fields[index], &lengths[index], &hash_result, 4);
//         index += set_value( &fields[index], &lengths[index], &ttl, 1);
//         index += set_value( &fields[index], &lengths[index], &length, 2);
//         index += set_value( &fields[index], &lengths[index], &layers[L_TRANS], 1);
//         index += set_value( &fields[index], &lengths[index], &layers[L_NET], 1);
//         break;
//      }
//
//      case TS_TTL_PROTO_IP_ID: {          
//          if (layers[L_NET] == N_IP) {
//              length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 2])));  
//          } else if (layers[L_NET] == N_IP6) {
//              length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 4])));
//          } else {
//              LOGGER_fatal( "cannot parse packet length" );
//              length = 0;
//          }
//          
//          int index = 0;
//          index += set_value( &fields[index], &lengths[index], &timestamp, 8);
//          index += set_value( &fields[index], &lengths[index], &hash_result, 4);
//          index += set_value( &fields[index], &lengths[index], &ttl, 1);
//          index += set_value( &fields[index], &lengths[index], &length, 2);
//          index += set_value( &fields[index], &lengths[index], &layers[L_TRANS], 1);
//          index += set_value( &fields[index], &lengths[index], &layers[L_NET], 1);
//          // this needs to be IPv4 and UDP or TCP or SCTP (not yet supported)
//          // TODO: switch template members
//          uint32_t ipa = 0;
//          if( N_IP == layers[L_NET] ) {
//             index += set_value( &fields[index], &lengths[index], 
//                   (uint32_t*) &packet[if_device->offset[L_NET] + 12], 4);
//          }
//          else {
//             index += set_value( &fields[index], &lengths[index], &ipa, 4);
//          }
//          uint16_t port = 0;
//          switch( layers[L_TRANS] ) {
//             case T_TCP:
//             case T_UDP:
//             //case T_SCTP:
//                port = ntohs(*((uint16_t*) &packet[if_device->offset[L_TRANS]]));
//                break;
//             default:
//                port = 0;
//          }
//          index += set_value( &fields[index], &lengths[index], &port, 2);
//          if( N_IP == layers[L_NET] ) {
//             index += set_value( &fields[index], &lengths[index], 
//                   (uint32_t*) &packet[if_device->offset[L_NET] + 16], 4);
//          }
//          else {
//             index += set_value( &fields[index], &lengths[index], &ipa, 4);
//          }
//          switch( layers[L_TRANS] ) {
//             case T_TCP:
//             case T_UDP:
//             //case T_SCTP:
//                port = ntohs(*((uint16_t*) &packet[if_device->offset[L_TRANS] + 2]));
//                break;
//             default:
//                port = 0;
//          }
//          index += set_value( &fields[index], &lengths[index], &port, 2);
//          break;
//      }
//
//      default:
//         LOGGER_info( "!!!no template specified!!!" );
//         return;
//      } // switch (options.templateID)
//
//      //LOGGER_debug( "%d", size);
//      //int i = 0;
//      //for( i = 0; i < size; ++i ) {
//      //   LOGGER_debug( "%p: %d: %d", fields[i], lengths[i], *( (int*)fields[i]));
//      //}
//
//      // send ipfix packet 
//      if (0 > ipfix_export_array(if_device->ipfixhandle, template, size, fields, lengths)) {
//         LOGGER_fatal( "ipfix_export() failed: %s", strerror(errno));
//         exit(1);
//      }
//
//      // flush ipfix storage if max packetcount is reached
//      if (if_device->export_packet_count >= g_options.export_packet_count) {
//         //todo: export_flush_device( if_device );
//         if_device->export_packet_count = 0;
//         export_flush();
//      }
//
//   } // if((options.sel_range_min < hash_result) && (options.sel_range_max > hash_result))
////   else {
////      LOGGER_info( "INFO: drop packet; hash not in selection range");
////   }
//}
#endif

/**
 * initial cb function;
 * selection of runtime configuration commands
 * command: "mid: <id> -<cmd> <value>
 * @param cmd string
 *
 * returns: 1 consumed, 0 otherwise
 */
int runtime_configuration_cb(char* conf_msg) {
   unsigned long mID = 0; // session id
   int matches;

   LOGGER_debug("configuration message received: '%s'", conf_msg);
   // check prefix: "mid: <id>"
   matches = sscanf(conf_msg, "mid: %lu ", &mID);
   if (1 == matches) {
      LOGGER_debug("Message ID: %lu", mID);

      // fetch command from string starting with hyphen '-'
      char cmd = '?';
      int length = strlen(conf_msg);

      int i = 0;
      for (i = 0; i < length; ++i, ++conf_msg) {
         if ('-' == *conf_msg) {
            // get command
            ++conf_msg;
            cmd = *conf_msg;
            ++conf_msg;

            // remove leading whitespaces
            while (isspace(*conf_msg))
               ++conf_msg;

            // execute command
            LOGGER_debug("configuration command '%c': %s", cmd, conf_msg);
            return (*getFunction(cmd))(mID, conf_msg);
         }
      }
   }

   return NETCON_CMD_UNKNOWN;
}

/**
 * send available command
 * command: h,?
 * returns: 1 consumed, 0 otherwise
 */
int configuration_help(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);
   int i;

   int size = 1;
   for (i = 0; i < config_fct_length; ++i) {
      size += configuration_fct[i].desc_length;
   }

   char response[size];
   char* tmp = response;
   for (i = 0; i < config_fct_length; ++i) {
      strcpy(tmp, configuration_fct[i].desc);
      tmp += configuration_fct[i].desc_length;
   }

   for (i = 0; i < g_options.number_interfaces; i++) {
      LOGGER_debug("==> '%s'", response);
      export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid, 0,
            response);
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: t <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_template(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   if (-1 == parseTemplate(msg, &g_options)) {
      LOGGER_warn("unknown template: %s", msg);
   } else {
      int i;
      char response[256];
      snprintf(response, 256, "INFO: new template set: %s", msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: f <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_filter(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   if (-1 == set_all_filter(msg)) {
      LOGGER_error("error setting filter: %s", msg);
   } else {
      int i;
      char response[256];
      snprintf(response, 256, "INFO: new filter expression set: %s", msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: J <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_export_to_probestats(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   int new_timeout = strtol(msg, NULL, 0);
   if (0 <= new_timeout) {
      events.export_timer_stats.repeat = new_timeout;
      ev_timer_again(events.loop, &events.export_timer_stats);

      int i;
      char response[256];
      snprintf(response, 256, "INFO: new probestats export timeout set: %s",
            msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: K <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_export_to_ifstats(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   int new_timeout = strtol(msg, NULL, 0);
   if (0 <= new_timeout) {
      events.export_timer_sampling.repeat = new_timeout;
      ev_timer_again(events.loop, &events.export_timer_sampling);

      int i;
      char response[256];
      snprintf(response, 256, "INFO: new ifstats export timeout set: %s", msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: I <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_export_to_pktid(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   int new_timeout = strtol(msg, NULL, 0);
   if (0 <= new_timeout) {
      events.export_timer_pkid.repeat = new_timeout;
      ev_timer_again(events.loop, &events.export_timer_pkid);

      int i;
      char response[256];
      snprintf(response, 256, "INFO: new packet export timeout set: %s", msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: m <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_min_selection(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   uint32_t value = set_sampling_lowerbound(&g_options, msg);
   int i;
   char response[256];
   snprintf(response, 256, "INFO: minimum selection range set: %d", value);
   for (i = 0; i < g_options.number_interfaces; i++) {
      LOGGER_debug("==> %s", response);
      export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid, 0,
            response);
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: M <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_max_selection(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   uint32_t value = set_sampling_upperbound(&g_options, msg);
   int i;
   char response[256];
   snprintf(response, 256, "INFO: maximum selection range set: %d", value);
   for (i = 0; i < g_options.number_interfaces; i++) {
      LOGGER_debug("==> %s", response);
      export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid, 0,
            response);
   }
   return NETCON_CMD_MATCHED;
}

/**
 * command: r <value>
 * returns: 1 consumed, 0 otherwise
 */
int configuration_set_ratio(unsigned long mid, char *msg) {
   LOGGER_debug("Message ID: %lu", mid);

   /* currently sampling ratio is equal for all devices */
   if (-1 == set_sampling_ratio(&g_options, msg)) {
      LOGGER_error("error setting sampling ration: %s", msg);
   } else {
      int i;
      char response[256];
      snprintf(response, 256, "INFO: new sampling ratio set: %s", msg);
      for (i = 0; i < g_options.number_interfaces; i++) {
         LOGGER_debug("==> %s", response);
         export_data_sync(&if_devices[i], ev_now(events.loop) * 1000, mid,
               0, response);
      }
   }
   //   if( messageId > 0 ){
   //      char response[255];
   //      snprintf(response,255,"ERROR: invalid command: %s",msg);
   //      LOGGER_debug("==> %s",response);
   //      /* FIXME review: interface devices and options are still confuse*/
   //      for (i = 0; i < options.number_interfaces; i++) {
   //         export_data_sync(&pcap_devices[i],
   //               ev_now(events.loop)*1000,
   //               messageId,
   //               0,
   //               response);
   //      }
   //   }
   return NETCON_CMD_MATCHED;
}

/*-----------------------------------------------------------------------------
 Export
 -----------------------------------------------------------------------------*/
void export_data_interface_stats(device_dev_t *dev,
      uint64_t observationTimeMilliseconds, u_int32_t size,
      u_int64_t deltaCount) {
   static uint16_t lengths[] = { 8, 4, 8, 4, 4, 0, 0 };
   static char interfaceDescription[16];
#ifndef PFRING
   struct pcap_stat pcapStat;
   void* fields[] = { &observationTimeMilliseconds, &size, &deltaCount,
         &pcapStat.ps_recv, &pcapStat.ps_drop, dev->device_name,
         interfaceDescription };
#else
   pfring_stat pfringStat;
   void* fields[] = {&observationTimeMilliseconds, &size, &deltaCount
      , &pfringStat.recv
      , &pfringStat.drop
      , dev->device_name
      , interfaceDescription};
#endif

   snprintf(interfaceDescription, sizeof(interfaceDescription), "%s",
         ntoa(dev->IPv4address));
   lengths[5] = strlen(dev->device_name);
   lengths[6] = strlen(interfaceDescription);

#ifndef PFRING
   /* Get pcap statistics in case of live capture */
   if (TYPE_PCAP == dev->device_type) {
      if (pcap_stats(dev->device_handle.pcap, &pcapStat) < 0) {
         LOGGER_error("Error DeviceNo   %s: %s", dev->device_name,
               pcap_geterr(dev->device_handle.pcap));
      }
   } else {
      pcapStat.ps_drop = 0;
      pcapStat.ps_recv = 0;
   }
#else
   if ( TYPE_PFRING == dev->device_type ) {
      if (pfring_stats(dev->device_handle.pfring, &pfringStat) < 0) {
         LOGGER_error("Error DeviceNo   %s: Failed to get statistics",
               dev->device_name);
      }
   } else {
      pfringStat.drop = 0;
      pfringStat.recv = 0;
   }
#endif

   LOGGER_trace("sampling: (%d, %lu)", size, (long unsigned) deltaCount);
   if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_interface_stats, 7,
         fields, lengths) < 0) {
      LOGGER_error("ipfix export failed: %s", strerror(errno));
   } else {
      dev->sampling_size = 0;
      dev->sampling_delta_count = 0;
   }
}

void export_data_sync(device_dev_t *dev, int64_t observationTimeMilliseconds,
      u_int32_t messageId, u_int32_t messageValue, char * message) {
   static uint16_t lengths[] = { 8, 4, 4, 0 };
   lengths[3] = strlen(message);
   void *fields[] = { &observationTimeMilliseconds, &messageId, &messageValue,
         message };
   LOGGER_debug("export data sync");
   if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_sync, 4, fields,
         lengths) < 0) {
      LOGGER_error("ipfix export failed: %s", strerror(errno));
      return;
   }
   if (ipfix_export_flush(dev->ipfixhandle) < 0) {
      LOGGER_error("Could not export IPFIX (flush) ");
   }

}

void export_data_probe_stats(device_dev_t *dev) {
   static uint16_t lengths[] = { 8, 4, 8, 4, 4, 8, 8 };
   struct probe_stat probeStat;

   void *fields[] = { &probeStat.observationTimeMilliseconds,
         &probeStat.systemCpuIdle, &probeStat.systemMemFree,
         &probeStat.processCpuUser, &probeStat.processCpuSys,
         &probeStat.processMemVzs, &probeStat.processMemRss };

   probeStat.observationTimeMilliseconds = (uint64_t) ev_now(events.loop)
         * 1000;
   get_probe_stats(&probeStat);

   if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_probe_stats, 7,
         fields, lengths) < 0) {
      LOGGER_error("ipfix export failed: %s", strerror(errno));
      return;
   }

}

void export_data_location(device_dev_t *dev,
      int64_t observationTimeMilliseconds) {
   static uint16_t lengths[] = { 8, 4, 0, 0, 0, 0 };
   lengths[2] = strlen(getOptions()->s_latitude);
   lengths[3] = strlen(getOptions()->s_longitude);
   lengths[4] = strlen(getOptions()->s_probe_name);
   lengths[5] = strlen(getOptions()->s_location_name);
   void *fields[] = { &observationTimeMilliseconds, &getOptions()->ipAddress,
         getOptions()->s_latitude, getOptions()->s_longitude,
         getOptions()->s_probe_name, getOptions()->s_location_name };
   LOGGER_debug("export data location");
   //LOGGER_fatal("%s; %s",getOptions()->s_latitude, getOptions()->s_longitude );
   if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_location,
         sizeof(lengths) / sizeof(lengths[0]), fields, lengths) < 0) {
      LOGGER_error("ipfix export failed: %s", strerror(errno));
      return;
   }
   if (ipfix_export_flush(dev->ipfixhandle) < 0) {
      LOGGER_error("Could not export IPFIX (flush) ");
   }

}

/**
 * This causes libipfix to send cached messages to
 * the registered collectors.
 *
 * flushes each device
 */
void export_flush() {
   int i;
   LOGGER_trace("export_flush");
   for (i = 0; i < g_options.number_interfaces; i++) {
      if (ipfix_export_flush(if_devices[i].ipfixhandle) < 0) {
         LOGGER_error("Could not export IPFIX, device: %d", i);
         //         ipfix_reconnect();
         break;
      }
   }
}

void export_flush_all() {
   int i;
   LOGGER_trace("export_flush_all");
   for (i = 0; i < g_options.number_interfaces; i++) {
      export_flush_device(&if_devices[i]);
   }
}

void export_flush_device(device_dev_t* device) {
   LOGGER_trace("export_flush_device");
   if (0 != device) {
      device->export_packet_count = 0;
      if (ipfix_export_flush(device->ipfixhandle) < 0) {
         LOGGER_error("Could not export IPFIX: %s", device->device_name);
         //         ipfix_reconnect();
      }
   }
}

/**
 * Periodically called each export time interval.
 *
 */
void export_timer_pktid_cb (EV_P_ ev_timer *w, int revents) {
   LOGGER_trace("export timer tick");
   export_flush();
}

/**
 * Peridically called each export/sampling time interval
 */
void export_timer_sampling_cb (EV_P_ ev_timer *w, int revents) {
   int i;
   uint64_t observationTimeMilliseconds;
   LOGGER_trace("export timer sampling call back");
   observationTimeMilliseconds = (uint64_t)ev_now(events.loop) * 1000;
   for (i = 0; i < g_options.number_interfaces; i++) {
      device_dev_t *dev = &if_devices[i];
      export_data_interface_stats(dev, observationTimeMilliseconds, dev->sampling_size, dev->sampling_delta_count );
#ifdef PFRING
#ifdef PFRING_STATS
      print_stats( dev );
#endif
#endif
   }
   export_flush();
}

void export_timer_stats_cb (EV_P_ ev_timer *w, int revents) {
   /* using ipfix handle from first interface */
   export_data_probe_stats(&if_devices[0] );
   export_flush();
}

/**
 * Peridically called
 */
void export_timer_location_cb (EV_P_ ev_timer *w, int revents) {
   int i;
   uint64_t observationTimeMilliseconds;
   LOGGER_trace("export timer location call back");
   observationTimeMilliseconds = (uint64_t)ev_now(events.loop) * 1000;
   for (i = 0; i < g_options.number_interfaces; i++) {
      device_dev_t *dev = &if_devices[i];
      export_data_location(dev, observationTimeMilliseconds);
   }
   //export_flush();
}

/**
 * Periodically checks ipfix export fd and reconnects it
 * to netcon
 */
void resync_timer_cb (EV_P_ ev_timer *w, int revents) {
   int i;
   ipfix_collector_sync_t *col;

   for (i = 0; i < (g_options.number_interfaces); i++) {
      col = (ipfix_collector_sync_t*) if_devices[i].ipfixhandle->collectors;
      LOGGER_debug("collector_fd: %d", col->fd);
      netcon_resync( col->fd );
   }
}

