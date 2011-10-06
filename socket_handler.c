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


#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <errno.h>


#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h> /* TODO review: sysinfo is Linux only */
#include <sys/times.h>

#include <netinet/in.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <arpa/inet.h>

// Custom logger
#include "logger.h"

#include "settings.h"
#include "socket_handler.h"


#ifndef PFRING

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

typedef struct {
   const char* ip;
   const char* port;
}
ip_port_t;

ip_port_t parse_ip_port( char* s ) {
   ip_port_t rValue = {"",""};

   char* tmp;

   // get ip address
   char*  tok = strtok_r(s, ":", &tmp);
   if (NULL != tok) {
      rValue.ip = tok;

      // get port
      tok = strtok_r(NULL, ":", &tmp);
      if (tok != NULL) {
         rValue.port = tok;
      } 
      else {
         LOGGER_fatal("Please specify Port to listen on!\n");
      }
   } else 
   {
      LOGGER_fatal("Please specify IP to listen on!\n");
   }
   return rValue;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

void print_array( int log_level, char* fmt, const char* s, int l) {
   if( log_level <= logger_get_level() ) {
      int i = 0;
      int len = 3*l + 1;
      char a[len];
      char* t = a;
      for( i=0; i < l; ++i ) {
         sprintf( t, "%02x ", s[i]);
         t += 3;
      }
      a[len] = '\0';
      LOGGER_info( fmt, a ); 
   }
}

void print_addrinfo( struct addrinfo* ai ) {
   if( LOGGER_LEVEL_INFO <= logger_get_level() ) {
      if( NULL != ai )
      {
         LOGGER_info("FAMILY:    0x%02x", ai->ai_family);
         LOGGER_info("SOCKTYPE:  0x%02x", ai->ai_socktype);
         LOGGER_info("PROTOCOL:  0x%02x", ai->ai_protocol);
         LOGGER_info("FLAGS:     0x%02x", ai->ai_flags);
         LOGGER_info("CANONNAME: %s", ai->ai_canonname);
         LOGGER_info("ADDR_LEN:  %d", ai->ai_addrlen);
         switch( ai->ai_addr->sa_family ) {
            case AF_INET:
               LOGGER_info("ADDR_FAMILY: 0x%02x (INET)", ai->ai_addr->sa_family);
               print_array(LOGGER_LEVEL_INFO, "ADDR_DATA:   %s", ai->ai_addr->sa_data, ai->ai_addrlen);
            break;
            case AF_INET6:
               LOGGER_info("ADDR_FAMILY: 0x%02x (INET6)", ai->ai_addr->sa_family);
               print_array(LOGGER_LEVEL_INFO, "ADDR_DATA:   %s", ai->ai_addr->sa_data, ai->ai_addrlen);
            break;
            default:
               LOGGER_info("ADDR_FAMILY: 0x%02x (other)", ai->ai_addr->sa_family);
               print_array(LOGGER_LEVEL_INFO, "ADDR_DATA:   %s", ai->ai_addr->sa_data, ai->ai_addrlen);
            break;
         }
         LOGGER_info("--------------");

         print_addrinfo( ai->ai_next );
      }
   }
   return;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int create_connect( struct addrinfo* ai ) {
   int s = -1;

   // create a s for the returned service
   s = socket( ai->ai_family, ai->ai_socktype, ai->ai_protocol );
   if(-1 == s ) {
      perror("s create Error");
   }
   // connect the s to the service
   else if( -1 == connect(s, ai->ai_addr, ai->ai_addrlen) ) {
      close( s );
      s = -1;
      perror("Connect failed ");
      // TODO: output failure reasons
      // TODO: try to reconnect in case of tcp, if needed to implement
   }

   return s;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int create_bind( struct addrinfo* ai ) {
   int s = -1;

   // create a s for the returned service
   s = socket( ai->ai_family, ai->ai_socktype, ai->ai_protocol );
   if(-1 == s ) {
      perror("s create Error");
   }
   // connect the s to the service
   else if( -1 == bind(s, ai->ai_addr, ai->ai_addrlen) ) {
      close( s );
      s = -1;
      perror("Connect failed ");
      // TODO: output failure reasons
      // TODO: try to reconnect in case of tcp, if needed to implement
   }

   return s;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

void open_socket_inet(device_dev_t* if_device, options_t *options) {

   // TODO: not yet ready !!!
   ip_port_t        srv_addr; // address to connect the probe to
   struct addrinfo* a_res;    // address results
   struct addrinfo  a_hint;   // address results

   // parse address input string '<ip>:<port>'
   srv_addr = parse_ip_port(if_device->device_name);
   LOGGER_info("INET socket: '%s:%s'", srv_addr.ip, srv_addr.port);

   // TODO: IPv4 support IPv6 is added later
   memset( &a_hint, 0, sizeof(a_hint) );
   a_hint.ai_family   = AF_INET; // AF_INET6; AF_UNSPEC
   //a_hint.ai_family   = AF_UNSPEC;
   //a_hint.ai_socktype = SOCK_STREAM; //SOCK_STREAM | SOCK_DGRAM;
   a_hint.ai_socktype = SOCK_DGRAM; //SOCK_STREAM | SOCK_DGRAM;
   a_hint.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;

   // get all availabe address for the given ip port
   int rv = getaddrinfo(srv_addr.ip, srv_addr.port, &a_hint, &a_res);
   //int rv = getaddrinfo(srv_addr.ip, srv_addr.port, NULL, &a_res);
   if( 0 != rv ) {
      perror( "Socket error in getaddrinfo()" );
      perror( gai_strerror(rv) );
      exit(1);
   }

   // print the return addresses
   print_addrinfo( a_res );

   for( ; NULL != a_res; a_res = a_res->ai_next ) {
      //LOGGER_info( "connect" );
      LOGGER_info( "bind" );

      int socket = -1;

      // create a socket for the returned service
      //if_device->device_handle.socket = create_connect( a_res );
      socket = create_bind( a_res );
      if(-1 == socket ) {
         //perror("socket create_connect error");
         perror("socket create_bind error");
         exit(1);
      }

      if_device->device_handle.socket = socket;
      if_device->dh.fd = socket;
      if_device->dispatch = socket_dispatch_inet;

      // send 'hello' TODO: for test only
      //write( if_device->device_handle.socket, "HELLO!", 6 );
      //write( if_device->device_handle.socket, "", 1 );
      return; // connect first interface only
   }

   // TODO: for UDP send initial message ?
}

#endif

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

void open_socket_unix(device_dev_t* if_device, options_t *options) {
   struct sockaddr_un socket_address;
   int socket_addressLength = 0;
   int s = -1;

   // create a socket to work with
   s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
   if (0 > s) {
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
   if (0 > connect(s, (__CONST_SOCKADDR_ARG) &socket_address, socket_addressLength)) {
      perror("socket: connect");
      exit(2);
   }

   if_device->device_handle.socket = s;
   if_device->dh.fd = s;
   if_device->dispatch = socket_dispatch_unix;

#endif
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

int socket_dispatch_inet(dh_t dh, int max_packets, pcap_handler packet_handler, u_char* user_args)
{
   LOGGER_trace("Enter");

   int      socket = dh.fd;
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
         LOGGER_warn( "socket_dispatch: snaplan exceed Buffer size (%d); "
               "use Buffersize instead.\n", BUFFER_SIZE );
      }

      // recv is blocking; until connection is closed
      // TODO: check handling
      switch(hdr.caplen = recvfrom(socket, buffer, caplen, 0, NULL, NULL)) {
         case 0: {
                    perror("socket: recv(); connection shutdown");
                    return -1;
                 }

         case -1: {
                     if (EAGAIN == errno || EWOULDBLOCK == errno) {
                        return nPackets;
                     } 
                     else {
                        perror("socket: recv()");
                        return -1;
                     }
                  }

         default: {
                     if( LOGGER_LEVEL_DEBUG <= logger_get_level() ){
                        int i = 0;
                        for( i=0; i < hdr.caplen; ++i ) {
                           LOGGER_debug( "%02x ", buffer[i]);
                        }
                     }

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

   LOGGER_trace("Return");
   return nPackets;
}

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#ifndef PFRING
int socket_dispatch_unix(dh_t dh, int max_packets, pcap_handler packet_handler, u_char* user_args)
{
   LOGGER_trace("Enter");

   int      socket = dh.fd;
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
         LOGGER_warn( "socket_dispatch: snaplan exceed Buffer size (%d); "
               "use Buffersize instead.\n", BUFFER_SIZE );
      }

      // recv is blocking; until connection is closed
      switch(hdr.caplen = recv(socket, buffer, caplen, 0)) {
         case 0: {
                    perror("socket: recv(); connection shutdown");
                    return -1;
                 }

         case -1: {
                     if (EAGAIN == errno || EWOULDBLOCK == errno) {
                        return nPackets;
                     } 
                     else {
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

   LOGGER_trace("Return");
   return nPackets;
}
#endif

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

#ifndef PFRING
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
         LOGGER_warn( "socket_dispatch: snaplan exceed Buffer size (%d); "
               "use Buffersize instead.\n", BUFFER_SIZE );
      }

      // recv is blocking; until connection is closed
      switch(hdr.caplen = recv(socket, buffer, caplen, 0)) {
         case 0: {
                    perror("socket: recv(); connection shutdown");
                    return -1;
                 }

         case -1: {
                     if (EAGAIN == errno || EWOULDBLOCK == errno) {
                        return nPackets;
                     } 
                     else {
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
#endif

