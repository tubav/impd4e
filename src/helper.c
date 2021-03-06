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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>

#ifndef PFRING
#include <pcap.h>
#endif

#include <string.h>
#include <ctype.h>

#ifdef PFRING
#include <netinet/ip.h>
#include <net/ethernet.h>     /* the L2 protocols */
#include <pf_plugin_impd4e.h>
#endif

#include "logger.h"
#include "helper.h"
#include "constants.h"

#include "settings.h"

uint32_t getIPv4AddressFromDevice(char* dev_name) {

   int fd;
   struct ifreq ifr;

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
   close(fd);

   // return IP address in network byte order
   return ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
}

char* l_trim( char* s ) {
   // character string is NULL terminated

   if( NULL != s ) {
      while( '\0' != *s && isspace(*s) ) ++s;
   }
   return s;
}

void r_trim( char* s ) {
   // character string is NULL terminated

   if( NULL != s ) {
      int   len = strlen( s );
      char* pos = s + len; // point to '\0'

      while( --pos > s && isspace( *pos ) ) *pos = '\0';
   }
}

/**
 * Helper for printing out IPv4 address
 * TODO: use inet_htoa; inet_ntoa instead
 */
char *htoa(uint32_t ipaddr) {
   static char addrstr[16];
   ipaddr = htonl(ipaddr);
   uint8_t *p = (uint8_t*) &ipaddr;
   sprintf(addrstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
   return addrstr;
}

char *ntoa(uint32_t ipaddr) {
   static char addrstr[16];
   uint8_t *p = (uint8_t*) &ipaddr;
   sprintf(addrstr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
   return addrstr;
}

#ifndef PFRING
void setNONBlocking( device_dev_t* pDevice )
{
   switch (pDevice->device_type) {
   case TYPE_PCAP_FILE:
   case TYPE_PCAP:
      if (pcap_setnonblock(pDevice->device_handle.pcap, 1, errbuf) < 0) {
         LOGGER_fatal( "pcap_setnonblock: %s: %s"
                  , pDevice->device_name, errbuf);
         LOGGER_error( "pcap_setnonblock: %s: %s"
               , pDevice->device_name, errbuf );

      }
      break;

   case TYPE_SOCKET_INET:
   case TYPE_SOCKET_UNIX: {
      int flags = 0;
      if ((flags = fcntl(pDevice->device_handle.socket, F_GETFL, 0)) < 0) {
         // todo: handle error
         LOGGER_fatal( "fcntl (F_GETFL) fails");
      }

      if (fcntl(pDevice->device_handle.socket, F_SETFL, flags | O_NONBLOCK) < 0) {
         // todo: handle error
         LOGGER_fatal( "fcntl (F_SETFL - _NONBLOCK) fails");
      }

      break;
   }

   default:
      break;
   }
}
#endif

int get_file_desc( device_dev_t* pDevice ) {
   switch (pDevice->device_type) {
   case TYPE_testtype:
    #ifndef PFRING
   case TYPE_PCAP_FILE:
   case TYPE_PCAP:
      return pcap_fileno(pDevice->device_handle.pcap);
      break;
    #endif

    #ifdef PFRING
    case TYPE_PFRING:
            return pDevice->device_handle.pfring->fd;
        break;
    #endif

   case TYPE_SOCKET_INET:
   case TYPE_SOCKET_UNIX:
      return pDevice->device_handle.socket;
      break;

   default:
      return 0;
      break;
   }
   return 0;
}

#ifdef PFRING
//#define verbose
#ifdef verbose
/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
   u_int i, j;
   char *cp;

   cp = buf;
   if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
   else
      *cp++ = '0';

   *cp++ = hex[*ep++ & 0xf];

   for(i = 5; (int)--i >= 0;) {
      *cp++ = ':';
      if ((j = *ep >> 4) != 0)
         *cp++ = hex[j];
      else
         *cp++ = '0';

      *cp++ = hex[*ep++ & 0xf];
   }

   *cp = '\0';
   return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
   char *cp, *retStr;
   u_int byte;
   int n;

   cp = &buf[bufLen];
   *--cp = '\0';

   n = 4;
   do {
      byte = addr & 0xff;
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0) {
         *--cp = byte % 10 + '0';
         byte /= 10;
         if (byte > 0)
            *--cp = byte + '0';
      }
      *--cp = '.';
      addr >>= 8;
   } while (--n > 0);

   /* Convert the string to lowercase */
   retStr = (char*)(cp+1);

   return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
   static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

   return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
   static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

   snprintf(buf, sizeof(buf),
         "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
         addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
         addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
         addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
         addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
         addr6.s6_addr[15]);

   return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
   static char protoName[8];

   switch(proto) {
      case IPPROTO_TCP:  return("TCP");
      case IPPROTO_UDP:  return("UDP");
      case IPPROTO_ICMP: return("ICMP");
      default:
         snprintf(protoName, sizeof(protoName), "%d", proto);
         return(protoName);
   }
}

/* ****************************************************** */

int32_t gmt2local(time_t t) {
   int dt, dir;
   struct tm *gmt, *loc;
   struct tm sgmt;

   if (t == 0)
      t = time(NULL);
   gmt = &sgmt;
   *gmt = *gmtime(&t);
   loc = localtime(&t);
   dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
         (loc->tm_min - gmt->tm_min) * 60;

   /*
    * If the year or julian day is different, we span 00:00 GMT
    * and must add or subtract a day. Check the year first to
    * avoid problems when the julian day wraps.
    */
   dir = loc->tm_year - gmt->tm_year;
   if (dir == 0)
      dir = loc->tm_yday - gmt->tm_yday;
   dt += dir * 24 * 60 * 60;

   return (dt);
}

#endif // verbose

#ifdef PFRING_STATS

static struct timeval startTime;
#define MAX_NUM_THREADS 1
unsigned long long numPkts = 0, numBytes = 0;
u_int8_t wait_for_packet = 1, dna_mode = 0, do_shutdown = 0;

/* *************************************** */
/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
           struct timeval * before) {
  time_t delta_seconds;
  time_t delta_microseconds;

  /*
   * compute delta in second, 1/10's and 1/1000's second units
   */
  delta_seconds      = now -> tv_sec  - before -> tv_sec;
  delta_microseconds = now -> tv_usec - before -> tv_usec;

  if(delta_microseconds < 0) {
    /* manually carry a one from the seconds field */
    delta_microseconds += 1000000;  /* 1e6 */
    -- delta_seconds;
  }
  return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

/* ******************************** */

void print_stats( device_dev_t* dev ) {
  pfring_stat pfringStat;
  struct timeval endTime;
  double deltaMillisec;
  static u_int8_t print_all;
  static u_int64_t lastPkts = 0;
  u_int64_t diff;
  static struct timeval lastTime;

  if(startTime.tv_sec == 0) {
    gettimeofday(&startTime, NULL);
    print_all = 0;
  } else
    print_all = 1;

  gettimeofday(&endTime, NULL);
  deltaMillisec = delta_time(&endTime, &startTime);

  if(pfring_stats(dev->device_handle.pfring, &pfringStat) >= 0) {
    double thpt;
    unsigned long long nBytes = 0, nPkts = 0;

    nBytes += numBytes;
    nPkts += numPkts;

    thpt = ((double)8*nBytes)/(deltaMillisec*1000);

    fprintf(stderr, "=========================\n"
      "Interface: %s\n"
        "Absolute Stats: [%u pkts rcvd][%u pkts dropped]\n"
        "Total Pkts=%u/Dropped=%.1f %%\n",
      dev->device_name,
        (unsigned int)pfringStat.recv, (unsigned int)pfringStat.drop,
        (unsigned int)(pfringStat.recv+pfringStat.drop),
        pfringStat.recv == 0 ? 0 :
        (double)(pfringStat.drop*100)/(double)(pfringStat.recv+pfringStat.drop));
    fprintf(stderr, "%llu pkts - %llu bytes", nPkts, nBytes);

    if(print_all)
      fprintf(stderr, " [%.1f pkt/sec - %.2f Mbit/sec]\n",
          (double)(nPkts*1000)/deltaMillisec, thpt);
    else
      fprintf(stderr, "\n");

    if(print_all && (lastTime.tv_sec > 0)) {
      deltaMillisec = delta_time(&endTime, &lastTime);
      diff = pfringStat.recv-lastPkts;
      fprintf(stderr, "=========================\n"
          "Actual Stats: %llu pkts [%.1f ms][%.1f pkt/sec]\n",
          (long long unsigned int)diff,
          deltaMillisec, ((double)diff/(double)(deltaMillisec/1000)));
    }

    lastPkts = pfringStat.recv;
  }

  lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

  fprintf(stderr, "=========================\n\n");
}

/* ******************************** */


#endif // PFRING_STATS

/* *************************************** */
int pfring_dispatch_wrapper(dh_t dh, int cnt,
               void(*packet_handler)(u_char*, const struct pfring_pkthdr*, const u_char*),
               u_char* user_args) {
   return pfring_dispatch( dh.pfring, cnt, packet_handler, user_args );
}

int pfring_dispatch(pfring* pd, int max_packets,
               void(*packet_handler)(u_char*, const struct pfring_pkthdr*, const u_char*),
               u_char* user_args)
{
   int32_t  recv_ret = 0;
   uint8_t  buffer[BUFFER_SIZE];
   #ifdef verbose
   uint8_t* bufferPtr = buffer;
   #endif

   struct pfring_pkthdr hdr;

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
      switch(recv_ret =  pfring_recv(pd, (char*)buffer, sizeof(buffer), &hdr
                      , 0)) {
         case 0:
               // no packet available
            break;
         case -1:
            perror("pf_ring: recv()");
               return -1;
            break;
         default:
            packet_handler(user_args, &hdr, buffer);
            #ifdef verbose
               struct ether_header ehdr;
               u_short eth_type, vlan_id;
               char buf1[32], buf2[32];
               struct ip ip;
               int s = (hdr.ts.tv_sec + gmt2local(0)) % 86400;

               printf("%02d:%02d:%02d.%06u ",
               s / 3600, (s % 3600) / 60, s % 60,
               (unsigned)hdr.ts.tv_usec);

               if(hdr.extended_hdr.parsed_header_len > 0) {
                  printf("[eth_type=0x%04X]", hdr.extended_hdr.parsed_pkt.eth_type);
                  printf("[l3_proto=%u]", (unsigned int)hdr.extended_hdr.parsed_pkt.l3_proto);

                  printf("[%s:%d -> ", (hdr.extended_hdr.parsed_pkt.eth_type == 0x86DD) ?
                        in6toa(hdr.extended_hdr.parsed_pkt.ipv6_src) : intoa(hdr.extended_hdr.parsed_pkt.ipv4_src),
                        hdr.extended_hdr.parsed_pkt.l4_src_port);
                  printf("%s:%d] ", (hdr.extended_hdr.parsed_pkt.eth_type == 0x86DD) ?
                        in6toa(hdr.extended_hdr.parsed_pkt.ipv6_dst) : intoa(hdr.extended_hdr.parsed_pkt.ipv4_dst),
                        hdr.extended_hdr.parsed_pkt.l4_dst_port);

                  printf("[%s -> %s] ",
                        etheraddr_string(hdr.extended_hdr.parsed_pkt.smac, buf1),
                        etheraddr_string(hdr.extended_hdr.parsed_pkt.dmac, buf2));
               }

               memcpy(&ehdr, bufferPtr+hdr.extended_hdr.parsed_header_len, sizeof(struct ether_header));
               eth_type = ntohs(ehdr.ether_type);

               printf("[%s -> %s][eth_type=0x%04X] ",
                     etheraddr_string(ehdr.ether_shost, buf1),
                     etheraddr_string(ehdr.ether_dhost, buf2), eth_type);

               if(eth_type == 0x8100) {
                  vlan_id = (bufferPtr[14] & 15)*256 + bufferPtr[15];
                  eth_type = (bufferPtr[16])*256 + bufferPtr[17];
                  printf("[vlan %u] ", vlan_id);
                  bufferPtr+=4;
               }

               if(eth_type == 0x0800) {
                  memcpy(&ip, bufferPtr+hdr.extended_hdr.parsed_header_len+sizeof(ehdr), sizeof(struct ip));
                  printf("[%s:%d ", intoa(ntohl(ip.ip_src.s_addr)), hdr.extended_hdr.parsed_pkt.l4_src_port);
                  printf("-> %s:%d] ", intoa(ntohl(ip.ip_dst.s_addr)), hdr.extended_hdr.parsed_pkt.l4_dst_port);

                  printf("[tos=%d][tcp_seq_num=%u][caplen=%d][len=%d][parsed_header_len=%d]"
                        "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
                        hdr.extended_hdr.parsed_pkt.ipv4_tos, hdr.extended_hdr.parsed_pkt.tcp.seq_num,
                        hdr.caplen, hdr.len, hdr.extended_hdr.parsed_header_len,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.eth_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset);

               } else {
                  if(eth_type == 0x0806)
                     printf("[ARP]");
                  else
                     printf("[eth_type=0x%04X]", eth_type);

                  printf("[caplen=%d][len=%d][parsed_header_len=%d]"
                        "[eth_offset=%d][l3_offset=%d][l4_offset=%d][payload_offset=%d]\n",
                        hdr.caplen, hdr.len, hdr.extended_hdr.parsed_header_len,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.eth_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset,
                        hdr.extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset);
               }
            #endif // verbose
            break;

      }
   return 1;
}
#endif // PFRING

#ifndef PFRING
int  set_all_filter( const char* bpf ) {
  int i = 0;

  for( i = 0; i < g_options.number_interfaces; ++i )
  {
    set_filter( &if_devices[i], bpf);
  }
  return 0;
}

int set_filter(device_dev_t* pd, const char* bpf) {
   /* apply filter */
   struct bpf_program fp;

   if (bpf) {
      if (-1 == pcap_compile(pd->device_handle.pcap, &fp,
            bpf, 0, 0)) {
         LOGGER_fatal( "Couldn't parse filter %s: %s"
                , bpf
                , pcap_geterr(pd->device_handle.pcap));
          return -1;
      }
      if (-1 == pcap_setfilter(pd->device_handle.pcap, &fp)) {
         LOGGER_fatal( "Couldn't install filter %s: %s"
                , bpf
                , pcap_geterr(pd->device_handle.pcap));
          return -1;
      }
   }
   return 0;
}

void setFilter(device_dev_t* pcap_device) {
   /* apply filter */
   struct bpf_program fp;

   if (g_options.bpf) {
      if (-1 == pcap_compile(pcap_device->device_handle.pcap, &fp,
            g_options.bpf, 0, 0)) {
         LOGGER_fatal( "Couldn't parse filter %s: %s", g_options.bpf,
               pcap_geterr(pcap_device->device_handle.pcap));
      }
      if (-1 == pcap_setfilter(pcap_device->device_handle.pcap, &fp)) {
         LOGGER_fatal( "Couldn't install filter %s: %s", g_options.bpf,
               pcap_geterr(pcap_device->device_handle.pcap));
      }
   }
}
#endif

#ifdef PFRING
int setPFRingFilter(device_dev_t* pfring_device) {
   uint8_t i = 0;
    // data like hash and selection func which will be passed to kernel filter
    struct impd_data *plugin_data;

    // if no filter was given then define a dummy filter which matches all
    // packets. this filter will call the pf_ring-plugin which handles
    // packet-selection
    // also set filtering policy to accept
    if ( g_options.rules_in_list == 0 ) {
        filtering_rule rule;
        memset(&rule, 0, sizeof(rule));
        // add pf_ring selection plugin
        rule.plugin_action.plugin_id = 23;
        rule.extended_fields.filter_plugin_id = 23;
        plugin_data = (struct impd_data*)rule.extended_fields.filter_plugin_data;
        // TODO: set correct selection-plugin as user demanded
        plugin_data->sel_range_min = 0;
        plugin_data->sel_range_max = 65535;
        plugin_data->hash_function = BOB;
        plugin_data->pktid_function = Net;
        plugin_data->selection_function = Rec;
        //memcpy(&(rule.extended_fields.filter_plugin_data), &plugin_data, sizeof(struct plugin_data));
        g_options.rules[0] = rule;
        g_options.rules_in_list++;
        // also set filtering policy to accept
        g_options.filter_policy = 1;
    }
    else {
        // rules were set to explicitly allow some packets.
        // the pf_ring-plugin which handles packet-selection is called with
        // each matching rule.
        // set default filtering policy to drop all other packets.
        g_options.filter_policy = 0;
    }

   for ( i = 0; i < g_options.rules_in_list; i++ ) {
        // add pf_ring selection plugin
        g_options.rules[i].plugin_action.plugin_id = 23;
        g_options.rules[i].extended_fields.filter_plugin_id = 23;
        plugin_data = (struct impd_data*)g_options.rules[i].extended_fields.filter_plugin_data;
        // TODO: set correct selection-plugin as user demanded
        plugin_data->sel_range_min = g_options.sel_range_min;
        plugin_data->sel_range_max = g_options.sel_range_max;
        plugin_data->hash_function = BOB;
        plugin_data->pktid_function = BOB;
        plugin_data->selection_function = U_TCP_and_Net;

      if(pfring_add_filtering_rule(pfring_device->device_handle.pfring,
                               &g_options.rules[i]) < 0) {
         LOGGER_fatal( "setPFRingFilter(%d) failed", i);
         return -1;
      }
      LOGGER_fatal( "setPFRingFilter(%d) succeeded", i);
   }
   return 0;
}

int8_t setPFRingFilterPolicy(device_dev_t* pfring_device) {

   // check if user supplied filtering policy and if not, set it to ACCEPT
   if( g_options.filter_policy == -1 )
      g_options.filter_policy = 1;

   if(pfring_toggle_filtering_policy(pfring_device->device_handle.pfring,
         g_options.filter_policy) < 0) {
      LOGGER_fatal( "setPFRingFilterPolicy(%d) failed", g_options.filter_policy);
      return -1;
   }
   LOGGER_fatal( "setPFRingFilterPolicy(%d) succeeded", g_options.filter_policy);
   return 0;
}
#endif //PFRING

void print_byte_array_hex( uint8_t* p, int length ) {
   int i = 0;
   fprintf( stderr, "bytes(length=%d): ", length );
   for( i = 0; i < length; ++i )
      fprintf( stderr, "%02x ", p[i] );
   fprintf( stderr, "\n" );
}




