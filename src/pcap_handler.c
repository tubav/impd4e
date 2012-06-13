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


// system header files
#include <stdlib.h>

#ifndef PFRING
#include <pcap.h>
#endif

// local header files
#include "pcap_handler.h"

#include "ev_handler.h"
#include "packet_handler.h"

#include "settings.h"
#include "helper.h"

#include "logger.h"


#ifndef PFRING
void determineLinkType(device_dev_t* pcap_device) {
   pcap_device->link_type = pcap_datalink(pcap_device->device_handle.pcap);
   switch (pcap_device->link_type) {
   case DLT_EN10MB:
      // Ethernet
      pcap_device->pkt_offset = 14;
      LOGGER_info("dltype: DLT_EN10M");
      break;
   case DLT_ATM_RFC1483:
      pcap_device->pkt_offset = 8;
      LOGGER_info("dltype: DLT_ATM_RFC1483");
      break;
   case DLT_LINUX_SLL:
      pcap_device->pkt_offset = 16;
      LOGGER_info("dltype: DLT_LINUX_SLL");
      break;
   case DLT_RAW:
      pcap_device->pkt_offset = 0;
      LOGGER_info("dltype: DLT_RAW");
      break;
   default:
      LOGGER_fatal( "Link Type (%d) not supported - default to DLT_RAW", pcap_device->link_type);
      pcap_device->pkt_offset = 0;
      break;
   }
}
#endif

#ifndef PFRING
int pcap_dispatch_wrapper(dh_t dh, int cnt, pcap_handler ph, u_char* ua) {
   LOGGER_trace("Enter");
   return pcap_dispatch( dh.pcap, cnt, ph, ua );
   LOGGER_trace("Return");
   return 0;
}

void open_pcap_file(device_dev_t* if_dev, options_t *options) {

   // todo: parameter check
   pcap_t * pcap = NULL;
   pcap = pcap_open_offline(if_dev->device_name, errbuf);
   if (NULL == pcap) {
      LOGGER_fatal( "%s", errbuf);
   }
   if_dev->device_handle.pcap = pcap;
   if_dev->dh.pcap = pcap;
   if_dev->dispatch = pcap_dispatch_wrapper;

   determineLinkType(if_dev);
   setFilter(if_dev);

   // TODO: some rework is still needed
   // register timer handling for files to be read to ev_handler
   LOGGER_debug("Register io handling for interface: %s", if_dev->device_name);

   setNONBlocking(if_dev);

   int fd = get_file_desc(if_dev);
   LOGGER_debug("File Descriptor: %d", fd);

   /* storing a reference of packet device to
    be passed via watcher on a packet event so
    we know which device to read the packet from */
   LOGGER_info("register event timer: read pcap file (%s)", if_dev->device_name);
   ev_watcher* watcher = event_register_timer(EV_DEFAULT_ packet_watcher_cb, 1);
   watcher->data = (device_dev_t *) if_dev;

   return;
}

void open_pcap(device_dev_t* if_dev, options_t *options) {

   pcap_t * pcap = NULL;
   pcap = pcap_open_live(if_dev->device_name,
         options->snapLength, 1, 1000, errbuf);
   if (NULL == pcap) {
      LOGGER_fatal( "%s", errbuf);
      exit(1);
   }

   if_dev->device_handle.pcap = pcap;
   if_dev->dh.pcap = pcap;
   if_dev->dispatch = pcap_dispatch_wrapper;

   // if (pcap_lookupnet(options->if_names[i],
   //		&(if_devices[i].IPv4address), &(if_devices[i].mask), errbuf)
   //		< 0) {
   //	printf("could not determine netmask and Ip-Adrdess of device %s \n",
   //			options->if_names[i]);
   // }

   /* I want IP address attached to device */
   if_dev->IPv4address = getIPv4AddressFromDevice(if_dev->device_name);

   /* display result */
   fprintf( stderr , "Device %s has IP %s\n"
         , if_dev->device_name
         , ntoa(if_dev->IPv4address));

   determineLinkType(if_dev);
   setFilter(if_dev);

   // TODO: some rework is still needed
   // register read handling to ev_handler
   LOGGER_debug("Register io handling for interface: %s", if_dev->device_name);

   setNONBlocking(if_dev);

   int fd = get_file_desc(if_dev);
   LOGGER_debug("File Descriptor: %d", fd);

   /* storing a reference of packet device to
    be passed via watcher on a packet event so
    we know which device to read the packet from */
   // TODO: implement an own packet watcher callback
   LOGGER_info("register event io: read pcap interface (%s)", if_dev->device_name);
   ev_watcher* watcher = event_register_io_r(EV_DEFAULT_ packet_watcher_cb, fd);
   watcher->data = (device_dev_t *) if_dev;

   return;
}
#endif // #ifndef PFRING


