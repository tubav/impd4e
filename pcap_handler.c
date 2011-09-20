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

// Custom logger
#include "logger.h"

#include "pcap_handler.h"
#include "settings.h"
#include "helper.h"

#ifndef PFRING
#include <pcap.h>
#endif

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
void open_pcap_file(device_dev_t* if_dev, options_t *options) {

   // todo: parameter check

   if_dev->device_handle.pcap = pcap_open_offline(if_dev->device_name, errbuf);
   if (NULL == if_dev->device_handle.pcap) {
      LOGGER_fatal( "%s", errbuf);
   }
   determineLinkType(if_dev);
   setFilter(if_dev);
}

void open_pcap(device_dev_t* if_dev, options_t *options) {

   if_dev->device_handle.pcap = pcap_open_live(if_dev->device_name,
         options->snapLength, 1, 1000, errbuf);
   if (NULL == if_dev->device_handle.pcap) {
      LOGGER_fatal( "%s", errbuf);
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
   fprintf( stderr , "Device %s has IP %s\n"
         , if_dev->device_name
         , ntoa(if_dev->IPv4address));

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
   //				LOGGER_fatal( "read wrong IP format of Interface %s ",
   //						options->if_names[i]);
   //				exit(1);
   //			}
   //			if_devices[i].IPv4address = ntohl((uint32_t) inp.s_addr);
   //			LOGGER_info( "Device %s has IP %s", options->if_names[i], htoa(
   //					if_devices[i].IPv4address));
   //			pclose(fp);

}
#endif // #ifndef PFRING


