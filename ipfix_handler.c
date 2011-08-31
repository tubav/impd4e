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

#include <string.h> // strerror()
#include <errno.h>  // errno
#include <stdlib.h> // exit()

// Custom logger
#include "logger.h"

#include "settings.h"
#include "ipfix_handler.h"

// ipfix staff
#include "ipfix.h"
#include "ipfix_def.h"
#include "ipfix_def_fokus.h"
#include "ipfix_fields_fokus.h"
#include "templates.h"

// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// Global Variables
// -----------------------------------------------------------------------------
ipfix_t*          ipfix_handle = NULL;


// -----------------------------------------------------------------------------
// Structures, Typedefs
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------


// -----------------------------------------------------------------------------
// Functions
// -----------------------------------------------------------------------------
ipfix_t* ipfix() {
   if( NULL == ipfix_handle ) {
      LOGGER_fatal( "ipfix module is not successfully initialised");
      exit(EXIT_FAILURE);
   }
   return ipfix_handle;
}

// -----------------------------------------------------------------------------

void libipfix_init() {
   if (ipfix_init() < 0) {
      LOGGER_fatal( "cannot init ipfix module: %s", strerror(errno));

   }
   if (ipfix_add_vendor_information_elements(ipfix_ft_fokus) < 0) {
      LOGGER_fatal( "cannot add FOKUS IEs: %s\n", strerror(errno));
      exit(EXIT_FAILURE);
   }
}

// -----------------------------------------------------------------------------

void libipfix_open(device_dev_t *if_device, options_t *options) {
   // set initial export packe count
   if_device->export_packet_count = 0;

   // use observationDomainID if explicitely given via
   // cmd line, else use interface IPv4address as oid
   // TODO: alternative oID instead of IP address --> !!different device types!!
   uint32_t odid = (options->observationDomainID != 0)
      ? options->observationDomainID
      : if_device->IPv4address;

   if( options->use_oid_first_interface ){
      odid = if_devices[0].IPv4address;
   }

   if (ipfix_open(&(if_device->ipfixhandle), odid, IPFIX_VERSION) < 0) {
      LOGGER_fatal( "ipfix_open() failed: %s", strerror(errno));

   }

   // add collector
   // -------------------------------------------------------------------------
   if (ipfix_add_collector(if_device->ipfixhandle,
            options->collectorIP, options->collectorPort, IPFIX_PROTO_TCP) < 0) {
      LOGGER_error("ipfix_add_collector(%s,%d) failed: %s",
            options->collectorIP, options->collectorPort, strerror(errno));
   }

   // create templates
   // -------------------------------------------------------------------------
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
           if_device->ipfixtmpl_ts_ttl_ip,
           export_fields_ts_ttl_proto_ip) < 0) {
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
   if (IPFIX_MAKE_TEMPLATE(if_device->ipfixhandle,
            if_device->ipfixtmpl_location, export_fields_location) < 0) {
      LOGGER_fatal("template initialization failed: %s", strerror(errno));
      exit(EXIT_FAILURE);
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

