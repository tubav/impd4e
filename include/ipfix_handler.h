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

#ifndef _IPFIX_HANDLER_H_
#define _IPFIX_HANDLER_H_


#include "settings.h"

// -----------------------------------------------------------------------------
// Type definitions
// -----------------------------------------------------------------------------

//export_fields_t export_fields_min[] = {
//export_fields_t export_fields_ts[] = {
//export_fields_t export_fields_ts_ttl_proto[] = {
//export_fields_t export_fields_ts_ttl_proto_ip[] = {
//export_fields_t export_fields_openepc[] = {
//
//export_fields_t export_fields_location[] = {
//export_fields_t export_fields_sync[] = {
//export_fields_t export_fields_probe_stats[] = {
//export_fields_t export_fields_interface_stats[] = {

// template definition
// array indecies: they must be continious and must start with 0
typedef enum template_id_u{
        LOCATION_ID = 0
      , SYNC_ID
      , PROBE_STATS_ID
      , INTF_STATS_ID
      , MINT_ID
      , TS_ID
      , TS_TTL_PROTO_ID
      , TS_TTL_PROTO_IP_ID
      , TS_OPEN_EPC_ID
      , TS_ID_EPC_ID
}
template_id_t;

#define MIN_NAME              "min"
#define TS_TTL_RROTO_NAME     "lp"
#define TS_NAME               "ts"
#define TS_TTL_RROTO_IP_NAME  "ls"
#define TS_OPEN_EPC           "tsep"
#define TS_ID_EPC             "tsip"



// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

// return ipfix handle
inline ipfix_t* ipfix();

void libipfix_init(uint32_t observation_id);
void libipfix_register_templates();
void libipfix_connect( options_t *options );

//void libipfix_open(device_dev_t *if_device, options_t *options);

void libipfix_reconnect();

ipfix_template_t* get_template( int template_id );

void export_flush();

#endif /* _IPFIX_HANDLER_H_*/

