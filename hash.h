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


#ifndef HASH_H_
#define HASH_H_


#define BITS_PER_BYTE 8
#define bitsizeof(t) (sizeof(t) * BITS_PER_BYTE)

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "constants.h"



// find layers in pcap paket
void findHeaders( const uint8_t *packet, uint16_t packetLength, uint32_t *headerOffset, uint8_t *layers );

// parse range selection from given parameter
// used to be a comma seperated list of byte offsets and ranges
void parseRange( char* arg );


uint32_t copyFields_Rec( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Only_Net( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_U_TCP_and_Net( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Packet( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Raw( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Link( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Net( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Trans( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint32_t copyFields_Payload( packet_t *packet,
      buffer_t *buffer,
      uint32_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Select(const uint8_t *packet, uint16_t packetLength,
      uint8_t *outBuffer, uint16_t outBufferLength );

uint32_t calcHashValue_BOB        ( buffer_t * );
uint32_t calcHashValue_Hsieh      ( buffer_t * );
uint32_t calcHashValue_OAAT       ( buffer_t * );
uint32_t calcHashValue_TWMXRSHash ( buffer_t * );
//uint32_t calcHashValue_SBOX       ( buffer_t * );

#endif /*HASH_H_*/
