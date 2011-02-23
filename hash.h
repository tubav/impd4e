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




typedef enum {
	L_LINK = 0,
	L_NET,
	L_TRANS,
	L_PAYLOAD
} OSIlayer_t;


typedef enum {
    L_UNKNOWN = 0,
    L_ETHERNET,
    L_ATM_RFC1483
} linkProt_t;

typedef enum {
    N_UNKNOWN = 0,
    N_IP = 4,
    N_IP6 = 6
} netProt_t;

typedef enum {
    T_UNKNOWN = 0,
    T_ICMP    = 1,
    T_IGMP    = 2,
    T_GGP     = 3,
    T_IPIP    = 4,
    T_STREAM  = 5,
    T_TCP     = 6,
    T_EGP     = 8,
    T_IGP     = 9,
    T_UDP     = 17,
    T_MUX     = 18,
    T_IDPR    = 35,
    T_IPV6    = 41,
    T_IDRP    = 45,
    T_RSVP    = 46,
    T_GRE     = 47,
    T_MOBILE  = 55,
    T_ICMP6   = 58
} transProt_t;

typedef enum {
	P_NONE = 0,
	P_EXISTS = 1
} payload_t;

// get the ttl-field of an IPv4 header
uint8_t getTTL( const uint8_t *packet, uint16_t packetLength, int16_t offset, netProt_t nettype );

// find layers in pcap paket
void findHeaders( const uint8_t *packet, uint16_t packetLength, int16_t *headerOffset, uint8_t *layers );

// parse range selection from given parameter
// used to be a comma seperated list of byte offsets and ranges
void parseRange( char* arg );


uint16_t copyFields_Rec( const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Only_Net(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_U_TCP_and_Net(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]			);

uint16_t copyFields_Packet(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Raw(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Link(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Net(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Trans(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Payload(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]);

uint16_t copyFields_Select(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength );

uint32_t calcHashValue_BOB( uint8_t *dataBuffer, uint16_t dataBufferLength );
uint32_t calcHashValue_Hsieh( uint8_t *dataBuffer, uint16_t dataBufferLength );
uint32_t calcHashValue_OAAT(uint8_t *dataBuffer, uint16_t dataBufferLength);
uint32_t calcHashValue_TWMXRSHash(uint8_t *dataBuffer, uint16_t dataBufferLength);
//uint32_t calcHashValue_SBOX(uint8_t *dataBuffer,uint16_t dataBufferLength);

#endif /*HASH_H_*/
