#ifndef HASH_H_
#define HASH_H_


#define BITS_PER_BYTE 8
#define bitsizeof(t) (sizeof(t) * BITS_PER_BYTE)

#include <stdbool.h>



void findHeaders( const uint8_t *packet, uint16_t packetLength, int16_t *headerOffset, uint8_t *layers, uint8_t *ttl);  // find layers in pcap paket


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

uint32_t calcHashValue_BOB( uint8_t *dataBuffer, uint16_t dataBufferLength );
uint32_t calcHashValue_Hsieh( uint8_t *dataBuffer, uint16_t dataBufferLength );
uint32_t calcHashValue_OAAT(uint8_t *dataBuffer, uint16_t dataBufferLength);
//uint32_t calcHashValue_SBOX(uint8_t *dataBuffer,uint16_t dataBufferLength);
uint32_t calcHashValue_TWMXRSHash(uint8_t *dataBuffer, uint16_t dataBufferLength);

#endif /*HASH_H_*/
