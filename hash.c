/* impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll) & TU-Berlin (Christian Henke)
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation;
 *  either version 3 of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <inttypes.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <math.h>
#include <pcap.h>
#include <string.h>


#include <arpa/inet.h>
#include "mlog.h"
#include "constants.h"

#include "hash.h"
#include "bobhash.h"
#include "hsieh.h"
#include "twmx.h"




#define min(X, Y)                \
({ typeof (X) x_ = (X);          \
   typeof (Y) y_ = (Y);          \
   (x_ < y_) ? x_ : y_; })


const uint32_t initval=0x32545;

//! netmask for filter code
//! do not try to get the real one -> ip broadcast wont work
const unsigned long NETMASK = 0x0;

// fixed header lengths


const int ETHER_HLEN = 14;
const int UDP_HLEN = 8;
const int ICMP_HLEN = 4;
const int ICMP6_HLEN = 4;
const int IP6_HLEN = 40;

/* IPv6 extension header types */
const uint8_t IP6HDR_HOP   =  0;
const uint8_t IP6HDR_ROUTE = 43;
const uint8_t IP6HDR_FRAG  = 44;
const uint8_t IP6HDR_DEST  = 60;
const uint8_t IP6HDR_AH    = 51;
const uint8_t IP6HDR_ESP   = 50;

const int OFLAG = 1;

/** copies the IP Header into the hash input */
// assume 'findHeaders()' run before calling that function
uint16_t copy_NetFields( const uint8_t* packet, uint16_t packetLength
					   , uint8_t* outBuffer, uint16_t outBufferLength
					   , int16_t headerOffset[4], uint8_t layers[4] )
{	// copy Net_Layer_Fields

	uint16_t length = 0;

	if (layers[L_NET] == N_IP) {  // case IPv4

		//  we choose the fields of IP Header which are static between hops but are variable between flows
		 memcpy(outBuffer,   packet+headerOffset[L_NET],    8);
		 memcpy(outBuffer+8, packet+headerOffset[L_NET]+9,  1);
		 memcpy(outBuffer+9, packet+headerOffset[L_NET]+12, 8);
		 length=17;

	}
	if (layers[L_NET] == N_IP6)  { // case IPv6
	 	memcpy(outBuffer,   packet+headerOffset[L_NET],   7);
		memcpy(outBuffer+7, packet+headerOffset[L_NET]+8, 32);
		length +=39;
	}
	return length;
}


/** copy recommended 8 bytes -- only TCP UDP ICMP supported */

uint16_t copyFields_Rec( const uint8_t *packet,   uint16_t packetLength
					   , uint8_t *outBuffer,      uint16_t outBufferLength
					   , int16_t headerOffset[4], uint8_t layers[4] ) { // these are just pointer, the size doesn't matter

	uint16_t copiedbytes=0;

	// find headers of the IP STACK
	findHeaders(packet, packetLength, headerOffset, layers);

	if ((headerOffset[L_TRANS] != -1) && (layers[L_TRANS] != T_UNKNOWN) ) {
		if (layers[L_NET] == N_IP) {
				memcpy(outBuffer,packet+headerOffset[L_NET]+4,2); // IP ID
				copiedbytes+=2;
				if (layers[L_TRANS] == T_TCP) {
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+6,2);
					copiedbytes+=2;
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+10,2);
					copiedbytes+=2;
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+16,2);
					copiedbytes+=2;
				}
				if (layers[L_TRANS] == T_UDP) {
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS],2);
					copiedbytes+=2;
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+3,1);
					copiedbytes+=1;
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+5,3);
					copiedbytes+=3;
				}
				if ((layers[L_TRANS] == T_ICMP) || (layers[L_TRANS] == T_ICMP6)) {
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+2,2);
					copiedbytes+=2;
					memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS]+12,4);
					copiedbytes+=4;
				}
		}
	}

return copiedbytes;
}


/** copies the IP Header into the hash input */

uint16_t copyFields_Only_Net( const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]
			 )
{	// copy Net_Layer_Fields

	uint16_t copiedbytes = 0;

	// find headers of the IP STACK
	// todo: probably not needed here; just case for IP which used to be known already
	// todo: or it can be simplified
	findHeaders(packet, packetLength, headerOffset, layers);

	copiedbytes = copy_NetFields( packet,       packetLength
			                    , outBuffer,    outBufferLength
			                    , headerOffset, layers);

	return copiedbytes;
}

/** copies the IP Header and Transport Header (only TCP,ICMP,UDP) into the Hash Input */

uint16_t copyFields_U_TCP_and_Net( const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]
			)
{
	uint16_t  copiedbytes=0;
	int 	  piece_length = 0;

	// find headers of the IP STACK
	findHeaders(packet, packetLength, headerOffset, layers);

	copiedbytes = copy_NetFields( packet,       packetLength
			                    , outBuffer,    outBufferLength
			                    , headerOffset, layers);

	// check if there is a transport layer included in the packet
	if ((headerOffset[L_TRANS] != -1) && (layers[L_TRANS] != T_UNKNOWN) ) {
		if ( (layers[L_TRANS] == T_TCP) || (layers[L_TRANS] == T_ICMP) || (layers[L_TRANS] == T_ICMP6) ) {
		    piece_length = min(20,packetLength-(headerOffset[L_TRANS]));
		    memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS],piece_length);
		    copiedbytes += piece_length;
		}
		if (layers[L_TRANS] == T_UDP) {
			piece_length = min(8,packetLength-(headerOffset[L_TRANS]));
			memcpy(outBuffer+copiedbytes,packet+headerOffset[L_TRANS],piece_length);
			copiedbytes += piece_length;
		}
	}
	else {
		copiedbytes = 0;
	}

	return copiedbytes;
}

/** copy everything that is in the packet except variable fields into the hash input */

uint16_t copyFields_Packet( const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4]
			)
{
	uint16_t copiedbytes = 0;
	int piecelength      = 0;

	// find headers of the IP STACK
	findHeaders(packet, packetLength, headerOffset, layers);

	copiedbytes = copy_NetFields( packet,       packetLength
			                    , outBuffer,    outBufferLength
			                    , headerOffset, layers);

	piecelength = min(packetLength-20, 50);
	memcpy(outBuffer+copiedbytes,packet+headerOffset[L_NET]+20,piecelength);

	return (copiedbytes+packetLength-20);
}

uint16_t copyFields_Raw(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4])
{
	//mlogf( ALWAYS ,"copyFields_Raw(): pL=%d, bL=%d\n", packetLength, outBufferLength);

	// uint16_t length = min( packetLength, outBufferLength );
	memcpy( outBuffer, packet, packetLength);

	return packetLength; // length;
}

uint16_t copyFields_Select(const uint8_t *packet, uint16_t packetLength,
			 uint8_t *outBuffer, uint16_t outBufferLength,
			 int16_t headerOffset[4], uint8_t layers[4])
{
	mlogf( ALWAYS ,"copyFields_Select(): not yet implemented\n");
	return 0;
}



//
//
uint32_t calcHashValue_BOB( uint8_t *dataBuffer, uint16_t dataBufferLength )
{	uint32_t result;
   	result = BOB_Hash(dataBuffer,dataBufferLength, initval);
    return result;
}

uint32_t calcHashValue_Hsieh( uint8_t *dataBuffer, uint16_t dataBufferLength )
{	uint32_t result;
	result = Hsieh_Hash((char*)dataBuffer,dataBufferLength);
    return result;
}

uint32_t calcHashValue_OAAT(uint8_t *dataBuffer, uint16_t dataBufferLength){
  uint32_t   hash, i;
  for (hash=0, i=0; i<dataBufferLength; ++i)
  {
    hash += dataBuffer[i];
    hash += (hash << 10);
    hash ^= (hash >> 6);
  }
  hash += (hash << 3);
  hash ^= (hash >> 11);
  hash += (hash << 15);
  return hash;
}

uint32_t calcHashValue_SBOX(uint8_t *dataBuffer,uint16_t dataBufferLength)
    {	uint64_t sbox[256] = {
    	0xF53E1837, 0x5F14C86B, 0x9EE3964C, 0xFA796D53,
        0x32223FC3, 0x4D82BC98, 0xA0C7FA62, 0x63E2C982,
        0x24994A5B, 0x1ECE7BEE, 0x292B38EF, 0xD5CD4E56,
        0x514F4303, 0x7BE12B83, 0x7192F195, 0x82DC7300,
        0x084380B4, 0x480B55D3, 0x5F430471, 0x13F75991,
        0x3F9CF22C, 0x2FE0907A, 0xFD8E1E69, 0x7B1D5DE8,
        0xD575A85C, 0xAD01C50A, 0x7EE00737, 0x3CE981E8,
        0x0E447EFA, 0x23089DD6, 0xB59F149F, 0x13600EC7,
        0xE802C8E6, 0x670921E4, 0x7207EFF0, 0xE74761B0,
        0x69035234, 0xBFA40F19, 0xF63651A0, 0x29E64C26,
        0x1F98CCA7, 0xD957007E, 0xE71DDC75, 0x3E729595,
        0x7580B7CC, 0xD7FAF60B, 0x92484323, 0xA44113EB,
        0xE4CBDE08, 0x346827C9, 0x3CF32AFA, 0x0B29BCF1,
        0x6E29F7DF, 0xB01E71CB, 0x3BFBC0D1, 0x62EDC5B8,
        0xB7DE789A, 0xA4748EC9, 0xE17A4C4F, 0x67E5BD03,
        0xF3B33D1A, 0x97D8D3E9, 0x09121BC0, 0x347B2D2C,
        0x79A1913C, 0x504172DE, 0x7F1F8483, 0x13AC3CF6,
        0x7A2094DB, 0xC778FA12, 0xADF7469F, 0x21786B7B,
        0x71A445D0, 0xA8896C1B, 0x656F62FB, 0x83A059B3,
        0x972DFE6E, 0x4122000C, 0x97D9DA19, 0x17D5947B,
        0xB1AFFD0C, 0x6EF83B97, 0xAF7F780B, 0x4613138A,
        0x7C3E73A6, 0xCF15E03D, 0x41576322, 0x672DF292,
        0xB658588D, 0x33EBEFA9, 0x938CBF06, 0x06B67381,
        0x07F192C6, 0x2BDA5855, 0x348EE0E8, 0x19DBB6E3,
        0x3222184B, 0xB69D5DBA, 0x7E760B88, 0xAF4D8154,
        0x007A51AD, 0x35112500, 0xC9CD2D7D, 0x4F4FB761,
        0x694772E3, 0x694C8351, 0x4A7E3AF5, 0x67D65CE1,
        0x9287DE92, 0x2518DB3C, 0x8CB4EC06, 0xD154D38F,
        0xE19A26BB, 0x295EE439, 0xC50A1104, 0x2153C6A7,
        0x82366656, 0x0713BC2F, 0x6462215A, 0x21D9BFCE,
        0xBA8EACE6, 0xAE2DF4C1, 0x2A8D5E80, 0x3F7E52D1,
        0x29359399, 0xFEA1D19C, 0x18879313, 0x455AFA81,
        0xFADFE838, 0x62609838, 0xD1028839, 0x0736E92F,
        0x3BCA22A3, 0x1485B08A, 0x2DA7900B, 0x852C156D,
        0xE8F24803, 0x00078472, 0x13F0D332, 0x2ACFD0CF,
        0x5F747F5C, 0x87BB1E2F, 0xA7EFCB63, 0x23F432F0,
        0xE6CE7C5C, 0x1F954EF6, 0xB609C91B, 0x3B4571BF,
        0xEED17DC0, 0xE556CDA0, 0xA7846A8D, 0xFF105F94,
        0x52B7CCDE, 0x0E33E801, 0x664455EA, 0xF2C70414,
        0x73E7B486, 0x8F830661, 0x8B59E826, 0xBB8AEDCA,
        0xF3D70AB9, 0xD739F2B9, 0x4A04C34A, 0x88D0F089,
        0xE02191A2, 0xD89D9C78, 0x192C2749, 0xFC43A78F,
        0x0AAC88CB, 0x9438D42D, 0x9E280F7A, 0x36063802,
        0x38E8D018, 0x1C42A9CB, 0x92AAFF6C, 0xA24820C5,
        0x007F077F, 0xCE5BC543, 0x69668D58, 0x10D6FF74,
        0xBE00F621, 0x21300BBE, 0x2E9E8F46, 0x5ACEA629,
        0xFA1F86C7, 0x52F206B8, 0x3EDF1A75, 0x6DA8D843,
        0xCF719928, 0x73E3891F, 0xB4B95DD6, 0xB2A42D27,
        0xEDA20BBF, 0x1A58DBDF, 0xA449AD03, 0x6DDEF22B,
        0x900531E6, 0x3D3BFF35, 0x5B24ABA2, 0x472B3E4C,
        0x387F2D75, 0x4D8DBA36, 0x71CB5641, 0xE3473F3F,
        0xF6CD4B7F, 0xBF7D1428, 0x344B64D0, 0xC5CDFCB6,
        0xFE2E0182, 0x2C37A673, 0xDE4EB7A3, 0x63FDC933,
        0x01DC4063, 0x611F3571, 0xD167BFAF, 0x4496596F,
        0x3DEE0689, 0xD8704910, 0x7052A114, 0x068C9EC5,
        0x75D0E766, 0x4D54CC20, 0xB44ECDE2, 0x4ABC653E,
        0x2C550A21, 0x1A52C0DB, 0xCFED03D0, 0x119BAFE2,
        0x876A6133, 0xBC232088, 0x435BA1B2, 0xAE99BBFA,
        0xBB4F08E4, 0xA62B5F49, 0x1DA4B695, 0x336B84DE,
        0xDC813D31, 0x00C134FB, 0x397A98E6, 0x151F0E64,
        0xD9EB3E69, 0xD3C7DF60, 0xD2F2C336, 0x2DDD067B,
        0xBD122835, 0xB0B3BD3A, 0xB0D54E46, 0x8641F1E4,
        0xA0B38F96, 0x51D39199, 0x37A6AD75, 0xDF84EE41,
        0x3C034CBA, 0xACDA62FC, 0x11923B8B, 0x45EF170A,
	};
        uint32_t hash = 0;
        uint16_t i;
        for (i = 0; i< dataBufferLength; i++ )
        {
            hash ^= sbox[dataBuffer[i]];
            hash *= 3;
        }
        return hash;
    }



uint32_t calcHashValue_TWMXRSHash(uint8_t *dataBuffer, uint16_t dataBufferLength) {
	uint32_t result;
   	result = TWMXHash(dataBuffer,dataBufferLength, initval);
   	return result;
}


uint8_t getTTL( const uint8_t *packet, uint16_t packetLength, int16_t offset, netProt_t nettype )
{
	if( N_IP == nettype ) return packet[offset + 8];
	else return 0;
}


void findHeaders( const uint8_t *packet, uint16_t packetLength, int16_t *headerOffset, uint8_t *layers )
{
    unsigned short offs = headerOffset[L_NET];
    int net_type = 0;
    int proto = 0;
    // printf("IPv4 Packet \n", headerOffset[L_NET]);
    headerOffset[L_TRANS]   = -1;  // the offset will be -1.
    headerOffset[L_PAYLOAD] = -1;

    // get the type of this layer from the IP version
	if ((packet[headerOffset[L_NET]] & 0xf0) == (6<<4)) {
		net_type = 0x86DD;  // IPv6
	}
	else if ((packet[headerOffset[L_NET]] & 0xf0) == (4<<4)) {
		net_type = 0x0800;
	}
	else {
		// todo: global constant header file
		mlogf( WARNING ,"***NO IPV4/IPv6 packet ***\n");
		net_type = 0; // neither v4 nor v6, should not happen for raw IP link type
	}


    switch (net_type) {
    case 0x0800:
        // IPv4
        offs += ((packet[headerOffset[L_NET]] & 0x0F) << 2);  // IHL -> bits 4-7 schow length in 32 bits values
        proto = packet[headerOffset[L_NET] + 9];
        layers[L_NET] = N_IP;
        break;
    case 0x86DD:
    	layers[L_NET] = N_IP6;
        // IPv6
        offs += IP6_HLEN;  // 40 byte IP6 Length
        proto = packet[headerOffset[L_NET] + 6];
        // IPv6 skip options
        // FIXME currenty ESP is not supported
        while (	   (proto == IP6HDR_HOP)
        		|| (proto == IP6HDR_ROUTE)
        		|| (proto == IP6HDR_FRAG)
        		|| (proto == IP6HDR_AH)
        		|| (proto == IP6HDR_DEST) )
        {
            if (proto != IP6HDR_AH) {
                offs += packet[headerOffset[L_NET] + offs + 1] * 8 + 8;
            } else {
                offs += packet[headerOffset[L_NET] + offs + 1] * 4 + 8;
            }
            proto = packet[headerOffset[L_NET] + offs];
        }

        break;
    default:
        offs = 0;
        layers[L_NET] = N_UNKNOWN;
        return;
    }

    if (offs<packetLength) {
        headerOffset[L_TRANS] = offs;
    } else {
    	return;
    }

    layers[L_TRANS] = proto;
    // only support ICMP, UDP and TCP for now
    switch (proto) {
    case IPPROTO_ICMP:
        offs += ICMP_HLEN;
	//	layers[L_TRANS] = T_ICMP;
        break;
    case IPPROTO_ICMPV6:
        offs += ICMP6_HLEN;
    //    layers[L_TRANS] = T_ICMP6;
        break;
    case IPPROTO_UDP:
        offs += UDP_HLEN;
     //   layers[L_TRANS] = T_UDP;
        break;
    case IPPROTO_TCP:
    	if (packetLength >= headerOffset[L_TRANS] + 12) {
    		offs += (packet[headerOffset[L_TRANS] + 12 ] & 0xF0) >> 2;
    	}
    //     layers[L_TRANS] = T_TCP;
         break;
    default:
        offs = 0;
    //    layers[L_TRANS] = T_UNKNOWN;
        return;
    }
    if (offs<packetLength) {
        headerOffset[L_PAYLOAD] = offs;
    }
    else {
   		return;
    }
}
//
// /** is the packet inside the hash selection range? */
//

//
// /** calculates the hash value over the hash input */
//
//void hashPacket(Hash_t* Hash )
//    {
//
//
//	findHeaders( Hash->packet, Hash->packetLength, Hash->headerOffset, Hash->layers );
//
//
//	if (!(selectFieldsCopyFunction(Hash))) {
//		printf("not a valid copyfunction");
//    	}
//
//
//
//	/* append some payload bytes to copied fields */
//
// 	if (Hash->copiedBytes != 0) {
// 	   switch (Hash->hash_function_ID) {
// 	   	case FUNCTION_BOB: Hash->hashResult = calcHashValue_BOB(Hash->buffer,Hash->copiedBytes); break;
// 	   	case FUNCTION_HSIEH: Hash->hashResult = calcHashValue_Hsieh(Hash->buffer,Hash->copiedBytes); break;
// 	   	case FUNCTION_OAAT: Hash->hashResult = calcHashValue_OAAT(Hash->buffer,Hash->copiedBytes); break;
// 	   	case FUNCTION_SBOX: Hash->hashResult = calcHashValue_SBOX(Hash->buffer,Hash->copiedBytes); break;
// 	   	case FUNCTION_TWMX: Hash->hashResult = calcHashValue_TWMXRSHash(Hash->buffer,Hash->copiedBytes); break;
// 	   	default: break;
// 	   }
//	}
// }












