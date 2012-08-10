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
#include <errno.h>     // errno
#include <string.h>    // strerror
#include <arpa/inet.h> // ntohs
#include <pcap.h>
#include <time.h>
//#include <ipfix.h>

#ifdef PFRING
#include <sys/time.h>
#endif

// local header files
#include "packet_handler.h"

#include "ev_handler.h"
#include "ipfix_handler.h"

#include "hash.h"

//#include "helper.h"
#include "settings.h" // g_options
#include "constants.h"
#include "logger.h"


#define OP_CODE 1 /* identifies a rule packet for openepc*/

/**
 * Called whenever a new packet is available. Note that packet_pcap_cb is
 * responsible for reading the packet.
 *
 * TODO: each interface handler should implement its own packet watcher callback
 */
void packet_watcher_cb(EV_P_ ev_watcher *w, int revents) {
    int error_number = 0;

    LOGGER_trace("Enter");
    LOGGER_trace("event: %d", revents);

    // retrieve respective device a new packet was seen
    device_dev_t *pcap_dev_ptr = (device_dev_t *) w->data;

    switch (pcap_dev_ptr->device_type) {
        case TYPE_testtype:
#ifndef PFRING
        case TYPE_PCAP_FILE:
        case TYPE_PCAP:
        case TYPE_SOCKET_INET:
        case TYPE_SOCKET_UNIX:
        {
            error_number = pcap_dev_ptr->dispatch(pcap_dev_ptr->dh
                    , PCAP_DISPATCH_PACKET_COUNT
                    , handle_packet
                    , (u_char*) pcap_dev_ptr);

            if (0 > error_number) {
                LOGGER_error("Error DeviceNo   %s", pcap_dev_ptr->device_name);
                LOGGER_error("Error No.: %d", error_number);
                LOGGER_error("Error No.: %d", errno);

                // on error deregister event handler
                if( EV_READ == (EV_READ & revents) ) {
                	event_deregister_io( EV_A_ (ev_io*)w );
                }
                else if( EV_TIMER == (EV_TIMER & revents) ) {
                	event_deregister_timer( EV_A_ (ev_timer*)w );
                }
            }
            LOGGER_trace("Packets read: %d", error_number);
        }
            break;
#else
        case TYPE_PFRING:
        {
            LOGGER_trace("pfring");
            error_number = pcap_dev_ptr->dispatch(pcap_dev_ptr->dh
                    , PCAP_DISPATCH_PACKET_COUNT
                    , packet_pfring_cb
                    , (u_char*) pcap_dev_ptr);

            if (0 > error_number) {
                LOGGER_error("Error DeviceNo   %s", pcap_dev_ptr->device_name);
                LOGGER_error("Error No.: %d", error_number);
                LOGGER_error("Error No.: %d", errno);
            }
            LOGGER_trace("Packets read: %d", error_number);
        }
            break;
#endif

        default:
            break;
    }
    LOGGER_trace("Return");
}
#ifdef PFRING

void packet_pfring_cb(u_char *user_args, const struct pfring_pkthdr *header,
        const u_char *packet) {
    device_dev_t* if_device = (device_dev_t*) user_args;
    uint8_t layers[4] = {0};
    uint32_t hash_result = 0;
    uint32_t copiedbytes = 0;
    uint8_t ttl = 0;
    uint64_t timestamp = 0;
    int pktid = 0;

    LOGGER_trace("packet_pfring_cb");

    if_device->sampling_delta_count++;
    if_device->totalpacketcount++;

    layers[L_NET] = header->extended_hdr.parsed_pkt.ip_version;
    layers[L_TRANS] = header->extended_hdr.parsed_pkt.l3_proto;

    // hash was already calculated in-kernel. use it
    hash_result = header->extended_hdr.parsed_pkt.pkt_detail.aggregation.num_pkts;
    /*
     printf("offsets@t0 l(3,4,5): %d, %d, %d\n",
     header->extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset + if_device->offset[L_NET],
     header->extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset + if_device->offset[L_NET],
     header->extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset + if_device->offset[L_NET]);
     */
    //if_device->offset[L_NET]       = header->extended_hdr.parsed_pkt.pkt_detail.offset.l3_offset;
    if_device->offset[L_TRANS] = header->extended_hdr.parsed_pkt.pkt_detail.offset.l4_offset + if_device->offset[L_NET];
    if_device->offset[L_PAYLOAD] = header->extended_hdr.parsed_pkt.pkt_detail.offset.payload_offset + if_device->offset[L_NET];

    //printf("pre getTTL: caplen: %02d, offset_net: %02d, ipv: %d\n",
    //            header->caplen, if_device->offset[L_NET], layers[L_NET]);
    ttl = getTTL(packet, header->caplen, if_device->offset[L_NET],
            layers[L_NET]);

    if_device->export_packet_count++;
    if_device->sampling_size++;

    // bypassing export if disabled by cmd line
    if (g_options.export_pktid_interval <= 0) {
        return;
    }

    // in case we want to use the hashID as packet ID
    if (g_options.hashAsPacketID == 1) {
        pktid = hash_result;
    } else {
        // selection of viable fields of the packet - depend on the selection function choosen
        copiedbytes = g_options.selection_function(packet, header->caplen,
                if_device->outbuffer, if_device->outbufferLength,
                if_device->offset, layers);
        pktid = g_options.pktid_function(if_device->outbuffer, copiedbytes);
    }

    /*
     printf("offsets@t1 l(3,4,5): %d, %d, %d\n",
     if_device->offset[L_NET],
     if_device->offset[L_TRANS],
     if_device->offset[L_PAYLOAD]);
     */

    //printf("pktid: 0d%d\n", pktid);

    timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
            + (uint64_t) header->ts.tv_usec;

    switch (g_options.templateID) {
        case MINT_ID:
        {
            void* fields[] = {&timestamp, &hash_result, &ttl};
            uint16_t lengths[] = {8, 4, 1};

            if (0 > ipfix_export_array(ipfix(),
                    if_device->ipfixtmpl_min, 3, fields, lengths)) {
                LOGGER_fatal("ipfix_export() failed: %s", strerror(errno));
                exit(1);
            }
            break;
        }

        case TS_ID:
        {
            void* fields[] = {&timestamp, &hash_result};
            uint16_t lengths[] = {8, 4};

            if (0 > ipfix_export_array(ipfix(),
                    if_device->ipfixtmpl_ts, 2, fields, lengths)) {
                LOGGER_fatal("ipfix_export() failed: %s", strerror(errno));
                exit(1);
            }
            break;
        }

        case TS_TTL_PROTO_ID:
        {
            uint16_t length;

            if (layers[L_NET] == N_IP) {
                length = ntohs(*((uint16_t*)
                        (&packet[if_device->offset[L_NET] + 2])));
            } else if (layers[L_NET] == N_IP6) {
                length = ntohs(*((uint16_t*)
                        (&packet[if_device->offset[L_NET] + 4])));
            } else {
                LOGGER_fatal("cannot parse packet length");
                length = 0;
            }

            void* fields[] = {&timestamp,
                &hash_result,
                &ttl,
                &length,
                &layers[L_TRANS],
                &layers[L_NET]};
            uint16_t lengths[6] = {8, 4, 1, 2, 1, 1};

            if (0 > ipfix_export_array(ipfix(),
                    if_device->ipfixtmpl_ts_ttl, 6, fields, lengths)) {
                LOGGER_fatal("ipfix_export() failed: %s", strerror(errno));
                exit(1);
            }
            break;
        }
        default:
            break;
    } // switch (options.templateID)

    // flush ipfix storage if max packetcount is reached
    if (if_device->export_packet_count >= g_options.export_packet_count) {
        if_device->export_packet_count = 0;
        export_flush();
    }
}
#endif


inline int set_value(void** field, uint16_t* length, void* value, uint16_t size) {
    *field = value;
    *length = size;
    return 1;
}

static void print_array(const u_char *p, int l) {
    int i = 0;
    for (i = 0; i < l; ++i) {
        if( 0 != i && 0 == i%4 ) {
           if( 0 == i%20 )
              fprintf(stderr, "\n");
           else
              fprintf(stderr, "| ");
        }
        fprintf(stderr, "%02x ", p[i]);
        //LOGGER_debug( "%02x ", packet[i]);
    }
    fprintf(stderr, "\n");
}

static void print_ip4(const u_char *p, int l) {
    if (0x40 != (p[0]&0xf0)) {
        print_array(p, l);
        return;
    }
    int i = 0;
    for (i = 0; i < l && i < 12; ++i) {
        fprintf(stderr, "%02x ", p[i]);
    }
    fprintf(stderr, "\b [");
    for (; i < l && i < 16; ++i) {
        fprintf(stderr, "%3d.", p[i]);
    }
    fprintf(stderr, "\b] [");
    for (; i < l && i < 20; ++i) {
        fprintf(stderr, "%3d.", p[i]);
    }
    fprintf(stderr, "\b] ");
    for (; i < l; ++i) {
        fprintf(stderr, "%02x ", p[i]);
    }
    fprintf(stderr, "\n");
}

inline uint8_t get_ttl(packet_t *p, uint32_t offset, netProt_t nettype) {
    switch (nettype) {
        case N_IP:
        {
            return p->ptr[offset + 8];
        }
        case N_IP6:
        {
            return p->ptr[offset + 7];
        }
        default:
        {
            return 0;
        }
    }
}

inline uint16_t get_ip_length(packet_t *p, uint32_t offset, netProt_t nettype) {
    switch (nettype) {
        case N_IP:
        {
            return ntohs(*((uint16_t*) (&p->ptr[offset + 2])));
        }
        case N_IP6:
        {
            return ntohs(*((uint16_t*) (&p->ptr[offset + 4])));
        }
        default:
        {
            LOGGER_fatal("cannot parse packet length");
            return 0;
        }
    }
}

inline uint8_t* get_ipa(packet_t *p, uint32_t offset, netProt_t nettype) {
    static uint32_t unknown_ipa = 0;
    switch (nettype) {
        case N_IP:
        {
            return p->ptr + offset + 12;
        }
        case N_IP6:
        default:
        {
            return (uint8_t*) &unknown_ipa;
        }
    }
}

inline uint16_t get_port(packet_t *p, uint32_t offset, transProt_t transtype) {
    switch (transtype) {
        case T_UDP:
        case T_TCP:
        case T_SCTP:
        {
            return ntohs(*((uint16_t*) (&p->ptr[offset])));
        }
        default:
        {
            return 0;
        }
    }
}

// return the packet protocol beyond the link layer (defined by rfc )
// !! the raw packet is expected (include link layer)
// return 0 if unknown

inline uint16_t get_nettype(packet_t *packet, int linktype) {
    switch (linktype) {
        case DLT_EN10MB: // 14 octets
            // Ethernet
            return ntohs(*((uint16_t*) (&packet->ptr[12])));
            break;
        case DLT_ATM_RFC1483: // 8 octets
            return ntohs(*((uint16_t*) (&packet->ptr[6])));
            break;
        case DLT_LINUX_SLL: // 16 octets
            // TODO: either the first 2 octets or the last 2 octets
            return ntohs(*((uint16_t*) (&packet->ptr[14])));
            break;
        case DLT_RAW:
            break;
        default:
            break;
    }
    return 0;
}

// return the packet protocol beyond the link layer (defined by rfc )
// !! the raw packet is expected (include link layer)
// return 0 if unknown

inline uint16_t get_nettype_pkt(packet_t *packet) {
    // check if at least 20 bytes are available
    if (20 <= packet->len) {
        // currently only IP (v4, v6) is relevant
        switch (packet->ptr[0]&0xf0) {
            case 0x40: return 0x0800;
                break;
            case 0x60: return 0x86DD;
                break;
        }
    }
    return 0;
}

inline uint64_t get_timestamp(struct timeval ts) {
    return (uint64_t) ts.tv_sec * 1000000ULL
            + (uint64_t) ts.tv_usec;
}

inline packet_t decode_array(packet_t* p) {
    packet_t data = {NULL, 0};
    data.len = ntohs(*((uint16_t*) (p->ptr)));
    data.ptr = p->ptr + 2;
    p->ptr += (data.len + 2);
    p->len -= (data.len + 2);
    return data;
}

// decode value of type
// [length][data]
inline packet_t decode_raw(packet_t *p, uint32_t len) {
    packet_t data = {NULL, 0};

    data.len = len;
    data.ptr = p->ptr;
    p->len -= len;
    p->ptr += len;
    return data;
}

inline uint64_t decode_uint64(packet_t *p) {
    uint64_t value = 0;
    memcpy( &value, p->ptr, 8 );
    p->ptr += 8;
    p->len -= 8;
//    int i = 0;
//    for( i = 0; i < 8; ++i ) {
//        value <<= 8;
//        value += *((uint8_t*) p->ptr);
//        --(p->len);
//        ++(p->ptr);
//    }
    return value;
}

inline uint32_t decode_uint32(packet_t *p) {
    uint32_t value = ntohl(*((uint32_t*) p->ptr));
    p->len -= 4;
    p->ptr += 4;
    return value;
}

inline uint16_t decode_uint16(packet_t *p) {
    uint16_t value = ntohs(*((uint16_t*) p->ptr));
    p->len -= 2;
    p->ptr += 2;
    return value;
}

inline uint8_t decode_uint8(packet_t *p) {
    uint8_t value = *p->ptr;
    p->len -= 1;
    p->ptr += 1;
    return value;
}

inline void apply_offset(packet_t *pkt, uint32_t offset) {
    LOGGER_trace("Offset: %d", offset);
    if (offset < pkt->len) {
        pkt->ptr += offset;
        pkt->len -= offset;
    } else {
        pkt->len = 0;
    }
}

void handle_default_packet(packet_t *packet, packet_info_t *packet_info) {
    LOGGER_info("packet type: 0x%04X (not supported)", packet_info->nettype);
}

void handle_ip_packet(packet_t *packet, packet_info_t *packet_info) {
    uint32_t hash_id = 0;
    uint32_t pkt_id = 0;

    uint32_t offsets[4] = {0}; // layer offsets for: link, net, transport, payload
    uint8_t layers[4] = {0}; // layer protocol types for: link, net, transport, payload

    LOGGER_trace(" ");

    // reset hash buffer
    packet_info->device->hash_buffer.len = 0;

    // find headers of the IP STACK
    findHeaders(packet->ptr, packet->len, offsets, layers);

    // selection of viable fields of the packet - depend on the selection function choosen
    // locate protocolsections of ip-stack --> findHeaders() in hash.c
    g_options.selection_function(packet,
            &packet_info->device->hash_buffer,
            offsets, layers);

    if (0) print_array(packet_info->device->hash_buffer.ptr, packet_info->device->hash_buffer.len);

    if (0 == packet_info->device->hash_buffer.len) {
        LOGGER_trace("Warning: packet does not contain Selection");
        return;
    }

    // hash the chosen packet data
    hash_id = g_options.hash_function(&packet_info->device->hash_buffer);
    if( LOGGER_LEVEL_DEBUG == logger_get_level() ) {
        uint8_t*  b = packet_info->device->hash_buffer.ptr;
        uint32_t bl = packet_info->device->hash_buffer.len;
        // create null terminated string
        char str_buffer[3*bl];
        char* p = str_buffer;
        int i = 0;
        for( i = 0; i < bl; ++i, p+=3 ) {
            sprintf(p, "%02x ", b[i]);
        }
        *(p-1)='\0';
        LOGGER_debug("hash id: 0x%08X (%u) (%s)", hash_id, hash_id, str_buffer);
    }

    // hash id must be in the chosen selection range to count
    if ((g_options.sel_range_min <= hash_id) &&
            (g_options.sel_range_max >= hash_id)) {
        packet_info->device->export_packet_count++;
        packet_info->device->sampling_size++;

        // bypassing export if disabled by cmd line
        if (g_options.export_pktid_interval <= 0) {
            return;
        }

        // in case we want to use the hashID as packet ID
        if (g_options.hashAsPacketID) {
            pkt_id = hash_id;
        } else {
            pkt_id = g_options.pktid_function(&packet_info->device->hash_buffer);
        }

        uint32_t          t_id = packet_info->device->template_id;

        t_id = (-1 == t_id) ? g_options.templateID : t_id;

        ipfix_template_t  *template = get_template( t_id );
        int               size = template->nfields;
        void              *fields[size];
        uint16_t          lengths[size];

        uint8_t ttl = 0;
        uint64_t timestamp = 0;
        uint16_t length = 0; // dummy for TS_TTL_PROTO template id
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t *src_ipa = 0;
        uint8_t *dst_ipa = 0;
        uint32_t rule_id = 0;

        switch (t_id) {
            case TS_ID:
            {
                timestamp = get_timestamp(packet_info->ts);

                int index = 0;
                index += set_value(&fields[index], &lengths[index], &timestamp, 8);
                index += set_value(&fields[index], &lengths[index], &hash_id, 4);
                break;
            }

            case MINT_ID:
            {
                timestamp = get_timestamp(packet_info->ts);
                ttl = get_ttl(packet, offsets[L_NET], layers[L_NET]);

                int index = 0;
                index += set_value(&fields[index], &lengths[index], &timestamp, 8);
                index += set_value(&fields[index], &lengths[index], &hash_id, 4);
                index += set_value(&fields[index], &lengths[index], &ttl, 1);
                break;
            }

            case TS_TTL_PROTO_ID:
            {
                timestamp = get_timestamp(packet_info->ts);
                ttl = get_ttl(packet, offsets[L_NET], layers[L_NET]);
                length = get_ip_length(packet, offsets[L_NET], layers[L_NET]);

                int index = 0;
                index += set_value(&fields[index], &lengths[index], &timestamp, 8);
                index += set_value(&fields[index], &lengths[index], &hash_id, 4);
                index += set_value(&fields[index], &lengths[index], &ttl, 1);
                index += set_value(&fields[index], &lengths[index], &length, 2);
                index += set_value(&fields[index], &lengths[index], &layers[L_TRANS], 1);
                index += set_value(&fields[index], &lengths[index], &layers[L_NET], 1);
                break;
            }

            case TS_TTL_PROTO_IP_ID:
            {
                timestamp = get_timestamp(packet_info->ts);
                ttl = get_ttl(packet, offsets[L_NET], layers[L_NET]);
                length = get_ip_length(packet, offsets[L_NET], layers[L_NET]);
                src_port = get_port(packet, offsets[L_TRANS], layers[L_TRANS]);
                dst_port = get_port(packet, offsets[L_TRANS] + 2, layers[L_TRANS]);
                src_ipa = get_ipa(packet, offsets[L_NET], layers[L_NET]);
                dst_ipa = get_ipa(packet, offsets[L_NET] + 4, layers[L_NET]);

                int index = 0;
                index += set_value(&fields[index], &lengths[index], &timestamp, 8);
                index += set_value(&fields[index], &lengths[index], &hash_id, 4);
                index += set_value(&fields[index], &lengths[index], &ttl, 1);
                index += set_value(&fields[index], &lengths[index], &length, 2);
                index += set_value(&fields[index], &lengths[index], &layers[L_TRANS], 1);
                index += set_value(&fields[index], &lengths[index], &layers[L_NET], 1);
                index += set_value(&fields[index], &lengths[index], src_ipa, 4);
                index += set_value(&fields[index], &lengths[index], &src_port, 2);
                index += set_value(&fields[index], &lengths[index], dst_ipa, 4);
                index += set_value(&fields[index], &lengths[index], &dst_port, 2);
                break;
            }

            case TS_ID_EPC_ID:
            {
                // an epc packet has 80 bytes of packet information
                // and 4 bytes for a rule id
                // and 8 bytes for a timestamp
                // the packet must have a least 84 bytes for packet and rule id
                // the packet must have a least 92 bytes for packet, rule id and timestamp

                timestamp = get_timestamp(packet_info->ts);
                src_ipa = get_ipa(packet, offsets[L_NET], layers[L_NET]);
                src_port = get_port(packet, offsets[L_TRANS], layers[L_TRANS]);
                dst_ipa = get_ipa(packet, offsets[L_NET] + 4, layers[L_NET]);
                dst_port = get_port(packet, offsets[L_TRANS] + 2, layers[L_TRANS]);
                
                LOGGER_debug("receive timestamp: 0x%" PRIx64 " us", timestamp);
                LOGGER_debug("receive timestamp: 0x%" PRIx64 " ms", timestamp/1000);
                LOGGER_debug("receive timestamp: 0x%" PRIx64 " s", timestamp/1000/1000);
                // if( 92 == packet->len ) {
                if( false == g_options.force_timestamp ) {
                    struct timeval ts;
                    decode_raw(packet, packet->len-12);
                    ts.tv_sec  = htonl(decode_uint32(packet));
                    ts.tv_usec = htonl(decode_uint32(packet));
                    timestamp  = get_timestamp(ts);
                }
                else {
                    decode_raw(packet, packet->len-4);
                }
                LOGGER_debug("message timestamp: 0x%" PRIx64 "", timestamp);
                rule_id = decode_uint32(packet);
                
                int index = 0;
                index += set_value(&fields[index], &lengths[index], &timestamp, 8);
                index += set_value(&fields[index], &lengths[index], &hash_id, 4);
                index += set_value(&fields[index], &lengths[index], &rule_id, 4);
                index += set_value(&fields[index], &lengths[index], &layers[L_NET], 1);
                index += set_value(&fields[index], &lengths[index], src_ipa, 4);
                index += set_value(&fields[index], &lengths[index], &src_port, 2);
                index += set_value(&fields[index], &lengths[index], dst_ipa, 4);
                index += set_value(&fields[index], &lengths[index], &dst_port, 2);
                break;
            }

            default:
                LOGGER_info("!!!no template specified!!!");
                return;
        } // switch (options.templateID)

        //LOGGER_debug( "%d", size);
        //int i = 0;
        //for( i = 0; i < size; ++i ) {
        //   LOGGER_debug( "%p: %d: %d", fields[i], lengths[i], *( (int*)fields[i]));
        //}

        // send ipfix packet
        if (0 > ipfix_export_array(ipfix(), template, size, fields, lengths)) {
            LOGGER_fatal("ipfix_export() failed: %s", strerror(errno));
        }

        // flush ipfix storage if max packetcount is reached
        if (packet_info->device->export_packet_count >= g_options.export_packet_count) {
            //todo: export_flush_device( packet_info->device );
            packet_info->device->export_packet_count = 0;
            export_flush();
        }

        // reset dropped packet, if a packet was processed
        packet_info->device->packets_dropped = 0;

    } // if (hash in selection range)
    else {
        // count dropped packets
        packet_info->device->packets_dropped++;
        LOGGER_debug("packets dropped: %u\n", packet_info->device->packets_dropped);
    }
}

void handle_open_epc_packet(packet_t *packet, packet_info_t *packet_info) {
    LOGGER_trace("Enter");

    uint32_t t_id = packet_info->device->template_id;
    t_id = (-1 == t_id) ? g_options.templateID : t_id;

    ipfix_template_t  *template = get_template( t_id );
    int size = template->nfields;
    void* fields[size];
    uint16_t lengths[size];
    int i;
    uint32_t dummy = 0;    
    uint8_t rule_flag     = 0;
    uint32_t rule_id      = 0;
    uint64_t timestamp    = 0;
    uint8_t src_ai_fam    = 0;
    uint8_t dst_ai_fam    = 0;
    uint8_t src_prefix    = 0;
    uint8_t dst_prefix    = 0;
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;
    uint16_t sdf_counter  = 0;
    uint32_t qci          = 0;
    uint32_t max_dl       = 0;
    uint32_t max_ul       = 0;
    uint32_t gua_dl       = 0;
    uint32_t gua_ul       = 0;
    uint32_t apn_dl       = 0;
    uint32_t apn_ul       = 0;
    packet_t apn          = {NULL, 0};
    packet_t rule_name    = {NULL, 0};
    packet_t imsi         = {NULL, 0};
    packet_t flow_desc    = {NULL, 0};
    packet_t src_ipa      = {NULL, 0};
    packet_t dst_ipa      = {NULL, 0};
    packet_t decode       = *packet;

    switch (t_id) {
        case TS_OPEN_EPC_ID:
        {
            //if (*((uint8_t*)packet) == OP_CODE) {
                rule_flag = decode_uint8(&decode);
                rule_id   = decode_uint32(&decode);
                imsi      = decode_array(&decode);
                apn       = decode_array(&decode);
                rule_name = decode_array(&decode);
                
                qci     = decode_uint32(&decode);
                max_dl  = decode_uint32(&decode);
                max_ul  = decode_uint32(&decode);
                gua_dl  = decode_uint32(&decode);
                gua_ul  = decode_uint32(&decode);
                apn_dl  = decode_uint32(&decode);
                apn_ul  = decode_uint32(&decode);
                
                /* TODO: Zeit richtig setzen da im Moment Microseconds zuerck
                 *       geliefert werden, wir aber Milliseconds fuer unser
                 *       Template brauchen
                 */
                timestamp = get_timestamp(packet_info->ts); 
                timestamp /= 1000;

                int index = 0;
                index += set_value(&fields[index],
                        &lengths[index], &timestamp, 8);
                index += set_value(&fields[index],
                        &lengths[index], &rule_flag, 1);
                index += set_value(&fields[index],
                        &lengths[index], &rule_id, 4);
                index += set_value(&fields[index],
                        &lengths[index], apn.ptr, apn.len);
                index += set_value(&fields[index],
                        &lengths[index], rule_name.ptr, rule_name.len);
                index += set_value(&fields[index],
                        &lengths[index], imsi.ptr, imsi.len);
                index += set_value(&fields[index], &lengths[index], &qci, 4);
                index += set_value(&fields[index], &lengths[index], &max_dl, 4);
                index += set_value(&fields[index], &lengths[index], &max_ul, 4);
                index += set_value(&fields[index], &lengths[index], &gua_dl, 4);
                index += set_value(&fields[index], &lengths[index], &gua_ul, 4);
                index += set_value(&fields[index], &lengths[index], &apn_dl, 4);
                index += set_value(&fields[index], &lengths[index], &apn_ul, 4);
                sdf_counter = decode_uint16(&decode);
                
                for (i = 0; i < sdf_counter; i++) {
                    int int_idx = index;

                    flow_desc  = decode_array(&decode);

                    src_ai_fam = decode_uint8(&decode);
                    src_prefix = decode_uint8(&decode);
                    src_port   = decode_uint16(&decode);

                    if (src_ai_fam == AF_INET) {
                        src_ipa = decode_raw(&decode, 4);
                    } else {
                        src_ipa.ptr = (uint8_t*)&dummy;
                        src_ipa.len = 4;
                    }

                    dst_ai_fam = decode_uint8(&decode);
                    dst_prefix = decode_uint8(&decode);
                    dst_port = decode_uint16(&decode);

                    if(dst_ai_fam == AF_INET) {
                        dst_ipa = decode_raw(&decode, 4);   
                    } else {
                        dst_ipa.ptr = (uint8_t*)&dummy;
                        dst_ipa.len = 4;
                    }
                    
                    int_idx += set_value(&fields[int_idx], &lengths[int_idx], src_ipa.ptr, src_ipa.len);
                    int_idx += set_value(&fields[int_idx], &lengths[int_idx], &src_port, 2);
                    int_idx += set_value(&fields[int_idx], &lengths[int_idx], dst_ipa.ptr, dst_ipa.len);
                    int_idx += set_value(&fields[int_idx], &lengths[int_idx], &dst_port, 2);

                    if (0 > ipfix_export_array(ipfix(), template, size, fields, lengths)) {
                        LOGGER_fatal("ipfix_export() failed: %s", strerror(errno));
                    }    
                }
                break;
            //}
        }
        
        default:
            LOGGER_info("!!!no template specified!!!");
            return;
    } // switch (options.templateID)

    export_flush();

    LOGGER_trace("Return");
    return;
}

void handle_packet(u_char *user_args, const struct pcap_pkthdr *header, const u_char * packet) {
    packet_t pkt = {(uint8_t*) packet, header->caplen};
    packet_info_t info = {header->ts, header->len, (device_dev_t*) user_args};

    LOGGER_trace("Enter");

    info.device->sampling_delta_count++;
    info.device->totalpacketcount++;

    // debug output
    if (0) print_array(pkt.ptr, pkt.len);

    if ((info.device->device_type == TYPE_SOCKET_UNIX ||
            info.device->device_type == TYPE_SOCKET_INET)
            && info.device->template_id == TS_OPEN_EPC_ID) {
        handle_open_epc_packet(&pkt, &info);
    } else {
        switch (info.device->device_type) {
            case TYPE_PCAP:
            case TYPE_PCAP_FILE:
                // get packet type from link layer header
                info.nettype = get_nettype(&pkt, info.device->link_type);
                break;

            case TYPE_SOCKET_UNIX:
            case TYPE_SOCKET_INET:
                info.nettype = get_nettype_pkt(&pkt);
                break;
            case TYPE_FILE:
            case TYPE_UNKNOWN:
            default:
                break;
        }
        LOGGER_trace("nettype: 0x%04X", info.nettype);

        // apply net offset - skip link layer header for further processing
        apply_offset(&pkt, info.device->pkt_offset);

        // apply user offset
        apply_offset(&pkt, g_options.offset);

        // debug output
        if (0) print_array(pkt.ptr, pkt.len);

        if (0x0800 == info.nettype || // IPv4
                0x86DD == info.nettype) // IPv6
        {
            if (0) print_ip4(pkt.ptr, pkt.len);
            handle_ip_packet(&pkt, &info);
            //LOGGER_trace( "drop" );
        } else {
            handle_default_packet(&pkt, &info);
        }
    }
    LOGGER_trace("Return");
}

