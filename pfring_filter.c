/* impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Robert Wuttke <flash@jpod.cc>
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your 
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "pfring_filter.h"

/* this defines an invalid protocol */
#define INVALID_PROT 0xFF

/* last assigned protocol number */
uint8_t last_prot = 0x8f;

/* list all ip protocol numbers as assigned by the iana
 * see: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
char* protocols[0xff] = {
            "hopopt",
            "icmp",
            "igmp",
            "ggp",
            "ipv4",
            "st",
            "tcp",
            "cbt",
            "egp",
            "igp",
            "bbn-rcc-mon",
            "nvp-ii",
            "pup",
            "argus",
            "emcon",
            "xnet",
            "chaos",
            "udp",
            "mux",
            "dcn-meas",
            "hmp",
            "prm",
            "xns-idp",
            "trunk-1",
            "trunk-2",
            "leaf-1",
            "leaf-2",
            "rdp",
            "irtp",
            "iso-tp4",
            "netblt",
            "mfe-nsp",
            "merit-inp",
            "dccp",
            "3pc",
            "idpr",
            "xtp",
            "ddp",
            "idpr-cmtp",
            "tp++",
            "il",
            "ipv6",
            "sdrp",
            "ipv6-route",
            "ipv6-frag",
            "idrp",
            "rsvp",
            "gre",
            "dsr",
            "bna",
            "esp",
            "ah",
            "i-nlsp",
            "swipe",
            "narp",
            "mobile",
            "tlsp",
            "skip",
            "ipv6-icmp",
            "ipv6-nonxt",
            "ipv6-opts",
            "anyhost",
            "cftp",
            "anynet",
            "sat-expak",
            "kryptolan",
            "rvd",
            "ippc",
            "anydistfs",
            "sat-mon",
            "visa",
            "ipcv",
            "cpnx",
            "cphb",
            "wsn",
            "pvp",
            "br-sat-mon",
            "sun-nd",
            "wb-mon",
            "wb-expak",
            "iso-ip",
            "vmtp",
            "secure-vmtp",
            "vines",
            "ttp",
            "nsfnet-igp",
            "dgp",
            "tcf",
            "eigrp",
            "ospfigp",
            "sprite-rpc",
            "larp",
            "mtp",
            "ax.25",
            "ipip",
            "micp",
            "scc-sp",
            "etherip",
            "encap",
            "anyprivenc",
            "gmtp",
            "ifmp",
            "pnni",
            "pim",
            "aris",
            "scps",
            "qnx",
            "a/n",
            "ipcomp",
            "snp",
            "compaq-peer",
            "ipx-in-ip",
            "vrrp",
            "pgm",
            "any0hop",
            "l2tp",
            "ddx",
            "iatp",
            "stp",
            "srp",
            "uti",
            "smp",
            "sm",
            "ptp",
            "isisoveripv4",
            "fire",
            "crtp",
            "crudp",
            "sscopmce",
            "iplt",
            "sps",
            "pipesctp",
            "fc",
            "rsvp-e2e-ignore",
            "mobilityheader",
            "udplite",
            "mplsinip",
            "manet",
            "hip",
            "shim6",
            "wesp",
            "rohc",
            "exptest0",
            "exptest1"
        };

/* converts a string describing an ip protocol to the corresponding 
 * protocol number as assinged by the iana. lower case string is expected.
 * see: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 * returns protocol number as assinged by the iana if found
 * returns 0xff if not found (0xff is marked as reserved by iana)
 */
uint8_t get_ip_prot( const char* prot ) {
    int i = 0;

    for ( i = 0; i <= last_prot; i++ )
        if ( strncmp(protocols[i], prot, sizeof(protocols[i])) == 0 )
            // found protocol
            return i;

    return INVALID_PROT;
}

/* if found, prints protocol name and number */
void print_ip_prot( const char* prot ) {
    int i = 0;

    for ( i = 0; i <= last_prot; i++ )
        if ( strncmp(protocols[i], prot, sizeof(protocols[i])) == 0 )
            // found protocol
            printf("prot(0x%02x): %s\n", i, protocols[i]);
}

/* print all protocol names and numbers */
void print_all_ip_prot() {
    int i = 0;

    for ( i = 0; i <= last_prot; i++ )
        printf("prot(0x%02x): %s\n", i, protocols[i]);
}

/* print all protocol names */
void print_all_ip_prot_str() {
    int i = 0;

    // print all but last prot
    for ( i = 0; i < last_prot; i++ )
        printf("%s, ", protocols[i]);
    // print last prot
    printf("%s", protocols[last_prot]);
}
