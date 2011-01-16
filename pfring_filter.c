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

/* converts a string describing an ip protocol to the corresponding 
 * protocol number as assinged by the iana. lower case string is expected.
 * see: http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 * returns protocol number as assinged by the iana if found
 * returns 0xff if not found (0xff is marked as reserved by iana)
 */
uint8_t get_ip_prot( const char* prot ) {
    int i = 0;

    for ( i = 0; i <= last_ip_prot; i++ )
        if ( strncmp(ip_protocols[i], prot, sizeof(ip_protocols[i])) == 0 )
            // found protocol
            return i;

    return INVALID_PROT;
}

/* if found, prints protocol name and number */
void print_ip_prot( const char* prot ) {
    int i = 0;

    for ( i = 0; i <= last_ip_prot; i++ )
        if ( strncmp(ip_protocols[i], prot, sizeof(ip_protocols[i])) == 0 )
            // found protocol
            printf("prot(0x%02x): %s\n", i, ip_protocols[i]);
}

/* print all protocol names and numbers */
void print_all_ip_prot() {
    int i = 0;

    for ( i = 0; i <= last_ip_prot; i++ )
        printf("prot(0x%02x): %s\n", i, ip_protocols[i]);
}

/* print all protocol names */
void print_all_ip_prot_str() {
    int i = 0;

    // print all but last prot
    for ( i = 0; i < last_ip_prot; i++ )
        printf("%s, ", ip_protocols[i]);
    // print last prot
    printf("%s", ip_protocols[last_ip_prot]);
}
