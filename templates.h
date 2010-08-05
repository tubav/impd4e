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

#ifndef TEMPLATES_H_
#define TEMPLATES_H_

#include "ipfix.h"
#include "ipfix_def.h"
#include "ipfix_def_fokus.h"

/*
 * for an introduction to the IPFIX protocol see:
 * RFC5101 - http://tools.ietf.org/html/rfc5101
 *
 * for an overview of available IPFIX fields and
 * their meaning see 
 * RFC5102 - http://tools.ietf.org/html/rfc5102
 * (or in more himan readable form:
 * http://www.iana.org/assignments/ipfix/ipfix.xhtml)
 */


/*
 * when invoked with "-t min" the following fields are exported
 * in each IPFIX data record:
 */

export_fields_t export_fields_min[] = {
                { 0, IPFIX_FT_OBSERVATIONTIMEMICROSECONDS, 8 },
                { 0, IPFIX_FT_DIGESTHASHVALUE, 4 },
                { 0, IPFIX_FT_IPTTL, 1}
};

/*
 * when invoked with "-t lp" the following fields are exported
 * in each IPFIX data record:
 */

export_fields_t export_fields_ts_ttl_proto[] = {
                { 0, IPFIX_FT_OBSERVATIONTIMEMICROSECONDS, 8 },
                { 0, IPFIX_FT_DIGESTHASHVALUE, 4 },
                { 0, IPFIX_FT_IPTTL, 1},
 				{ 0, IPFIX_FT_TOTALLENGTHIPV4, 2 },
                { 0, IPFIX_FT_PROTOCOLIDENTIFIER, 1},
                { 0, IPFIX_FT_IPVERSION, 1}
};

export_fields_t export_fields_sampling[] = {
				{ 0, IPFIX_FT_SAMPLINGSIZE, 4 },
				{ 0, IPFIX_FT_PACKETTOTALCOUNT, 8}
};

/* Overall system statistics (Linux)
 man 2 sysinfo */

/* export_fields_t export_sysinfo[] = {
		{IPFIX_ENO_FOKUS, IPFIX_FT_PT_CPU_IDLE, 2},
		{IPFIX_ENO_FOKUS, IPFIX_FT_PT_CPU_PROCESS, 2},
		{IPFIX_ENO_FOKUS, IPFIX_FT_PT_RAM_PROCESS, 4},
		{IPFIX_ENO_FOKUS, IPFIX_FT_PT_RAM_UNUSED, 4}
};
*/
/* Process times (POSIX)
man 2 times

*/




#endif
