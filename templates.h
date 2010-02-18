#ifndef TEMPLATES_H_
#define TEMPLATES_H_

#include "ipfix.h"
#include "ipfix_def.h"

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

#endif
