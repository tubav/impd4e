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


#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
//#include <stdint.h>
//#include <unistd.h>

//#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
//#include <fcntl.h>
//#include <linux/if.h>
//#include <netinet/in.h>

//#ifndef PFRING
//#include <pcap.h>
//#endif


//#ifdef PFRING
//#include <netinet/ip.h>
//#include <net/ethernet.h>     /* the L2 protocols */
//#include <pf_plugin_impd4e.h>
//#endif

#include "logger.h"
#include "settings.h"
//#include "helper.h"
//#include "constants.h"


// -----------------------------------------------------------------------------
// Global Variables
// -----------------------------------------------------------------------------
options_t g_options;

// -----------------------------------------------------------------------------
// Functions
// -----------------------------------------------------------------------------

/**
 * return a pointer to the global options variable
 * returns: pointer g_options
 */
options_t* getOptions() {
	return &g_options;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_lowerbound(options_t *options, char* s) {
  errno = 0;
  long long int value = strtoll(s, NULL, 0);

  if ( UINT32_MAX < value )
  {
    LOGGER_warn("selection range minimum 'out of range (UINT32_MAX)' used to be (uint32_t)");
    options->sel_range_min = UINT32_MAX;
  }
  else if ( 0 > value )
  {
    LOGGER_warn("selection range minimum 'out of range (ZERO)' used to be (uint32_t)");
    options->sel_range_min = 0;
  }
  else
  {
    options->sel_range_min = (uint32_t) value;
  }
  LOGGER_debug("selection range (lowerbound): %#08x (%d)", options->sel_range_min, options->sel_range_min);

  // check if upper bound is greater than lowerbound
  if(options->sel_range_max < options->sel_range_min)
  {
    LOGGER_warn( "lower bound (%#08x) > upper bound (%#08x); adjust upper bound"
               , options->sel_range_min
	       , options->sel_range_max );
    options->sel_range_max = options->sel_range_min;
  }

  return options->sel_range_min;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_upperbound(options_t *options, char* s) {
  errno = 0;
  long long int value = strtoll(s, NULL, 0);

  if ( UINT32_MAX < value )
  {
    LOGGER_warn("selection range maximum 'out of range (UINT32_MAX)' used to be (uint32_t)");
    options->sel_range_max = UINT32_MAX;
  }
  else if ( 0 > value )
  {
    LOGGER_warn("selection range maximum 'out of range (ZERO)' used to be (uint32_t)");
    options->sel_range_max = 0;
  }
  else
  {
    options->sel_range_max = (uint32_t) value;
  }
  LOGGER_debug("selection range (uppperbound): %#08x (%d)", options->sel_range_max, options->sel_range_max);

  // check if upper bound is greater than lowerbound
  if(options->sel_range_max < options->sel_range_min)
  {
    LOGGER_warn( "lower bound (%#08x) > upper bound (%#08x); adjust lower bound"
               , options->sel_range_min
	       , options->sel_range_max );
    options->sel_range_min = options->sel_range_max;
  }

  return options->sel_range_max;
}

// =============================================================================

/**
 * Set sampling ratio, returns -1 in case of failure.
 */
int set_sampling_ratio(options_t *options, char* value) {
	double sampling_ratio = strtod( value, NULL);
	LOGGER_debug("sampling ratio: %lf", sampling_ratio);
	/*
	 * for the sampling ratio we do not like values at the edge, therefore we use values beginning at the 10% slice.
	 */
	options->sel_range_min = 0x19999999;
	options->sel_range_max = (double) UINT32_MAX / 100 * sampling_ratio;

	if (UINT32_MAX - options->sel_range_max > options->sel_range_min) {
		options->sel_range_min = 0x19999999;
		options->sel_range_max += options->sel_range_min;
	} else {
		/* more than 90% therefore use also values from first 10% slice */
		options->sel_range_min = UINT32_MAX - options->sel_range_max;
		options->sel_range_max = UINT32_MAX;
	}
	return 0;
}

// =============================================================================

/**
 * Parse command line template
 */
 int parseTemplate(char *arg_string, options_t *options) {
	int k;
	struct templateDef {
		char *hstring;
		int templateID;
	} templates[] = { { MIN_NAME, MINT_ID }, { TS_TTL_RROTO_NAME,
			TS_TTL_PROTO_ID }, { TS_NAME, TS_ID } };

	// remove any leading whitespaces
	while( isspace(*arg_string) ) ++arg_string;

	for (k = 0; k < (sizeof(templates) / sizeof(struct templateDef)); k++) {
		if (strncasecmp(arg_string, templates[k].hstring, strlen(
				templates[k].hstring)) == 0) {
			return options->templateID = templates[k].templateID;
		}
	}
	return -1;
}

// =============================================================================

/**
 * Parse command line selection function
 */
void parseSelFunction(char *arg_string, options_t *options) {
	int k;
	struct selfunction {
		char *hstring;
		selectionFunction selfunction;
	} selfunctions[] = 	{ { HASH_INPUT_REC8,   copyFields_Rec }
						, { HASH_INPUT_IP,     copyFields_Only_Net }
						, { HASH_INPUT_IPTP,   copyFields_U_TCP_and_Net }
						, { HASH_INPUT_PACKET, copyFields_Packet }
						, { HASH_INPUT_RAW,    copyFields_Raw }
						, { HASH_INPUT_LINK,   copyFields_Link }
						, { HASH_INPUT_NET,    copyFields_Net }
						, { HASH_INPUT_TRANS,  copyFields_Trans }
						, { HASH_INPUT_PAYLOAD,copyFields_Payload }
						, { HASH_INPUT_SELECT, copyFields_Raw } };

	for (k = 0; k < (sizeof(selfunctions) / sizeof(struct selfunction)); k++) {
		if (strncasecmp(arg_string, selfunctions[k].hstring
				, strlen(selfunctions[k].hstring)) == 0)
		{
			options->selection_function = selfunctions[k].selfunction;

			// needed for RAW, LINK, NET, TRANS, PAYLOAD
			// set in hash.c
			parseRange( arg_string+strlen(selfunctions[k].hstring) );
		}
	}
}

// =============================================================================

/**
 * Parse command line hash function
 */
hashFunction parseFunction(char *arg_string) {
	int k;
	int j = 0;
	struct hashfunction {
		char *hstring;
		hashFunction function;
	} hashfunctions[] = { { HASH_FUNCTION_BOB, calcHashValue_BOB }
						, { HASH_FUNCTION_TWMX, calcHashValue_TWMXRSHash }
						, { HASH_FUNCTION_HSIEH, calcHashValue_Hsieh }
						, { HASH_FUNCTION_OAAT, calcHashValue_OAAT } };

	for (k = 0; k < (sizeof(hashfunctions) / sizeof(struct hashfunction)); k++) {
		if (strncasecmp(arg_string, hashfunctions[k].hstring
				, strlen(hashfunctions[k].hstring)) == 0)
		{
			j = k;
			LOGGER_info("using %s as hashFunction \n", hashfunctions[k].hstring);
		}
	}
	return hashfunctions[j].function;
}

// =============================================================================


// -----------------------------------------------------------------------------
// end of file
// -----------------------------------------------------------------------------

