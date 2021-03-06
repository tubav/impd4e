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

#ifndef SETTINGS_H_
#define SETTINGS_H_

#include <stdint.h>

#include "constants.h"

// -----------------------------------------------------------------------------
// Type definitions
// -----------------------------------------------------------------------------
typedef struct options
{
	char     basedir[100];
	uint8_t  number_interfaces;
	uint32_t templateID;
        uint32_t offset;
	char     collectorIP[256];
	int16_t  collectorPort;
	char*    bpf; // berkley packet filter
    #ifdef PFRING
    filtering_rule rules[MAX_RULES];
    uint16_t rules_in_list;
    int8_t   filter_policy;
    #endif // PFRING
	int               ai_family;
	uint32_t          observationDomainID;
	uint32_t          ipAddress; // network byte order
	hashFunction      hash_function;
	hashFunction      pktid_function;
	selectionFunction selection_function;
	uint32_t sel_range_min;
	uint32_t sel_range_max;
	uint16_t snapLength;
	uint8_t  verbosity;
	char*    verbosity_filter_string;
	uint32_t export_packet_count;
	uint32_t export_interval;
	char*  s_latitude;
	char*  s_longitude;
	char*  s_probe_name;
	char*  s_location_name;
	double sampling_ratio;
	bool   samplingResultExport;
	bool   resourceConsumptionExport;
	double export_pktid_interval;
	double export_sampling_interval;
	double export_stats_interval;
	double export_location_interval;
	int hashAsPacketID;
	int use_oid_first_interface;
} options_t;



// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------
inline options_t* getOptions();

int set_sampling_ratio(options_t *options, char* value);
int set_sampling_lowerbound(options_t *options, char* value);
int set_sampling_upperbound(options_t *options, char* value);

int parse_template(char *arg_string);
void parseSelFunction(char *arg_string, options_t *options);
hashFunction parseFunction(char *arg_string);

void print_help();
void parse_cmdline(int argc, char **argv);
void parse_cmdline_v2(int argc, char **argv);

void set_defaults_options(options_t *options);
void set_defaults_device(device_dev_t* dev);

// todo: use getter instead
extern options_t     g_options;

#endif /* SETTINGS_H_ */

