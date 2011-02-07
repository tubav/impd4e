/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Ramon Massek)
 * Copyright (c) 2010, Robert Wuttke <flash@jpod.cc>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free 
 * Software Foundation either version 3 of the License, or (at your option) any
 * later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EVENTHANDLER_H_
#define EVENTHANDLER_H_

#include <ev.h>

#ifndef PFRING
#include <pcap.h>
#endif

#include <ipfix.h>

#include "constants.h"
#include "helper.h"

// -----------------------------------------------------------------------------
// Type definitions
// -----------------------------------------------------------------------------

/* sync extension, depends on ipfix_collector_t defined in libipfix */
/* do not change order !!! */
typedef struct collector_node_sync {
	struct collector_node_sync *next;
	int   usecount;
	char* chost; /* collector hostname */
	int   cport; /* collector port */
	ipfix_proto_t protocol; /* used protocol (e.g. tcp) */
	int   fd;    /* open socket */
} ipfix_collector_sync_t;


typedef void (*timer_cb_t)(EV_P_ ev_timer *w, int revents);

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

/* -- signals --*/
void sigint_cb (EV_P_ ev_signal *w, int revents);
void sigalrm_cb (EV_P_ ev_signal *w, int revents);
void sigpipe_cb (EV_P_ ev_signal *w, int revents);


/* -- capture --*/
void packet_watcher_cb(EV_P_ ev_io *w, int revents);
#ifndef PFRING
void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header,
		const u_char * packet);
#else
void packet_pfring_cb(u_char *user_args, const struct pfring_pkthdr *header, 
        const u_char *packet);
#endif

/* -- export -- */
void export_timer_pktid_cb (EV_P_ ev_timer *w, int revents);
void export_timer_sampling_cb (EV_P_ ev_timer *w, int revents);
void export_timer_stats_cb (EV_P_ ev_timer *w, int revents);


// todo: not here
void export_flush();
void export_flush_device( device_dev_t* device );
void export_data_interface_stats(device_dev_t *dev,
		uint64_t observationTimeMilliseconds, u_int32_t size,
		u_int64_t deltaCount);
void export_data_probe_stats(device_dev_t *dev);
void export_data_sync(device_dev_t *dev,
		int64_t observationTimeMilliseconds, u_int32_t messageId,
		u_int32_t messageValue, char * message);


/* -- event loop --*/
void event_loop();
ev_timer* event_register_timer(EV_P_ ev_tstamp tstamp, timer_cb_t* cb );
void event_setup_pcapdev(struct ev_loop *loop);
void event_setup_netcon(struct ev_loop *loop);

int netcom_cmd_set_ratio(char *msg);

/* -- netcon / resync  -- */
void resync_timer_cb (EV_P_ ev_timer *w, int revents);



#endif /* EVENTHANDLER_H_ */
