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
typedef void (*io_cb_t)(EV_P_ ev_io *w, int revents);
typedef void (*watcher_cb_t)(EV_P_ ev_watcher *w, int revents);


typedef char* (*set_cfg_fct_t)(unsigned long mid, char* cmd_msg);

// !! do not change order !!
typedef struct {
  char cmd;
  set_cfg_fct_t fct;
  const char* desc;
}
cfg_fct_t;

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

set_cfg_fct_t getFunction(char cmd);

/* -- signals --*/
void sigint_cb  (EV_P_ ev_signal *w, int revents);
void sigalrm_cb (EV_P_ ev_signal *w, int revents);
void sigpipe_cb (EV_P_ ev_signal *w, int revents);


/* -- capture --*/
void packet_watcher_cb(EV_P_ ev_watcher *w, int revents);

/* -- export -- */
void export_timer_pktid_cb    (EV_P_ ev_watcher *w, int revents);
void export_timer_sampling_cb (EV_P_ ev_watcher *w, int revents);
void export_timer_stats_cb    (EV_P_ ev_watcher *w, int revents);
void export_timer_location_cb (EV_P_ ev_watcher *w, int revents);


// TODO: not here
void export_flush();
void export_flush_device( device_dev_t* device );
void export_data_interface_stats(device_dev_t *dev
      , uint64_t observationTimeMilliseconds
      , u_int32_t size
      , u_int64_t deltaCount);
void export_data_probe_stats(int64_t observationTimeMilliseconds);
void export_data_sync(device_dev_t *dev
      , int64_t observationTimeMilliseconds
      , u_int32_t messageId
      , u_int32_t messageValue
      , char * message);
void export_data_location(int64_t observationTimeMilliseconds);


/* -- event loop -- */
void event_loop( EV_P );
void event_loop_init( EV_P );
void event_loop_start( EV_P );
ev_watcher* event_register_io(EV_P_ watcher_cb_t cb, int fd);
ev_watcher* event_register_io_r(EV_P_ watcher_cb_t cb, int fd);
ev_watcher* event_register_io_w(EV_P_ watcher_cb_t cb, int fd);
ev_watcher* event_register_timer(EV_P_ watcher_cb_t cb, double timeout);
ev_watcher* event_register_timer_w(EV_P_ watcher_cb_t cb, double timeout);
void event_setup_pcapdev(EV_P);
void event_setup_netcon(EV_P);

/* -- runtime configuration -- */
int runtime_configuration_cb(char*);
char* configuration_help(unsigned long mid, char *msg);
char* configuration_set_template(unsigned long mid, char *msg);
char* configuration_set_filter(unsigned long mid, char *msg);
char* configuration_set_export_to_probestats(unsigned long mid, char *msg);
char* configuration_set_export_to_ifstats(unsigned long mid, char *msg);
char* configuration_set_export_to_pktid(unsigned long mid, char *msg);
char* configuration_set_min_selection(unsigned long mid, char *msg);
char* configuration_set_max_selection(unsigned long mid, char *msg);
char* configuration_set_ratio(unsigned long mid, char *msg);

/* -- netcon / resync  -- */
void resync_timer_cb (EV_P_ ev_watcher *w, int revents);



#endif /* EVENTHANDLER_H_ */
