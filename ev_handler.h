/*
 * eventHandler.h
 *
 *  Created on: 12.10.2010
 *      Author: rma
 */

#ifndef EVENTHANDLER_H_
#define EVENTHANDLER_H_

#include <ev.h>
#include <pcap.h>

#include "ipfix.h"

#include "main.h"


// -----------------------------------------------------------------------------
// Type definitions
// -----------------------------------------------------------------------------

/**
 * Event and Signal handling via libev
 */
struct {
	struct ev_loop *loop;
	ev_signal sigint_watcher;
	ev_signal sigalrm_watcher;
	ev_signal sigpipe_watcher;
	ev_timer export_timer_pkid;
	ev_timer export_timer_sampling;
	ev_timer export_timer_stats;
	ev_timer resync_timer;
	ev_io *packet_watchers;
} events;

/* sync extension, depends on ipfix_collector_t defined in libipfix */
typedef struct collector_node_sync {
	struct collector_node_sync *next;
	int usecount;
	char *chost; /* collector hostname */
	int cport; /* collector port */
	ipfix_proto_t protocol; /* used protocol (e.g. tcp) */
	int fd; /* open socket */
} ipfix_collector_sync_t;


typedef void (*timer_cb_t)(EV_P_ ev_timer *w, int revents);

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

/* -- event loop --*/
void event_loop();
ev_timer* event_register_timer(EV_P_ ev_tstamp tstamp, timer_cb_t* cb );

/* -- signals --*/
void sigint_cb (EV_P_ ev_signal *w, int revents);
void sigalrm_cb (EV_P_ ev_signal *w, int revents);
void sigpipe_cb (EV_P_ ev_signal *w, int revents);


/* -- capture --*/
void packet_watcher_cb(EV_P_ ev_io *w, int revents);
void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header,
		const u_char * packet);

/* -- export -- */
void export_flush();
void export_timer_pktid_cb (EV_P_ ev_timer *w, int revents);
void export_timer_sampling_cb (EV_P_ ev_timer *w, int revents);
void export_timer_stats_cb (EV_P_ ev_timer *w, int revents);
void export_data_interface_stats(pcap_dev_t *dev,
		uint64_t observationTimeMilliseconds, u_int32_t size,
		u_int64_t deltaCount);
void export_data_probe_stats(pcap_dev_t *dev);
void export_data_sync(pcap_dev_t *dev,
		int64_t observationTimeMilliseconds, u_int32_t messageId,
		u_int32_t messageValue, char * message);

// todo: not here
void export_flush();

void event_setup_pcapdev(struct ev_loop *loop);
void event_setup_netcon(struct ev_loop *loop);


/* -- netcon / resync  -- */
void resync_timer_cb (EV_P_ ev_timer *w, int revents);



#endif /* EVENTHANDLER_H_ */
