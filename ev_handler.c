
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#include "ev_handler.h"
#include "logger.h"
#include "netcon.h"

//#include "templates.h"
#include "hash.h"
#include "mlog.h"
#include "ipfix.h"
#include "ipfix_def.h"
#include "ipfix_def_fokus.h"
#include "stats.h"

// Custom logger
#include "logger.h"
#include "netcon.h"
#include "ev_handler.h"
#include <ev.h> // event loop

#include "main.h" // todo: circular reference; review

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------*/
#define RESYNC_PERIOD 1.5 /* seconds */

/**
 * Call back for SIGINT (Ctrl-C).
 * It breaks all loops and leads to shutdown.
 */
void sigint_cb (EV_P_ ev_signal *w, int revents) {
	LOGGER_info("Signal INT received");
	ev_unloop (loop, EVUNLOOP_ALL);
}

/**
 * SIGPIPE call back, currently not used.
 */
void sigpipe_cb (EV_P_ ev_signal *w, int revents) {
	LOGGER_info("Ignoring SIGPIPE, libipfix should indefinitely try to reconnect to collector.");
}

/**
 * SIGALRM call back, currently not used.
 */
void sigalrm_cb (EV_P_ ev_signal *w, int revents) {
	LOGGER_info("Signal ALRM received");
}

/**
 * Setups and starts main event loop.
 */
void event_loop() {
	//	struct ev_loop *loop = ev_default_loop (EVLOOP_ONESHOT);
	struct ev_loop *loop = ev_default_loop(0);
	if (!loop) {
		LOGGER_fatal("Could not initialize loop!");
		exit(EXIT_FAILURE);
	}
	LOGGER_info("event_loop()");
	/*=== Setting up event loop ==*/
	/* signals */
	ev_signal_init(&events.sigint_watcher, sigint_cb, SIGINT);
	ev_signal_start(loop, &events.sigint_watcher);
	ev_signal_init(&events.sigalrm_watcher, sigalrm_cb, SIGALRM);
	ev_signal_start(loop, &events.sigalrm_watcher);

	ev_signal_init(&events.sigpipe_watcher, sigpipe_cb, SIGPIPE);
	ev_signal_start(loop, &events.sigpipe_watcher);

	/* resync  */
	ev_init(&events.resync_timer, resync_timer_cb);
	events.resync_timer.repeat = RESYNC_PERIOD;
	ev_timer_again(loop, &events.resync_timer);

	/* export timers */
	ev_init (&events.export_timer_pkid, export_timer_pktid_cb );
	if(g_options.export_pktid_interval > 0 ){
		events.export_timer_pkid.repeat  = g_options.export_pktid_interval;
		ev_timer_again (loop, &events.export_timer_pkid);
	}
	ev_init (&events.export_timer_sampling, export_timer_sampling_cb );
	if(g_options.export_sampling_interval > 0){
		events.export_timer_sampling.repeat  = g_options.export_sampling_interval;
		ev_timer_again (loop, &events.export_timer_sampling);
	}
	ev_init (&events.export_timer_stats, export_timer_stats_cb );
	if( g_options.export_stats_interval > 0 ){
		events.export_timer_stats.repeat  = g_options.export_stats_interval;
		ev_timer_again (loop, &events.export_timer_stats);
	}

	/*  packet watchers */
	event_setup_pcapdev(loop);
	/* setup network console
	 */
	event_setup_netcon(loop);

	/* Enter main event loop; call unloop to exit.
	 *
	 * Everything is going to be handled within this call
	 * accordingly to callbacks defined above.
	 * */
	events.loop = loop;
	ev_loop(loop, 0);
}

/**
 * Called whenever a new packet is available. Note that packet_pcap_cb is
 * responsible for reading the packet.
 */
void packet_watcher_cb(EV_P_ ev_io *w, int revents) {
	LOGGER_trace("packet");
	// retrieve respective device a new packet was seen
	pcap_dev_t *pcap_dev_ptr = (pcap_dev_t *) w->data;

	// dispatch packet
	if( pcap_dispatch(pcap_dev_ptr->pcap_handle,
					PCAP_DISPATCH_PACKET_COUNT ,
					packet_pcap_cb,
					(u_char*) pcap_dev_ptr)< 0 ) {
		LOGGER_error( "Error DeviceNo  %s: %s\n",pcap_dev_ptr->ifname,
				pcap_geterr( pcap_dev_ptr->pcap_handle) );
	}

}

/**
 * Here we setup a pcap device in non block mode and configure libev to read
 * a packet as soon it is available.
 */
void event_setup_pcapdev(struct ev_loop *loop) {
	int i;
	pcap_dev_t * pcap_dev_ptr;
	for (i = 0; i < g_options.number_interfaces; i++) {
		LOGGER_debug("Setting up interface: %s", g_options.if_names[i]);

		pcap_dev_ptr = &pcap_devices[i];
		// TODO review
		pcap_dev_ptr->options = &g_options;

		if (pcap_setnonblock((*pcap_dev_ptr).pcap_handle, 1, pcap_errbuf) < 0) {
			LOGGER_error( "pcap_setnonblock: %s: %s", g_options.if_names[i],
					pcap_errbuf);
		}
		/* storing a reference of packet device to
		 be passed via watcher on a packet event so
		 we know which device to read the packet from */
		events.packet_watchers[i].data = (pcap_dev_t *) pcap_dev_ptr;
		ev_io_init(&events.packet_watchers[i], packet_watcher_cb, pcap_fileno(
				(*pcap_dev_ptr).pcap_handle), EV_READ);
		ev_io_start(loop, &events.packet_watchers[i]);
	}
}
/**
 * returns: 1 consumed, 0 otherwise
 */
int netcom_cmd_set_ratio(char *msg) {
	double sampling_ratio;
	unsigned long messageId = 0; // session id
	int i, matches;
	matches = sscanf(msg, "mid: %lu -r %lf ", &messageId, &sampling_ratio);
	if (matches == 2) {
		LOGGER_debug("id: %lu", messageId);
		/* currently sampling ratio is equal for all devices */
		for (i = 0; i < g_options.number_interfaces; i++) {
			if (sampling_set_ratio(pcap_devices[i].options, sampling_ratio)
					== -1) {
				LOGGER_error("error setting sampling ration: %f",
						sampling_ratio);
			} else {
				char response[255];
				snprintf(response, 255, "INFO: new sampling ratio: %.3f",
						sampling_ratio);
				LOGGER_debug("==> %s", response);
				export_data_sync(&pcap_devices[i], ev_now(events.loop) * 1000,
						messageId, 0, response);
			}
		}
		return NETCON_CMD_MATCHED;
	}
	//	if( messageId > 0 ){
	//		char response[255];
	//		snprintf(response,255,"ERROR: invalid command: %s",msg);
	//		LOGGER_debug("==> %s",response);
	//		/* FIXME review: interface devices and options are still confuse*/
	//		for (i = 0; i < options.number_interfaces; i++) {
	//			export_data_sync(&pcap_devices[i],
	//					ev_now(events.loop)*1000,
	//					messageId,
	//					0,
	//					response);
	//		}
	//	}
	return NETCON_CMD_UNKNOWN;
}

/**
 * Setup network console
 */
void event_setup_netcon(struct ev_loop *loop) {
	char *host = "localhost";
	int port = 5000;

	if (netcon_init(loop, host, port) < 0) {
		LOGGER_error("could not initialize netcon: host: %s, port: %d ", host,
				port);
	}
	netcon_register(netcom_cmd_set_ratio);
}

/*-----------------------------------------------------------------------------
 Export
 -----------------------------------------------------------------------------*/
void export_data_interface_stats(pcap_dev_t *dev,
		uint64_t observationTimeMilliseconds, u_int32_t size,
		u_int64_t deltaCount) {
	static uint16_t lengths[] = { 8, 4, 8, 4, 4, 0, 0 };
	static char interfaceName[255];
	static char interfaceDescription[255];
	struct pcap_stat pcapStat;
	struct in_addr addr;
	void *fields[] = { &observationTimeMilliseconds,
			&size, &deltaCount,
			&pcapStat.ps_recv, &pcapStat.ps_drop, interfaceName, interfaceDescription };
	snprintf(interfaceName,255, "%s",dev->ifname );
	addr.s_addr = htonl(dev->IPv4address);
	snprintf(interfaceDescription,255,"%s",inet_ntoa(addr));
	lengths[5]=strlen(interfaceName);
	lengths[6]=strlen(interfaceDescription);

	/* Get pcap statistics in case of live capture */
	if (g_options.file == NULL) {
		if (pcap_stats(dev->pcap_handle, &pcapStat) < 0) {
			LOGGER_error("Error DeviceNo  %s: %s\n", dev->ifname, pcap_geterr(
					dev->pcap_handle));
		}
	} else {
		pcapStat.ps_drop = 0;
		pcapStat.ps_recv = 0;
	}

	LOGGER_trace("sampling: (%d, %lu)", size, (long unsigned) deltaCount);
	if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_interface_stats, 7,
			fields, lengths) < 0) {
		LOGGER_error("ipfix export failed: %s", strerror(errno));
	} else {
		dev->sampling_size = 0;
		dev->sampling_delta_count = 0;
	}
}

void export_data_sync(pcap_dev_t *dev,
		int64_t observationTimeMilliseconds, u_int32_t messageId,
		u_int32_t messageValue, char * message) {
	static uint16_t lengths[] = { 8, 4, 4, 0 };
	lengths[3] = strlen(message);
	void *fields[] = { &observationTimeMilliseconds, &messageId, &messageValue,
			message };
	LOGGER_debug("export data sync");
	if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_sync, 4,
			fields, lengths) < 0) {
		LOGGER_error("ipfix export failed: %s", strerror(errno));
		return;
	}
	if (ipfix_export_flush(dev->ipfixhandle) < 0) {
		LOGGER_error("Could not export IPFIX (flush) ");
	}

}

void export_data_probe_stats(pcap_dev_t *dev) {
	static uint16_t lengths[] = { 8, 4, 8, 4, 4, 8, 8 };
	struct probe_stat probeStat;


	void *fields[] = { &probeStat.observationTimeMilliseconds,
			&probeStat.systemCpuIdle, &probeStat.systemMemFree,
			&probeStat.processCpuUser, &probeStat.processCpuSys,
			&probeStat.processMemVzs, &probeStat.processMemRss };

	probeStat.observationTimeMilliseconds = (uint64_t) ev_now(events.loop)
			* 1000;
	get_probe_stats(&probeStat);

	if (ipfix_export_array(dev->ipfixhandle, dev->ipfixtmpl_probe_stats, 7,
			fields, lengths) < 0) {
		LOGGER_error("ipfix export failed: %s", strerror(errno));
		return;
	}

}

/**
 * This causes libipfix to send cached messages to
 * the registered collectors.
 */
void export_flush() {
	int i;
	LOGGER_trace("export_flush");
	for (i = 0; i < g_options.number_interfaces; i++) {
		if( ipfix_export_flush(pcap_devices[i].ipfixhandle) < 0 ){
			LOGGER_error("Could not export IPFIX, device: %d", i);
			//			ipfix_reconnect();
			break;
		}
	}
}
/**
 * Periodically called each export time interval.
 *
 */
void export_timer_pktid_cb (EV_P_ ev_timer *w, int revents) {
	LOGGER_trace("export timer tick");
	export_flush();
}
/**
 * Peridically called each export/sampling time interval
 */
void export_timer_sampling_cb (EV_P_ ev_timer *w, int revents) {
	int i;
	uint64_t observationTimeMilliseconds;
	LOGGER_trace("export timer sampling call back");
	observationTimeMilliseconds = (uint64_t)ev_now(events.loop) * 1000;
	for (i = 0; i < g_options.number_interfaces ; i++) {
		pcap_dev_t *dev = &pcap_devices[i];
		export_data_interface_stats(dev, observationTimeMilliseconds, dev->sampling_size, dev->sampling_delta_count );
	}
	export_flush();
}
/**
 * Periodically checks ipfix export fd and reconnects it
 * to netcon
 */
void resync_timer_cb (EV_P_ ev_timer *w, int revents) {
	int i;
	ipfix_collector_sync_t *col;
	for (i = 0; i < (g_options.number_interfaces); i++) {
		col = (ipfix_collector_sync_t*) pcap_devices[i].ipfixhandle->collectors;
		netcon_resync( col->fd );

	}
}

void export_timer_stats_cb (EV_P_ ev_timer *w, int revents) {
	/* using ipfix handle from first interface */
	export_data_probe_stats(&pcap_devices[0] );
	export_flush();
}


