
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

#include "helper.h"
#include "constants.h"

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------*/
#define RESYNC_PERIOD 1.5 /* seconds */


/**
 * Event and Signal handling via libev
 */
struct {
	struct ev_loop *loop;
	ev_signal sigint_watcher;
	ev_signal sigalrm_watcher;
	ev_signal sigpipe_watcher;
	ev_timer  export_timer_pkid;
	ev_timer  export_timer_sampling;
	ev_timer  export_timer_stats;
	ev_timer  resync_timer;
	ev_io     packet_watchers[MAX_INTERFACES];
} events;


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
	/* export device measurements */
	ev_init (&events.export_timer_pkid, export_timer_pktid_cb );
	if(g_options.export_pktid_interval > 0 ){
		events.export_timer_pkid.repeat  = g_options.export_pktid_interval;
		ev_timer_again (loop, &events.export_timer_pkid);
	}
	/* export device sampling stats */
	ev_init (&events.export_timer_sampling, export_timer_sampling_cb );
	if(g_options.export_sampling_interval > 0){
		events.export_timer_sampling.repeat  = g_options.export_sampling_interval;
		ev_timer_again (loop, &events.export_timer_sampling);
	}
	/* export system stats */
	ev_init (&events.export_timer_stats, export_timer_stats_cb );
	if( g_options.export_stats_interval > 0 ){
		events.export_timer_stats.repeat  = g_options.export_stats_interval;
		ev_timer_again (loop, &events.export_timer_stats);
	}

	/*  packet watchers */
	event_setup_pcapdev(loop);

	/* setup network console */
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


/**
 * Here we setup a pcap device in non block mode and configure libev to read
 * a packet as soon it is available.
 */
void event_setup_pcapdev(struct ev_loop *loop) {
	int i;
	device_dev_t * pcap_dev_ptr;
	for (i = 0; i < g_options.number_interfaces; i++) {
		LOGGER_debug("Setting up interface: %s", if_devices[i].device_name);

		pcap_dev_ptr = &if_devices[i];
		// TODO review

		setNONBlocking( pcap_dev_ptr );

		/* storing a reference of packet device to
		 be passed via watcher on a packet event so
		 we know which device to read the packet from */
		// todo: review; where is the memory allocated
		events.packet_watchers[i].data = (device_dev_t *) pcap_dev_ptr;
		ev_io_init(&events.packet_watchers[i], packet_watcher_cb
				, get_file_desc( pcap_dev_ptr )
				, EV_READ);
		ev_io_start(loop, &events.packet_watchers[i]);
	}
}

/**
 * Called whenever a new packet is available. Note that packet_pcap_cb is
 * responsible for reading the packet.
 */
void packet_watcher_cb(EV_P_ ev_io *w, int revents) {
	LOGGER_trace("packet");
	// retrieve respective device a new packet was seen
	device_dev_t *pcap_dev_ptr = (device_dev_t *) w->data;

	switch (pcap_dev_ptr->device_type) {
	case TYPE_testtype:
	case TYPE_PCAP_FILE:
	case TYPE_PCAP:
		// dispatch packet
		if( 0 > pcap_dispatch(pcap_dev_ptr->device_handle.pcap
							, PCAP_DISPATCH_PACKET_COUNT
							, packet_pcap_cb
							, (u_char*) pcap_dev_ptr) )
		{
			LOGGER_error( "Error DeviceNo  %s: %s\n"
					, pcap_dev_ptr->device_name
					, pcap_geterr( pcap_dev_ptr->device_handle.pcap) );
		}

		break;

	case TYPE_SOCKET_INET:
	case TYPE_SOCKET_UNIX:
		if( 0 > socket_dispatch( if_devices[0].device_handle.socket
							, PCAP_DISPATCH_PACKET_COUNT
							, packet_pcap_cb
							, (u_char*) pcap_dev_ptr) )
		{
			LOGGER_error( "Error DeviceNo  %s: %s\n"
					, pcap_dev_ptr->device_name, "" );

		}
		break;

	default:
		break;
	}
}
// formaly known as handle_packet()
void packet_pcap_cb(u_char *user_args, const struct pcap_pkthdr *header, const u_char * packet) {
	device_dev_t* if_device = (device_dev_t*) user_args;
	//	int16_t headerOffset[4];
	uint8_t layers[4] = { 0 };
	uint32_t hash_result;
	uint32_t copiedbytes;
	uint8_t ttl;
	uint64_t timestamp;

	LOGGER_trace("handle packet");

	if_device->sampling_delta_count++;
	if_device->totalpacketcount++;

	if(0){//if( INFO <= mlog_vlevel ) {
		int i = 0;
		for (i = 0; i < header->caplen; ++i) {
			mlogf(INFO, "%02x ", packet[i]);
			//fprintf(stderr, "%c", packet[i]);
		}
		mlogf(INFO, "\n");
	}

	// selection of viable fields of the packet - depend on the selection function choosen
	copiedbytes = g_options.selection_function(packet, header->caplen,
			if_device->outbuffer, if_device->outbufferLength,
			if_device->offset, layers);

	ttl = getTTL(packet, header->caplen, if_device->offset[L_NET],
			layers[L_NET]);

	if (0 == copiedbytes) {

		mlogf(ALL, "Warning: packet does not contain Selection\n");
		// todo: ?alternative selection function
		// todo: ?for the whole configuration
		// todo: ????drop????
		return;
	}
	//	else {
	//		mlogf( WARNING, "Warnig: packet contain Selection (%d)\n", copiedbytes);
	//	}

	// hash the chosen packet data
	hash_result = g_options.hash_function(if_device->outbuffer, copiedbytes);
	mlogf( ALL, "hash result: 0x%04X\n", hash_result );

	// hash result must be in the chosen selection range to count
	if ((g_options.sel_range_min < hash_result)
			&& (g_options.sel_range_max > hash_result))
	{
		if_device->export_packet_count++;
		if_device->sampling_size++;

		// bypassing export if disabled by cmd line
		if (g_options.export_pktid_interval <= 0) {
			return;
		}

		int pktid = 0;
		// in case we want to use the hashID as packet ID
		if (g_options.hashAsPacketID == 1) {
			pktid = hash_result;
		} else {
			pktid = g_options.pktid_function(if_device->outbuffer, copiedbytes);
		}

		timestamp = (uint64_t) header->ts.tv_sec * 1000000ULL
				+ (uint64_t) header->ts.tv_usec;

		switch (g_options.templateID) {
		case MINT_ID: {
			void* fields[] = { &timestamp, &hash_result, &ttl };
			uint16_t lengths[] = { 8, 4, 1 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtmpl_min, 3, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		case TS_ID: {
			void* fields[] = { &timestamp, &hash_result };
			uint16_t lengths[] = { 8, 4 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtmpl_ts, 2, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		case TS_TTL_PROTO_ID: {
			uint16_t length;

			if (layers[L_NET] == N_IP) {
				length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 2])));
			} else if (layers[L_NET] == N_IP6) {
				length = ntohs(*((uint16_t*) (&packet[if_device->offset[L_NET] + 4])));
			} else {
				mlogf(ALWAYS, "cannot parse packet length \n");
				length = 0;
			}

			void* fields[] = { &timestamp, &hash_result, &ttl, &length, &layers[L_TRANS], &layers[L_NET] };
			uint16_t lengths[6] = { 8, 4, 1, 2, 1, 1 };

			if (0 > ipfix_export_array(if_device->ipfixhandle,
					if_device->ipfixtmpl_ts_ttl, 6, fields, lengths)) {
				mlogf(ALWAYS, "ipfix_export() failed: %s\n", strerror(errno));
				exit(1);
			}
			break;
		}

		default:
			break;
		} // switch (options.templateID)

		// flush ipfix storage if max packetcount is reached
		if (if_device->export_packet_count >= g_options.export_packet_count) {
			//todo: export_flush_device( if_device );
			if_device->export_packet_count = 0;
			export_flush();
		}

	} // if((options.sel_range_min < hash_result) && (options.sel_range_max > hash_result))
	else {
		mlogf(INFO, "INFO: drop packet; hash not in selection range\n");
	}
}


/**
 * returns: 1 consumed, 0 otherwise
 */
int netcom_cmd_set_ratio(char *msg) {
	double sampling_ratio;
	unsigned long messageId = 0; // session id
	int matches;
	matches = sscanf(msg, "mid: %lu -r %lf ", &messageId, &sampling_ratio);
	if (2 == matches) {
		LOGGER_debug("id: %lu", messageId);
		/* currently sampling ratio is equal for all devices */
		if (-1 == sampling_set_ratio(&g_options, sampling_ratio) ) {
			LOGGER_error("error setting sampling ration: %f", sampling_ratio);
		}
		else {
			int i;
			for (i = 0; i < g_options.number_interfaces; i++) {
				char response[255];
				snprintf(response, 255, "INFO: new sampling ratio: %.3f",
						sampling_ratio);
				LOGGER_debug("==> %s", response);
				export_data_sync(&if_devices[i], ev_now(events.loop) * 1000,
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

/*-----------------------------------------------------------------------------
 Export
 -----------------------------------------------------------------------------*/
void export_data_interface_stats(device_dev_t *dev,
		uint64_t observationTimeMilliseconds, u_int32_t size,
		u_int64_t deltaCount) {
	static uint16_t lengths[] = { 8, 4, 8, 4, 4, 0, 0 };
	static char interfaceName[255];
	static char interfaceDescription[255];
	struct pcap_stat pcapStat;
	struct in_addr addr;
	void*  fields[] = { &observationTimeMilliseconds, &size, &deltaCount
					, &pcapStat.ps_recv, &pcapStat.ps_drop
					, interfaceName, interfaceDescription };
	snprintf(interfaceName,255, "%s",dev->device_name );
	addr.s_addr = htonl(dev->IPv4address);
	snprintf(interfaceDescription,255,"%s",inet_ntoa(addr));
	lengths[5]=strlen(interfaceName);
	lengths[6]=strlen(interfaceDescription);

	/* Get pcap statistics in case of live capture */
	if ( TYPE_PCAP == dev->device_type ) {
		if (pcap_stats(dev->device_handle.pcap, &pcapStat) < 0) {
			LOGGER_error("Error DeviceNo  %s: %s\n", dev->device_name
						, pcap_geterr(dev->device_handle.pcap));
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

void export_data_sync(device_dev_t *dev,
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

void export_data_probe_stats(device_dev_t *dev) {
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
 *
 * flushes each device
 */
void export_flush() {
	int i;
	LOGGER_trace("export_flush");
	for (i = 0; i < g_options.number_interfaces; i++) {
		if( ipfix_export_flush(if_devices[i].ipfixhandle) < 0 ){
			LOGGER_error("Could not export IPFIX, device: %d", i);
			//			ipfix_reconnect();
			break;
		}
	}
}

void export_flush_all() {
	int i;
	LOGGER_trace("export_flush_all");
	for (i = 0; i < g_options.number_interfaces; i++) {
		export_flush_device( &if_devices[i] );
	}
}

void export_flush_device( device_dev_t* device ) {
	LOGGER_trace("export_flush_device");
	if( 0 != device ) {
		device->export_packet_count = 0;
		if( ipfix_export_flush(device->ipfixhandle) < 0 ){
			LOGGER_error("Could not export IPFIX: %s", device->device_name);
			//			ipfix_reconnect();
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
		device_dev_t *dev = &if_devices[i];
		export_data_interface_stats(dev, observationTimeMilliseconds, dev->sampling_size, dev->sampling_delta_count );
	}
	export_flush();
}

void export_timer_stats_cb (EV_P_ ev_timer *w, int revents) {
	/* using ipfix handle from first interface */
	export_data_probe_stats(&if_devices[0] );
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
		col = (ipfix_collector_sync_t*) if_devices[i].ipfixhandle->collectors;
		LOGGER_debug("collector_fd: %d", col->fd);
		netcon_resync( col->fd );
	}
}


