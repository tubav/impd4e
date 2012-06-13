
// system header files
#include <errno.h>  // errno
#include <string.h> //strlen

// local header files
#include "export_handler.h"

#include "ev_handler.h"
#include "ipfix_handler.h"

#include "helper.h"   // ntoa
#include "settings.h" // g_options
#include "logger.h"
#include "stats.h"    // struct probe_stat


/* -- export -- */
void export_timer_pktid_cb    (EV_P_ ev_watcher *w, int revents);
void export_timer_sampling_cb (EV_P_ ev_watcher *w, int revents);
void export_timer_stats_cb    (EV_P_ ev_watcher *w, int revents);
void export_timer_location_cb (EV_P_ ev_watcher *w, int revents);


// TODO: not here
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



ev_timer* export_timer_pkid;
ev_timer* export_timer_sampling;
ev_timer* export_timer_stats;
ev_timer* export_timer_location;

void export_handler_init(EV_P) {
    LOGGER_info("call");

    /* export timers */
    /* export device measurements */
    LOGGER_info("register event timer: export packets");
    export_timer_pkid = (ev_timer*)event_register_timer_w(
    		EV_A_
    		export_timer_pktid_cb,
    		g_options.export_pktid_interval
    		);

    /* export device sampling stats */
    LOGGER_info("register event timer: export sampling stats");
    export_timer_sampling = (ev_timer*)event_register_timer_w(
    		EV_A_
    		export_timer_sampling_cb,
    		g_options.export_sampling_interval
    		);

    /* export system stats - with at least one export*/
    LOGGER_info("register event timer: export system stats");
    export_timer_stats = (ev_timer*)event_register_timer(
    		EV_A_
    		export_timer_stats_cb,
    		g_options.export_stats_interval
    		);

    /* export system location - with at least one export*/
    LOGGER_info("register event timer: export system location");
    export_timer_location = (ev_timer*)event_register_timer(
    		EV_A_
    		export_timer_location_cb,
    		g_options.export_location_interval
    		);
}

/*-----------------------------------------------------------------------------
  Export
  -----------------------------------------------------------------------------*/
void export_data_interface_stats(device_dev_t *dev,
        uint64_t observationTimeMilliseconds, u_int32_t size,
        u_int64_t deltaCount) {
    static uint16_t lengths[] = {8, 4, 8, 4, 4, 0, 0};
    static char interfaceDescription[16];
#ifndef PFRING
    struct pcap_stat pcapStat;
    void* fields[] = {&observationTimeMilliseconds, &size, &deltaCount,
        &pcapStat.ps_recv, &pcapStat.ps_drop, dev->device_name,
        interfaceDescription};
#else
    pfring_stat pfringStat;
    void* fields[] = {&observationTimeMilliseconds, &size, &deltaCount
        , &pfringStat.recv
        , &pfringStat.drop
        , dev->device_name
        , interfaceDescription};
#endif

    snprintf(interfaceDescription, sizeof (interfaceDescription), "%s",
            ntoa(dev->IPv4address));
    lengths[5] = strlen(dev->device_name);
    lengths[6] = strlen(interfaceDescription);

#ifndef PFRING
    /* Get pcap statistics in case of live capture */
    if (TYPE_PCAP == dev->device_type) {
        if (pcap_stats(dev->device_handle.pcap, &pcapStat) < 0) {
            LOGGER_error("Error DeviceNo   %s: %s", dev->device_name,
                    pcap_geterr(dev->device_handle.pcap));
        }
    } else {
        pcapStat.ps_drop = 0;
        pcapStat.ps_recv = 0;
    }
#else
    if (TYPE_PFRING == dev->device_type) {
        if (pfring_stats(dev->device_handle.pfring, &pfringStat) < 0) {
            LOGGER_error("Error DeviceNo   %s: Failed to get statistics",
                    dev->device_name);
        }
    } else {
        pfringStat.drop = 0;
        pfringStat.recv = 0;
    }
#endif

    LOGGER_trace("sampling: (%d, %lu)", size, (long unsigned) deltaCount);
    if (ipfix_export_array(ipfix(), get_template(INTF_STATS_ID), 7,
            fields, lengths) < 0) {
        LOGGER_error("ipfix export failed: %s", strerror(errno));
    } else {
        dev->sampling_size = 0;
        dev->sampling_delta_count = 0;
    }
}

void export_data_sync(device_dev_t *dev, int64_t observationTimeMilliseconds,
        u_int32_t messageId, u_int32_t messageValue, char * message) {
    static uint16_t lengths[] = {8, 4, 4, 0};
    lengths[3] = strlen(message);
    void *fields[] = {&observationTimeMilliseconds, &messageId, &messageValue,
        message};
    LOGGER_debug("export data sync");
    if (ipfix_export_array(ipfix(), get_template(SYNC_ID), 4, fields,
            lengths) < 0) {
        LOGGER_error("ipfix export failed: %s", strerror(errno));
        return;
    }
    if (ipfix_export_flush(ipfix()) < 0) {
        LOGGER_error("Could not export IPFIX (flush) ");
    }

}

void export_data_probe_stats(int64_t observationTimeMilliseconds) {
    static uint16_t lengths[] = {8, 4, 8, 4, 4, 8, 8, 8};
    struct probe_stat probeStat;

    void *fields[] = { &probeStat.observationTimeMilliseconds
                     , &probeStat.systemCpuIdle
                     , &probeStat.systemMemFree
                     , &probeStat.processCpuUser
                     , &probeStat.processCpuSys
                     , &probeStat.processMemVzs
                     , &probeStat.processMemRss
                     , &probeStat.systemMemTotal
                     };

    ipfix_template_t* t = get_template(PROBE_STATS_ID);

    probeStat.observationTimeMilliseconds = observationTimeMilliseconds;
    get_probe_stats(&probeStat);

    if (ipfix_export_array(ipfix(), t, t->nfields, fields, lengths) < 0) {
        LOGGER_error("ipfix export failed: %s", strerror(errno));
        return;
    }
    if (ipfix_export_flush(ipfix()) < 0) {
        LOGGER_error("Could not export IPFIX (flush) ");
    }
}

void export_data_location(int64_t observationTimeMilliseconds) {
    static uint16_t lengths[] = {8, 4, 0, 0, 0, 0};
    lengths[2] = strlen(getOptions()->s_latitude);
    lengths[3] = strlen(getOptions()->s_longitude);
    lengths[4] = strlen(getOptions()->s_probe_name);
    lengths[5] = strlen(getOptions()->s_location_name);
    void *fields[] = {&observationTimeMilliseconds, &getOptions()->ipAddress,
        getOptions()->s_latitude, getOptions()->s_longitude,
        getOptions()->s_probe_name, getOptions()->s_location_name};

    LOGGER_debug("export data location");
    //LOGGER_fatal("%s; %s",getOptions()->s_latitude, getOptions()->s_longitude );
    if (ipfix_export_array(ipfix(), get_template(LOCATION_ID),
            sizeof (lengths) / sizeof (lengths[0]), fields, lengths) < 0) {
        LOGGER_error("ipfix export failed: %s", strerror(errno));
        return;
    }
    if (ipfix_export_flush(ipfix()) < 0) {
        LOGGER_error("Could not export IPFIX (flush) ");
    }
}

void export_flush_all() {
    int i;
    LOGGER_trace("export_flush_all");
    for (i = 0; i < g_options.number_interfaces; i++) {
        export_flush_device(&if_devices[i]);
    }
}

void export_flush_device(device_dev_t* device) {
    LOGGER_trace("export_flush_device");
    if (0 != device) {
        device->export_packet_count = 0;
        if (ipfix_export_flush(ipfix()) < 0) {
            LOGGER_error("Could not export IPFIX: %s", device->device_name);
            //         ipfix_reconnect();
        }
    }
}

/**
 * Periodically called each export time interval.
 */
void export_timer_pktid_cb(EV_P_ ev_watcher *w, int revents) {
    LOGGER_trace("export timer tick");
    export_flush();
}

/**
 * Peridically called each export/sampling time interval
 */
void export_timer_sampling_cb(EV_P_ ev_watcher *w, int revents) {
    int i;
    uint64_t observationTimeMilliseconds;
    LOGGER_trace("export timer sampling call back");
    observationTimeMilliseconds = (uint64_t) ev_now(EV_A) * 1000;
    for (i = 0; i < g_options.number_interfaces; i++) {
        device_dev_t *dev = &if_devices[i];
        export_data_interface_stats(dev, observationTimeMilliseconds, dev->sampling_size, dev->sampling_delta_count);
#ifdef PFRING
#ifdef PFRING_STATS
        print_stats(dev);
#endif
#endif
    }
    export_flush();
}

void export_timer_stats_cb(EV_P_ ev_watcher *w, int revents) {
    LOGGER_trace("export timer probe stats call back");
    export_data_probe_stats( (uint64_t) ev_now(EV_A) * 1000 );
}

/**
 * Peridically called
 */
void export_timer_location_cb(EV_P_ ev_watcher *w, int revents) {
    LOGGER_trace("export timer location call back");
    export_data_location( (uint64_t) ev_now(EV_A) * 1000 );
}

