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

// system header files
#include <stdio.h>  // printf
#include <stdlib.h> // malloc

// local header files
#include "ev_handler.h"
// Custom logger
#include "logger.h"

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------*/

/**
 * Event and Signal handling via libev
 */
ev_signal sigint_watcher;
ev_signal sigalrm_watcher;
ev_signal sigpipe_watcher;

/* -- signals --*/
void sigint_cb  (EV_P_ ev_signal *w, int revents);
void sigalrm_cb (EV_P_ ev_signal *w, int revents);
void sigpipe_cb (EV_P_ ev_signal *w, int revents);

/**
 * Call back for SIGINT (Ctrl-C).
 * It breaks all loops and leads to shutdown.
 */
void sigint_cb(EV_P_ ev_signal *w, int revents) {
    fprintf(stderr, "\n");
    LOGGER_info("Signal INT received");
    ev_unloop(EV_A_ EVUNLOOP_ALL);
}

/**
 * SIGPIPE call back, currently not used.
 */
void sigpipe_cb(EV_P_ ev_signal *w, int revents) {
    LOGGER_info("Ignoring SIGPIPE, libipfix should indefinitely try to reconnect to collector.");
}

/**
 * SIGALRM call back, currently not used.
 */
void sigalrm_cb(EV_P_ ev_signal *w, int revents) {
    LOGGER_info("Signal ALRM received");
}

/**
 * Setups and starts main event loop.
 */
void event_loop_init(EV_P) {
    LOGGER_info("call");

    /*=== Setting up event loop ==*/

    /* signals */
    ev_signal_init(&sigint_watcher, sigint_cb, SIGINT);
    ev_signal_start(EV_A_ & sigint_watcher);
    ev_signal_init(&sigalrm_watcher, sigalrm_cb, SIGALRM);
    ev_signal_start(EV_A_ & sigalrm_watcher);
    ev_signal_init(&sigpipe_watcher, sigpipe_cb, SIGPIPE);
    ev_signal_start(EV_A_ & sigpipe_watcher);

    return;
}

void event_loop_start( EV_P ) {
    LOGGER_info("call");
    /* Enter main event loop; call unloop to exit.
     *
     * Everything is going to be handled within this call
     * accordingly to callbacks defined above.
     * */
    ev_loop(EV_A_ 0);
    return;
}

/**
 * register io call-backs for reading
 */
ev_watcher* event_register_io_r(EV_P_ watcher_cb_t cb, int fd) {
	ev_io* ev_handle = (ev_io*) malloc(sizeof(ev_io));

	// ev_init does not case to ev_watcher, while setting callback
	ev_init( ev_handle, (io_cb_t)cb);
	ev_io_set(ev_handle, fd, EV_READ);
    ev_io_start(EV_A_ ev_handle);

	return (ev_watcher*) ev_handle;
}

/**
 * register io call-backs for writing
 */
ev_watcher* event_register_io_w(EV_P_ watcher_cb_t cb, int fd) {
	ev_io* ev_handle = (ev_io*) malloc(sizeof(ev_io));

	// ev_init does not case to ev_watcher, while setting callback
	ev_init( ev_handle, (io_cb_t)cb);
	ev_io_set(ev_handle, fd, EV_WRITE);
    ev_io_start(EV_A_ ev_handle);

	return (ev_watcher*) ev_handle;
}

/**
 * register io call-backs for reading and writing
 */
ev_watcher* event_register_io(EV_P_ watcher_cb_t cb, int fd) {
	ev_io* ev_handle = (ev_io*) malloc(sizeof(ev_io));

	// ev_init does not case to ev_watcher, while setting callback
	ev_init( ev_handle, (io_cb_t)cb);
	ev_io_set(ev_handle, fd, EV_READ|EV_WRITE);
    ev_io_start(EV_A_ ev_handle);

	return (ev_watcher*) ev_handle;
}

/**
 * register timer callbacks
 * first execution of the callback immediately
 */
ev_watcher* event_register_timer(EV_P_ watcher_cb_t cb, double to) {
	ev_timer* ev_handle = (ev_timer*) malloc(sizeof(ev_timer));

	// ev_init does not case to ev_watcher, while setting callback
	ev_init( ev_handle, (timer_cb_t)cb);
	ev_timer_set(ev_handle, 0, to);
    ev_timer_start(EV_A_ ev_handle);

	return (ev_watcher*) ev_handle;
}

/**
 * register timer callbacks
 * first execution of the callback after timeout
 */
ev_watcher* event_register_timer_w(EV_P_ watcher_cb_t cb, double to) {
	ev_timer* ev_handle = (ev_timer*) malloc(sizeof(ev_timer));

	// ev_init does not case to ev_watcher, while setting callback
	ev_init( ev_handle, (timer_cb_t)cb);
	ev_timer_set(ev_handle, 0, to);
    ev_timer_again(EV_A_ ev_handle);

	return (ev_watcher*) ev_handle;
}

/**
 * deregister timer event handler
 */

void event_deregister_timer( EV_P_ ev_timer *w ) {
	ev_timer_stop( EV_A_ w );
	return;
}

/**
 * deregister io event handler
 */

void event_deregister_io( EV_P_ ev_io *w ) {
	ev_io_stop( EV_A_ w );
	return;
}

