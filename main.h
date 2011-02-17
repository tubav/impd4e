/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll, Ramon Massek) &
 *                     TU-Berlin (Christian Henke)
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

#ifndef MAIN_H_
#define MAIN_H_

#include <ipfix.h>
#include <stdbool.h>

#include "settings.h"

#include "constants.h"



// todo: just a workaround for now

void  libipfix_init();
void  libipfix_open(device_dev_t *if_device, options_t *options);
void  libipfix_reconnect();



#endif /* MAIN_H_ */
