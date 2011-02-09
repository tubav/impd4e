/* impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll) & TU-Berlin (Christian Henke)
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software Foundation;
 *  either version 3 of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.

 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOGGER_H_
#define LOGGER_H_

/* Ignore some macros in case of not using gnuc */
#ifndef __GNUC__
#  define  __attribute__(x)  /*NOTHING*/
#  define __FUNCTION__ "unknown"
#endif




/**
 Log level, following convention from:
 http://www.slf4j.org/api/org/apache/commons/logging/Log.html
*/
#define LOG_N_LEVELS 6
#define LOGGER_LEVEL_FATAL 0
#define LOGGER_LEVEL_ERROR 1
#define LOGGER_LEVEL_WARN  2
#define LOGGER_LEVEL_INFO  3
#define LOGGER_LEVEL_DEBUG 4
#define LOGGER_LEVEL_TRACE 5




#define LOGGER_fatal(...) logger(LOGGER_LEVEL_FATAL ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__) // the most serious
#define LOGGER_error(...) logger(LOGGER_LEVEL_ERROR ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__)
#define LOGGER_warn(...)  logger(LOGGER_LEVEL_WARN  ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__)
#define LOGGER_info(...)  logger(LOGGER_LEVEL_INFO  ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__) // recommended default level
#define LOGGER_debug(...) logger(LOGGER_LEVEL_DEBUG ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__)
#define LOGGER_trace(...) logger(LOGGER_LEVEL_TRACE ,__FILE__,__LINE__,__FUNCTION__,__VA_ARGS__) // the least serious

/*
#define LOGGER_VERBOSITY_FATAL (LOG_N_LEVELS - 0);
#define LOGGER_VERBOSITY_ERROR (LOG_N_LEVELS - 1);
#define LOGGER_VERBOSITY_WARN  (LOG_N_LEVELS - 2);
#define LOGGER_VERBOSITY_INFO  (LOG_N_LEVELS - 3);
#define LOGGER_VERBOSITY_DEBUG (LOG_N_LEVELS - 4);
#define LOGGER_VERBOSITY_TRACE (LOG_N_LEVELS - 5);
*/

/**
 * Initialize logger. Levels lower than level will be bypassed.
 */
void logger_init( int level );
/**
 * Set logger level
 */
void logger_setlevel( int level );
void logger  ( int level, const char *file, int line, const char *function,
              char fmt[], ... ) __attribute__((format (printf, 5, 6)));



#endif /* LOGGER_H_*/
