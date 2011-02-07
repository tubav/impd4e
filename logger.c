/*
 * impd4e - a small network probe which allows to monitor and sample datagrams
 * from the network and exports hash-based packet IDs over IPFIX
 *
 * Copyright (c) 2010, Fraunhofer FOKUS (Carsten Schmoll) &
 *                     TU-Berlin (Christian Henke)
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

/*
 * This is basically libipfix mlog with some formatting updates and
 * following the log level convention used by slf4j.
 *
 * THIS LOGGER IS NOT THREAD SAFE!
 * TODO add support to log to file
 * TODO disable traces via macro
 *
 * logger.c
 *
 */
#include <stdio.h>
#include "logger.h"
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

/**
 * Logger model
 */
static struct  {
	int level;
	FILE        *fp;
	const char *time_fmt;
} logger_model ;


/**
 * Initialize logger
 */
void logger_init( int level ){
	// TODO support file
	logger_model.fp=NULL;
	//	logger_model.time_fmt="%m-%d-%Y %T.";
	logger_model.time_fmt="%T.";
	logger_setlevel(level);
}
void logger_setlevel( int level ){
	logger_model.level=level;
	logger_model.level=level<0?0:level;
	logger_model.level=level>LOG_N_LEVELS?LOG_N_LEVELS-1:level;

}
/**
 * Log message
 */
void logger ( int level, const char *file, int line, const char *function,  char fmt[], ... ) {
	static char tmpbuf[4001];
	static const char strlevel [][6] = {
			"FATAL",
			"ERROR",
			"WARN ",
			"INFO ",
			"DEBUG",
			"TRACE"
	};
	// time info
	char timeBuffer[64];
	struct timeval tv;
	time_t curtime;
	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;
	// varargs
	va_list args;

	if ( level > logger_model.level ){
		return;
	}
	logger_model.fp=logger_model.fp?logger_model.fp:stderr;

	// processing varargs
	va_start(args, fmt);
	(void) vsnprintf( tmpbuf, sizeof(tmpbuf), fmt, args );
	va_end(args);
	// creating log string
	strftime(timeBuffer,30,logger_model.time_fmt, localtime(&curtime));
	fprintf( logger_model.fp, "%s%ld %s %s (%s(), %s:%d)\n",
			timeBuffer, tv.tv_usec, strlevel[level],  tmpbuf,function, file, line );
	fflush( logger_model.fp );
}

