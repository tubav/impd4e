/*
 * This is basically libipfix mlog with some formatting updates and
 * following the log level convention used by slf4j.
 *
 * THIS LOGGER IS NOT THREAD SAFE!
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

