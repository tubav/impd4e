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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include "logger.h"

/**
 * Logger model
 */
static struct  {
   int level;
   FILE        *fp;
   const char *time_fmt;
} logger_model ;

typedef struct filter_list filter_list_t;
struct filter_list{
   filter_list_t* next;
   char* value;
};

static filter_list_t* include_list = NULL;
static filter_list_t* exclude_list = NULL;

filter_list_t* push_filter( filter_list_t* list, char* value ){
   if( NULL == list ) {
      list = (filter_list_t*) malloc( sizeof(filter_list_t) );
      list->next = NULL;
      list->value = value;
      // fprintf( stderr, "%s\n", list->value); // todo: remove when finish
   }
   else {
      // fprintf( stderr, "%s->", list->value); // todo: remove when finish
      list->next = push_filter( list->next, value );
   }
   return list;
}

void logger_set_filter( char* s_filter ) {
   char* token;
   // prevent segmentation fault when there is no string
   s_filter = s_filter?s_filter:"";

   // read all filter values
   token = strtok( s_filter, "," );
   if( NULL != token ) {
      do {
         if( '-' == token[0] ) {
            // add to exclude list
            exclude_list = push_filter( exclude_list, ++token );
         }
         else {
            // add to include list
            include_list = push_filter( include_list, token );
         }
      }
      while( NULL != (token = strtok( NULL, "," )) );
   }
}

bool is_filter( filter_list_t* list, const char* s ) {
   // check for end of list
   if( NULL == list ) return false;
   // check for matching anything
   if( 0 == strcmp("*", list->value) ) return true;

   const char* tmp_f = list->value;
   const char* tmp_s = s;
   bool  start_with_asterix = '*' == *tmp_f;

   // skip the asterix if needed
   tmp_f = start_with_asterix?tmp_f+1:tmp_f;
   do {
      int i = 0;
      while( '\0' != tmp_f[i] && '\0' != tmp_s[i] && tmp_f[i] == tmp_s[i]) {
         ++i;
      }
      if( '*'  == tmp_f[i] ) return true;
      if( tmp_s[i] == tmp_f[i] ) return true;
      ++tmp_s;
   }
   while( '\0' != *tmp_s && start_with_asterix); // find start location in string
//   if( '*' == *tmp_f ) {
//      ++tmp_f; // skip the asterix
//      while( '\0' != *tmp_s ) {
//         int i = 0;
//         while( '\0' != tmp_f[i] && '\0' != tmp_s[i] && tmp_f[i] == tmp_s[i]) {
//            ++i;
//         }
//         if( '*'  == tmp_f[i] ) return true;
//         if( tmp_s[i] == tmp_f[i] ) return true;
//         ++tmp_s;
//      }
//   }
//   else {
//      int i = 0;
//      while( '\0' != tmp_f[i] && '\0' != tmp_s[i] && tmp_f[i] == tmp_s[i]) {
//         ++i;
//      }
//      if( '*'  == tmp_f[i] ) return true;
//      if( tmp_s[i] == tmp_f[i] ) return true;
//   }

   return is_filter(list->next, s);
}

bool is_logging( const char* s ) {
   // check if function is in include list
   if( NULL == include_list || is_filter(include_list, s) ){
      if( NULL != exclude_list && is_filter(exclude_list, s) ) {
         return false;
      }
      return true;
   }
   return false;
}

/**
 * Initialize logger
 */
void logger_init( int level ){
   // TODO support file
   logger_model.fp=NULL;
   //   logger_model.time_fmt="%m-%d-%Y %T.";
   logger_model.time_fmt="%T.";
   logger_set_level(level);
}

void logger_set_level( int level ){
   logger_model.level=level;
   logger_model.level=level<0?0:level;
   logger_model.level=level>LOG_N_LEVELS?LOG_N_LEVELS-1:level;

}

int logger_get_level(){
   return logger_model.level;
}

/**
 * Log message
 */
void logger ( int level, const char *file, int line, const char *function,  char fmt[], ... ) {
   // stop logging if below log level
   if ( level > logger_model.level ){
      return;
   }

   if( is_logging(function) ) {
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

      logger_model.fp=logger_model.fp?logger_model.fp:stderr;

      gettimeofday(&tv, NULL);
      curtime=tv.tv_sec;

      // creating log string
      strftime(timeBuffer,30,logger_model.time_fmt, localtime(&curtime));

      // TODO: syncronisation may be needed
      // print start of line
      fprintf( logger_model.fp, "%s%ld %s ", timeBuffer, tv.tv_usec, strlevel[level]);

      // varargs
      va_list args;
      // processing varargs
      va_start(args, fmt);

      // print user data
      vfprintf( logger_model.fp, fmt, args );

      va_end(args);

      // print end of line
      fprintf( logger_model.fp, " (%s(), %s:%d)\n", function, file, line );

      fflush( logger_model.fp );
   }
}

//void logger_array(int level, const char *file, int line, const char *function,  char fmt[], char* p, int l ) {
//   int  len = 3*l;
//   char b[len];
//   int i;
//   for( i=0; i < l; ++i, len-=3 ) {
//      snprintf( b[i*3], len, "%02X ", p[i] );
//   }
//
//   //logger(
//}



