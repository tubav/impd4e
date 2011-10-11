#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([impd4e],[1.0])
AC_CONFIG_SRCDIR([./main.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET

VERSION=1.0
PACKAGE=impd4e

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
#AC_PATH_PROG(OPENSSL,openssl,openssl)

#
# IPv6 support
#
AC_ARG_ENABLE(ipv6,
[  --enable-ipv6           enable ipv6 (with ipv4) support
  --disable-ipv6          disable ipv6 support],
[ case "$enableval" in
  yes) ipv6=yes;;
  *)   ipv6=no ;;
  esac ], [ipv6=no])

if test $ipv6 = yes; then
	CPPFLAGS="-DINET6 $CPPFLAGS"
fi

# specify libpcap
#
case "$target_os" in
cygwin)
	CPPFLAGS="-DWINNT $CPPFLAGS"
        PCAP="wpcap"
        ;;
*)
        PCAP="pcap"
        ;;
esac

withval=""
withoutpcap="no"
AC_ARG_WITH(pcap,
[  --with-pcap=DIR         location of libpcap installation],
[ 
   if test $withval != no
   then
      AC_MSG_CHECKING(for lib$PCAP in $withval/lib)
      if test -f $withval/lib/lib$PCAP.a -o -f $withval/lib/lib$PCAP.so ; then
         LDFLAGS="$LDFLAGS -L$withval/lib "
         PCAPINCLS="-I$withval/include"
         AC_MSG_RESULT(yes)
      else
         AC_MSG_RESULT(no)
      fi
   else
      withoutpcap="yes"
   fi
] )


# os check
#
case "$target_os" in
freebsd*)
	LDFLAGS="$LDFLAGS -L/usr/local/lib "
	CPPFLAGS="$CPPFLAGS -I/usr/local/include "
	;;
esac

#############################
# Checks for libraries.     #
#############################

# libipfix support
##############################
AC_CHECK_LIB(ipfix, ipfix_open,,[AC_MSG_WARN([cannot find libipfix])])
AC_CHECK_LIB(misc, mlogf,,[AC_MSG_WARN([cannot find libmisc])])

# libev support
#############################
AC_CHECK_LIB(ev, ev_loop,,[AC_MSG_WARN([cannot find libev])])

# libpcap support
#############################
if test $withoutpcap != yes; then
    AC_CHECK_LIB([$PCAP], pcap_open_live,,
                 [AC_MSG_WARN([cannot find libpcap])])
    AC_CHECK_FUNCS(pcap_breakloop pcap_freecode)
#    AC_CHECK_LIB([$PCAP], pcap_open_live,[pcapsupport="yes"], 
#             [pcapsupport="no"; AC_MSG_WARN([cannot find libpcap])])
#    if test $pcapsupport = yes; then
#        SAVELIBS=$LIBS
#        LIBS="$LIBS $PCAPLIBS"
#        AC_CHECK_FUNCS(pcap_breakloop pcap_freecode)
#        LIBS=$SAVELIBS
#    else
#        PCAPLIBS=""
#    fi
#    AC_SUBST(PCAPLIBS)
#    AC_SUBST(PCAPINCLS)
#else
#    PCAPLIBS=""
fi

# Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h getopt.h libgen.h])
AC_CHECK_HEADERS([ev.h pcap.h ipfix.h inttypes.h stdlib.h unistd.h string.h limits.h stdio.h errno.h signal.h netinet/in.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_C_VOLATILE

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gettimeofday basename inet_ntoa memmove memset mkdir select strdup strerror])
AC_CHECK_FUNCS(gethostbyname,,[AC_CHECK_LIB(nsl,gethostbyname,,[AC_CHECK_LIB(socket,gethostbyname)])])
AC_CHECK_FUNCS(setsockopt,,[AC_CHECK_LIB(socket,setsockopt)])
AC_CHECK_FUNCS(hstrerror,,[AC_CHECK_LIB(resolv,hstrerror,,[AC_CHECK_LIB(socket,gethostbyname)])])
AC_CHECK_FUNCS([getopt_long],,
               [#FreeBSD has a gnugetopt library for this
               AC_CHECK_LIB([gnugetopt],[getopt_long],
                            [LIBS="-lgnugetopt $LIBS";AC_DEFINE([HAVE_GETOPT_LONG])])
               ])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
