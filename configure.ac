#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([impd4e],[1.0])
AC_CONFIG_SRCDIR([./main.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADER([config.h])
AC_CANONICAL_TARGET

#check for git-core
#and git githash and git branch used for building
AC_DEFINE_UNQUOTED([GIT_BRANCH],["`git status | grep branch | head -1 | sed "s/.*branch *//g"`"],[Git Branch])
AC_DEFINE_UNQUOTED([GIT_HASH],  ["`git log -1 --pretty=format:%H`"],[Git Hash])
AC_DEFINE_UNQUOTED([BUILD_DATE],["`date`"],[Build Date])
#AC_DEFINE_UNQUOTED([BUILD_VERSION],["`head -1 ./debian/changelog | perl -nle 'm/\S+\s+\((\S+)-\S+\)/ and print $$1'`"],[Build Version])

# Checks for programs.
#############################
AC_PROG_CC
AC_PROG_INSTALL
#AC_PATH_PROG(OPENSSL,openssl,openssl)
PKG_PROG_PKG_CONFIG

# DEBUG mode
AC_ARG_ENABLE(
   [debug],
   [AS_HELP_STRING([--enable-debug],[enable debug mode])],
   [AC_DEFINE([DEBUG], [], [enable debug mode])],
   []
)

# IPv6 support
AC_ARG_ENABLE(
   [ipv6],
   [AS_HELP_STRING([--enable-ipv6],[enable IPv6 (with IPv4) support]))],
   [AC_DEFINE([INET6], [], [enabel IPv6 (with IPv4) support])],
   []
)

# specify libpcap
case "$target_os" in
cygwin)
	CPPFLAGS="-DWINNT $CPPFLAGS"
   PCAP="wpcap"
   ;;
*)
   PCAP="pcap"
   ;;
esac

AC_ARG_WITH(pcap,
   [AS_HELP_STRING([--with-pcap=DIR],[location of libpcap installation])],
   [ 
      if test $withval != no ; then
         AC_MSG_CHECKING(for lib$PCAP in $withval/lib)
         if test -f $withval/lib/lib$PCAP.a -o -f $withval/lib/lib$PCAP.so ; then
            LDFLAGS="$LDFLAGS -L$withval/lib "
            PCAPINCLS="-I$withval/include"
            AC_MSG_RESULT(yes)
         else
            AC_MSG_RESULT(no)
         fi
         withoutpcap="no"
      else
         withoutpcap="yes"
      fi
   ],
   [withoutpcap="no"]
)


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
#############################
AC_CHECK_LIB(misc, mlogf,,[AC_MSG_WARN([cannot find libmisc])])
AC_CHECK_LIB(ipfix, ipfix_open,,[AC_MSG_ERROR([cannot find library])],[-lmisc])
AC_CHECK_HEADERS([ipfix.h])

# libev support
#############################
PKG_CHECK_MODULES(
   [EV], 
   [libev],
   [],
   [AC_MSG_WARN([pkg-config failed for libev, try alternative])
    AC_CHECK_LIB([ev],[ev_loop],, # this is supposed to be libev3
                 AC_CHECK_LIB([ev],[ev_run],,
                               #[AC_ DEFINE([EV_COMPAT3],[1],[activate compatibility mode for libev])])
                              [AC_MSG_ERROR([cannot find library])]
                 )
    )
    ]
)
AC_CHECK_HEADERS([ev.h])
AC_SUBST([EV_LIBS])
AC_SUBST([EV_CFLAGS])

# libpcap support
#############################
if test $withoutpcap != yes; then
   AC_CHECK_LIB([$PCAP], [pcap_open_live],,
                [AC_MSG_ERROR([cannot find library])])
   AC_CHECK_FUNCS(pcap_breakloop pcap_freecode)
   AC_CHECK_HEADERS([$PCAP.h])
fi

# Checks for header files.
AC_HEADER_STDC
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h getopt.h libgen.h])
AC_CHECK_HEADERS([inttypes.h stdlib.h unistd.h string.h limits.h stdio.h errno.h signal.h netinet/in.h])

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
