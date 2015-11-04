# configure.ac - for TGPG
# Copyright (C) 2007  g10 Code GmbH
#
# This file is part of TGPG.
#
# TGPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# TGPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
min_automake_version="1.9.3"

# Remember to change the version number immediately *after* a release.
# Set my_issvn to "yes" for non-released code.  Remember to run an
# "svn up" and "autogen.sh" right before creating a distribution.
m4_define([my_version], [0.0.0])
m4_define([my_issvn], [yes])

m4_define([svn_revision], m4_esyscmd([echo -n $( (svn info 2>/dev/null \
            || echo 'Revision: 0')|sed -n '/^Revision:/ {s/[^0-9]//gp;q;}')]))
AC_INIT([tgpg], my_version[]m4_if(my_issvn,[yes],[-svn[]svn_revision]),
        [bug-tgpg@g10code.com])
# Set development_version to yes if the minor number is odd or you
# feel that the default check for a development version is not
# sufficient.
development_version=no

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.2.0

AC_CONFIG_SRCDIR(src/tgpg.c)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_TARGET()
AM_INIT_AUTOMAKE
AB_INIT

AC_GNU_SOURCE

# Some status variables.
have_libgcrypt=no



# Confog.h top and bottom templates.
# To avoid double inclusion of config.h which might happen at some
# places, we add the usual double inclusion protection at the top of
# config.h.
#
AH_TOP([
#ifndef TGPG_CONFIG_H_INCLUDED
#define TGPG_CONFIG_H_INCLUDED
])

AH_BOTTOM([

/* We explicitly need to disable PTH's soft mapping as Debian
   currently enables it by default for no reason. */
#define PTH_SYSCALL_SOFT 0


#endif /*TGPG_CONFIG_H_INCLUDED*/
])


AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_CHECK_TOOL(AR, ar, :)
AC_ISC_POSIX
#gl_EARLY
AC_SYS_LARGEFILE

#
# Checks for libraries.
#

#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
        have_libgcrypt=yes,have_libgcrypt=no)



#
# Checks for header files.
#
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h unistd.h langinfo.h locale.h inttypes.h])
AC_HEADER_TIME


#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_UINT32_T


#
# Checks for library functions.
#
AC_FUNC_VPRINTF
AC_FUNC_FORK
AC_CHECK_FUNCS([strerror strlwr mmap strcasecmp strncasecmp gmtime_r])
AC_CHECK_FUNCS([gettimeofday atexit])

#
# gnulib checks
#


#
# W32 specific test
#



#
# Do we have zlib? Must do it here because Solaris failed
# when compiling a conftest (due to the "-lz" from LIBS).
# Note that we combine zlib and bzlib2 in ZLIBS.
#
_cppflags="${CPPFLAGS}"
_ldflags="${LDFLAGS}"
AC_ARG_WITH(zlib,
  [  --with-zlib=DIR         use libz in DIR],[
    if test -d "$withval"; then
      CPPFLAGS="${CPPFLAGS} -I$withval/include"
      LDFLAGS="${LDFLAGS} -L$withval/lib"
    fi
  ])

AC_CHECK_HEADER(zlib.h,
      AC_CHECK_LIB(z, deflateInit2_,
       ZLIBS="-lz",
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags}),
       CPPFLAGS=${_cppflags} LDFLAGS=${_ldflags})

AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

#
# Setup gcc specific options
#
if test "$GCC" = yes; then
    # Note that it is okay to use CFLAGS here because this are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wno-format-y2k -Wformat-security -Wformat-nonliteral"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi


#
# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
#
AC_ARG_ENABLE(optimization,
   AC_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                   fi])


#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_libgcrypt" = "no"; then
   die=no
   AC_MSG_NOTICE([[
***
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION using API $NEED_LIBGCRYPT_API is required.)
***]])
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi



AC_CONFIG_FILES([ m4/Makefile
Makefile
tools/Makefile
src/Makefile
doc/Makefile
tests/Makefile
])
AC_OUTPUT


echo "
        TGPG v${VERSION} has been configured as follows:

        Platform:  $host
"

