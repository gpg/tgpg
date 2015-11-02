# Makefile.am - for tgpg/src
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

## Process this file with automake to produce Makefile.in

AM_CFLAGS = $(LIBGCRYPT_CFLAGS)

noinst_PROGRAMS = tgpgtest

tgpg_source =  \
        tgpg.c tgpg.h tgpgdefs.h \
	cryptglue.c cryptglue.h \
        keystore.c  keystore.h \
        pktparser.c pktparser.h \
	protect.c protect.h \
	s2k.c s2k.h \
	util.c \
	strerror.c \
        decrypt.c


tgpgtest_SOURCES  = tgpgtest.c $(tgpg_source)

tgpgtest_LDADD = $(LIBGCRYPT_LIBS)




