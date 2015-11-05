# Makefile.am - for tgpg/src
# Copyright (C) 2015  g10 Code GmbH
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

# The test driver.
tgpgtest_SOURCES  = tgpgtest.c keystore-static.c
tgpgtest_CFLAGS = -I$(top_srcdir)/src
tgpgtest_LDADD = $(LIBGCRYPT_LIBS) -L../src -ltgpg

# Key generation
GPG		?= gpg2
GPGHOME		?= gpghome
GPGFLAGS	?=
GPGFLAGSH	 = --homedir "$(GPGHOME)" $(GPGFLAGS)
GPGX		 = $(GPG) $(GPGFLAGSH) --with-colons --with-keygrip -k

gpghome: key.script
	mkdir "$@"
	chmod 700 "$@"
	$(GPG) --homedir "$@" $(GPGFLAGS) --gen-key --batch '$<'

keystore-static.c: $(GPGHOME) ../tools/tgpg-keystore
	../tools/tgpg-keystore \
		`$(GPGX) | grep '^sub' | cut -d: -f5` \
		"$<"/private-keys-v1.d/`$(GPGX) | grep '^grp' | tail -n 1 | cut -d: -f10`.key >"$@"

%.gpg: %
	rm -f -- "$@"
	$(GPG) $(GPGFLAGSH) --recipient `$(GPGX) | grep '^sub' | cut -d: -f5` --disable-mdc -z0 --batch --encrypt "$<"

TESTFILE	= testdata

$(TESTFILE):
	dd if=/dev/urandom of="$@" bs=4k count=1

check: tgpgtest $(TESTFILE) $(TESTFILE).gpg
	test "`sha1sum < $(TESTFILE)`" \
		= "`./tgpgtest $(TESTFILE).gpg | sha1sum`"

clean-local:
	rm -rf -- gpghome $(TESTFILE) $(TESTFILE).gpg
