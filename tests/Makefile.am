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
tgpgtest_SOURCES  = tgpgtest.c keystore.c
tgpgtest_CFLAGS = -I$(top_srcdir)/src
tgpgtest_LDADD = $(LIBGCRYPT_LIBS) -L../src -ltgpg

# Key generation
GPG		?= gpg2
TGPG		?= ./tgpgtest$(EXEEXT)
GPGHOME		?= gpghome
GPGFLAGS	?=
GPGFLAGSH	 = --homedir "$(GPGHOME)" $(GPGFLAGS)
GPGX		 = $(GPG) $(GPGFLAGSH) --with-colons --with-keygrip -k

EXTRA_DIST = key.script runtests.bash

gpghome: key.script
	mkdir "$@"
	chmod 700 "$@"
	$(GPG) --homedir "$@" $(GPGFLAGS) --gen-key --batch '$<'

keystore.c: $(GPGHOME) ../tools/tgpg-keystore$(EXEEXT)
	../tools/tgpg-keystore$(EXEEXT) \
		`$(GPGX) | grep '^sub' | cut -d: -f5` \
		"$<"/private-keys-v1.d/`$(GPGX) | grep '^grp' | tail -n 1 | cut -d: -f10`.key >"$@"

%.gpg: %
	rm -f -- "$@"
	$(GPG) $(GPGFLAGSH) --recipient `$(GPGX) | grep '^sub' | cut -d: -f5` --disable-mdc -z0 --batch --encrypt --output="$@" "$<"

%.gpg.mdc: %
	rm -f -- "$@"
	$(GPG) $(GPGFLAGSH) --recipient `$(GPGX) | grep '^sub' | cut -d: -f5` --force-mdc -z0 --batch --encrypt --output="$@" "$<"

%.tgpg: % $(TGPG)
	rm -f -- "$@"
	$(TGPG) --debug --encrypt --disable-mdc "$<" >"$@" || ( rm "$@" ; exit 1 )

%.tgpg.mdc: % $(TGPG)
	rm -f -- "$@"
	$(TGPG) --debug --encrypt "$<" >"$@" || ( rm "$@" ; exit 1 )

TESTFILES	= test0 test1
TESTFILES_GPG	= $(foreach TEST,$(TESTFILES),$(TEST).gpg $(TEST).gpg.mdc $(TEST).tgpg $(TEST).tgpg.mdc)

test0:
	python -c "import sys; sys.stdout.write(64*'A')" >"$@"

test1:
	dd if=/dev/urandom of="$@" bs=64 count=1


check: tgpgtest $(TESTFILES_GPG)
	$(top_srcdir)/tests/runtests.bash $(TESTFILES)

CLEANFILES = keystore.c $(TESTFILES) $(TESTFILES_GPG)
clean-local:
	rm -rf -- gpghome
