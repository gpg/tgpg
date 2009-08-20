# Makefile.am - Top level makefile.
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

ACLOCAL_AMFLAGS = -I m4 
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = autogen.sh README.SVN

SUBDIRS = m4 src doc tests

dist-hook:
	echo "$(VERSION)" > $(distdir)/VERSION





