/* s2k.h - Internal interface to the string to key  functions.
   Copyright (C) 2007 g10 Code GmbH

   This file is part of TGPG.

   TGPG is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   TPGP is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
   MA 02110-1301, USA.  */

#ifndef S2K_H
#define S2K_H

int _tgpg_s2k_hash (const char *passphrase, int algo,
                    int mode, const unsigned char *salt, unsigned long count,
                    unsigned char *key, size_t keylen);

#endif /*S2K_H*/
