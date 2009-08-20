/* protect.h - Internal interface to the protec functions.
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

#ifndef PROTECT_H
#define PROTECT_H

int _tgpg_is_protected (const unsigned char *seckey);

int _tgpg_unprotect (const unsigned char *protectedkey, const char *passphrase,
                     unsigned char **result, size_t *resultlen);


#endif /*PROTECT_H*/
