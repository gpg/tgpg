/* keystore.h - Internal interface to the key storage.
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

#ifndef KEYSTORE_H
#define KEYSTORE_H

#include "tgpgdefs.h"

int _tgpg_have_secret_key (keyinfo_t ki);
int _tgpg_get_secret_key (keyinfo_t ki, tgpg_mpi_t *r_seckey);
void _tgpg_free_secret_key (tgpg_mpi_t seckey);


#endif /*KEYSTORE_H*/
