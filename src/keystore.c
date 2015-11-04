/* keystore.c - Key storage
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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "keystore.h"

/* XXX: Link this in.  */
extern struct keytable seckey_table[];

/* Return success (0) if we have the secret key matching the public
   key identified by KI. */
int
_tgpg_have_secret_key (keyinfo_t ki)
{
  int idx;

  fprintf (stderr, "DBG: Looking for keyid %04lx%04lx (algo %d)\n",
           ki->keyid[1], ki->keyid[0], ki->pubkey_algo);

  for (idx = 0; seckey_table[idx].algo; idx++)
    if (seckey_table[idx].algo == ki->pubkey_algo
        && seckey_table[idx].keyid_low == ki->keyid[0]
        && seckey_table[idx].keyid_high == ki->keyid[1])
      return 0;


  return TGPG_NO_SECKEY;
}


/* Return the secret key matching KI at R_SECKEY.  The caller needs to
   release the secret key later using _tgpg_free_secret_key.  */
int
_tgpg_get_secret_key (keyinfo_t ki, mpidesc_t *r_seckey)
{
  int idx, i;
  mpidesc_t mpis;

  fprintf (stderr, "DBG: get-secret_key for keyid %04lx%04lx (algo %d)\n",
           ki->keyid[1], ki->keyid[0], ki->pubkey_algo);

  for (idx = 0; seckey_table[idx].algo; idx++)
    if (seckey_table[idx].algo == ki->pubkey_algo
        && seckey_table[idx].keyid_low == ki->keyid[0]
        && seckey_table[idx].keyid_high == ki->keyid[1])
      break;
  if (!seckey_table[idx].algo)
    return TGPG_NO_SECKEY;

  if (seckey_table[idx].algo == PK_ALGO_RSA)
    {
      mpis = xtrycalloc (6+1, sizeof *mpis);
      if (!mpis)
        return TGPG_SYSERROR;
      for (i=0; i < 6; i++)
        {
          mpis[i].nbits    = seckey_table[idx].mpis[i].nbits;
          mpis[i].valuelen = seckey_table[idx].mpis[i].valuelen;
          mpis[i].value    = seckey_table[idx].mpis[i].value;
        }
      *r_seckey = mpis;
    }
  else
    return TGPG_INV_ALGO;

  return 0;
}



void
_tgpg_free_secret_key (mpidesc_t seckey)
{
  xfree (seckey);
}
