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


static struct
{
  int algo;
  unsigned long keyid_high;
  unsigned long keyid_low;
  struct mpidesc_s mpis[6];
} seckey_table[] = {
  {
    PK_ALGO_RSA, 0x907B5D16, 0x40619DD0,
    {
      { 1024, 17*7+9,
        "\xF1\xBD\x35\x42\x01\x51\xCC\xCD\x8E\x6F\x7F\x4A\x56\x0D\x8E\x8D\xA4"
        "\xCF\xB9\x62\xB7\x5D\x9E\x7A\x93\x2C\x68\x5F\x7D\xFA\x4F\x6F\xBA\x06"
        "\x03\x2A\xD0\x3E\xC3\x90\x40\x01\xD2\x89\xD2\xA2\x10\x9F\xEA\xB9\xF4"
        "\x90\x95\x11\x56\xF1\x75\xFD\x91\x1E\x30\x84\x20\xC4\x80\xEB\xB4\x5D"
        "\x65\xBD\x98\x87\x76\xD4\x89\x30\x68\x75\xA4\x8E\x1E\x38\x5D\x44\x76"
        "\x23\xB9\x0E\xB4\xD5\x2F\x2D\xE9\x2D\xB5\x87\x2F\xD7\xCD\x45\x4F\x32"
        "\x28\x6B\x3D\x38\x15\x05\x12\x34\x0D\xFE\x58\x81\x83\x5F\x83\x4D\x50"
        "\xB4\x24\x56\x55\xA5\xA5\xA9\x3F\x99" },
      { 8, 1,
        "\x29" },
      { 1024, 128,
        "\x09\xD3\xA8\xAB\x44\xBC\x8F\x9C\x20\xD8\xD3\x39\x22\xB7\xB4\x9F\xC6"
        "\x2D\xE8\x51\x05\x5F\x62\x04\xFB\x93\x7F\x0A\x20\x2D\x8E\xAD\x20\x89"
        "\x9C\x39\xEF\x7D\x59\x1E\xD6\xE5\x04\x65\x57\xA6\xD9\x21\x8E\xBE\xB6"
        "\xB0\x8B\x43\x4E\x76\x0B\x0A\x4E\xBE\xA0\x26\xAB\xFF\x95\x6F\x4C\x5B"
        "\xD7\x64\x07\x5E\xF6\x42\x74\xAE\x41\xB1\xDD\xED\x5C\x42\xA5\x47\xF6"
        "\xC6\x35\xE9\xDE\x5D\x4C\xFD\x83\x8F\xF2\xFE\xDE\x7F\xCC\x92\x76\x22"
        "\x9E\x60\x48\xB9\x29\xE4\x40\x3B\x58\xC5\x7A\x73\x03\x3E\xFA\x9C\x1A"
        "\x29\x21\x40\xBD\x6E\x11\x07\x1B\x19" },
      { 512, 64,
        "\xf4\x0E\xAF\xAB\x32\x96\x97\x0A\x27\x21\x61\x24\x4F\x56\xC3\x15\xFC"
        "\xA4\x5E\xC9\x60\x6F\x1B\x62\x63\x67\xCA\x7D\xD1\x64\xB6\x15\x40\x7A"
        "\x42\x07\x5C\x7D\x16\x4B\xC4\x33\xF4\xB7\xAB\x77\x29\xF3\x0B\x9D\xDF"
        "\x71\xF5\x6B\x94\xF9\x83\x7F\x34\x15\xD6\x8C\x80\xE1" },
      { 512, 64,
        "\xFD\x91\x7B\x12\x1A\x23\xE5\xC3\xA5\xB6\xBE\x80\x95\xD4\x27\xA9\x10"
        "\xC6\x1C\x90\xC5\x75\x6F\x66\x59\xA9\x65\x20\x73\x5A\x3F\x5A\x8D\xE2"
        "\x7C\x5E\x32\x2E\x40\x78\x7C\x05\xE6\x91\xA1\x08\xF5\xDE\x22\x3C\xBA"
        "\x79\xDF\x48\x04\xFA\x08\x6B\x53\xFC\x2C\x3A\xBD\xB9" },
      { 512, 64,
        "\xA6\xE9\xB3\xF8\xC5\x25\xF1\x2C\x04\xD8\x6C\xF2\xB3\x30\xC7\xB9\x95"
        "\x03\x0F\xDA\xC9\x45\xF7\x33\xED\x67\x86\xF3\xE2\xF0\x00\x50\x67\x25"
        "\x0F\x52\x14\x86\x1A\xFB\x92\xDE\x1C\xAE\x2F\xB1\xA6\x93\x15\x49\x29"
        "\xFA\x9B\xD8\xE9\x8D\xD4\x9C\xBD\xC0\x58\xC5\x25\x92" }
    }

  },

  { 0, 0, 0, { {0,0,""}, {0,0,""}, {0,0,""}, {0,0,""}, {0,0,""}, {0,0,""}}}
};





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
