/* pkcs1.c - PKCS#1 EME-PKCS1-v1_5 encoding and decoding.
   Copyright (C) 2015 g10 Code GmbH

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
#include <errno.h>
#include <locale.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "cryptglue.h"
#include "pktwriter.h"

/* Encode a message as specified in OpenPGPs version of the PKCS#1
   functions EME-PKCS1-v1_5 described in RFC4880.  As data is merely
   appended in this encoding, this function is not concerned with the
   body itself.  The to-be-prepended data is written to EM which must
   be at least 10 bytes long.  */
int
_tgpg_eme_pkcs1_encode (char *em, size_t emlen)
{
  size_t i, padding;

  if (emlen < 10)
    return TGPG_BUG; /* EM is too short.  */

  padding = emlen - 2;
  /* Note: The leading zero octet is lost in MPI encoding.  */
  *em++ = 2;

  /* Generate a padding of non-zero octets.  */
  _tgpg_randomize ((unsigned char *) em, padding);
  for (i = 0; i < padding; i++)
    while (em[i] == 0)
      _tgpg_randomize ((unsigned char *) &em[i], 1);

  em[padding] = 0;

  return 0;
}

/* Decode the message EM of length EMLEN as specified in OpenPGPs
   version of the PKCS#1 functions EME-PKCS1-v1_5 described in
   RFC4880.  A pointer to the embedded body of the message is returned
   in R_M, the length of the body is returned in R_MLEN.  */
int
_tgpg_eme_pkcs1_decode (const char *em, size_t emlen,
			const char **r_m, size_t *r_mlen)
{
  size_t n;

  /* Note: The leading zero octet is lost in MPI encoding.  */
  if (emlen < 10 || em[0] != 2)
    return TGPG_WRONG_KEY; /* Too short or not a type 2 block.  */

  /* Skip random part.  */
  for (n = 2; 1 < emlen && em[n]; n++)
    { /* skip */ }
  if (n < 9)
    return TGPG_WRONG_KEY; /* Not enough random bytes. */

  n++; /* Skip the terminating 0.  */

  *r_m = &em[n];
  *r_mlen = emlen - n;
  return 0;
}
