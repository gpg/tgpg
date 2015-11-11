/* pktwriter.c - OpenPGP packet writing functions.
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
#include "keystore.h"
#include "pktwriter.h"

/* Return the size of a new-style CTB with the given LENGTH.  */
static size_t __attribute ((const))
header_size (size_t length)
{
  if (length < 192)
    return 2;
  if (length < 8384)
    return 3;
  return 5;
}

/* Write an OpenPGP packet header with the given TAG and LENGTH to *P,
   and advance *P accordingly.  Return the size of the header.  If P
   is NULL, no data is actually written.  */
static size_t
write_header (unsigned char **p, unsigned char tag, size_t length)
{
  assert (tag < 1<<6 || ! "invalid tag");

  if (p == NULL)
    return header_size (length);

  /* Write packet tag.  */
  write_u8 (p, 0x80	/* always one */
	    | 0x40	/* new-style packet */
	    | tag);

  /* Write length.  */
  switch (header_size (length))
    {
    case 2:
      write_u8 (p, length);
      break;

    case 3:;
      size_t l = length - 192;
      write_u8 (p, ((l >> 8) & 0xff) + 192);
      write_u8 (p, ((l >> 0) & 0xff));
      break;

    case 5:
    write_u32 (p, length);
    }

  return header_size (length);
}

/* Write an OpenPGP public key encrypted packet to *P, and advance *P
   accordingly.  Return the size of the packet.  If P is NULL, no data
   is actually written.  */
size_t
_tgpg_write_pubkey_enc_packet (unsigned char **p,
			       keyinfo_t ki,
                               tgpg_mpi_t encdat, size_t enclen)
{
  int i;
  size_t length;
  unsigned char *start;

  assert (enclen || ! "invalid algorithm");
  assert (enclen <= MAX_PK_NENC);

  length = 10 /* version, keyid and algorithm */;
  for (i = 0; i < enclen; i++)
    length += 2 /* length */ + encdat[i].valuelen /* value */;

  if (p == NULL)
    return length + header_size (length);

  write_header (p, PKT_PUBKEY_ENC, length);
  start = *p;

  /* The packet version.  */
  write_u8 (p, 3);

  /* The keyid.  */
  write_u32 (p, ki->keyid[1]);
  write_u32 (p, ki->keyid[0]);

  /* The asymmetric encryption algorithm.  */
  write_u8 (p, ki->pubkey_algo);

  /* The encrypted session key.  */
  for (i = 0; i < enclen; i++)
    write_mpi (p, &encdat[i]);

  assert (*p - start == length);
  return length + header_size (length);
}

/* Write an OpenPGP symmetrically encrypted packet to *P, and advance
   *P accordingly.  As the body is merely appended to this header,
   this function is not concerned with the body itself.  Return the
   size of the packet.  If P is NULL, no data is actually written.  */
size_t
_tgpg_write_sym_enc_packet (unsigned char **p, size_t length)
{
  return write_header (p, PKT_ENCRYPTED, length) + length;
}


/* Construct a plaintext message in MSG, with the given FORMAT,
   FILENAME (which must not be larger than 0xff bytes), DATE, and
   containing the literal data PAYLOAD of given LENGTH.  */
int
_tgpg_encode_plaintext_message (bufdesc_t msg,
				unsigned char format,
				const char *filename,
				time_t date,
				const char *payload,
				size_t length)
{
  int rc;
  unsigned char *p;
  size_t header_length;

  if (strlen (filename) > 0xff)
    return TGPG_INV_VAL;

  header_length =
    + 2 /* format and filename length */
    + strlen (filename)
    + 4 /* the date */;

  rc = tgpg_data_resize (msg,
			 + header_size (header_length
                                        + length)
			 + header_length
			 + length);
  if (rc)
    return rc;

  p = (unsigned char *) msg->buffer;
  write_header (&p, PKT_PLAINTEXT, header_length + length);

  /* The format.  */
  write_u8 (&p, format);

  /* The filename, with its length prepended to it encoded as a single
     octet.  */
  write_u8 (&p, strlen (filename));
  memcpy (p, filename, strlen (filename));
  p += strlen (filename);

  /* The date.  */
  write_u32 (&p, (uint32_t) date);

  /* The literal data.  */
  memcpy (p, payload, length);

  return TGPG_NO_ERROR;
}
