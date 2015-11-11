/* encrypt.c - Encrypt operation
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
#include <time.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "cryptglue.h"
#include "keystore.h"
#include "pkcs1.h"
#include "pktwriter.h"

/* Assume that PLAIN is a data object holding a complete plaintext
   message.  Encrypt the message using KEY and store the result into
   CIPHER.  CTX is the usual context.  Returns 0 on success.  */
int
tgpg_encrypt (tgpg_t ctx, tgpg_data_t plain,
	      tgpg_key_t key, tgpg_data_t cipher)
{
  int rc;
  int i;
  size_t length;
  unsigned char *p;

  /* Asymmetric cipher parameters.  */
  struct keyinfo_s keyinfo =
    {
      { key->keyid_low, key->keyid_high },
      key->algo
    };
  tgpg_mpi_t encdat = NULL;
  size_t enclen;

  /* Block cipher parameters.  */
  int algo = CIPHER_ALGO_AES256;
  char *seskey;
  size_t seskeylen = _tgpg_cipher_keylen (algo);
  size_t blocksize = _tgpg_cipher_blocklen (algo);
  const char iv[16] = { 0 };

  /* The literal data packet.  */
  tgpg_data_t plainpacket = NULL;

  /* A buffer holding the PKCS1 encoded session key.  */
  char *buffer = NULL;
  unsigned short csum;
  size_t padding = 10;
  size_t bufferlen =
    padding
    + 1 /* algorithm */
    + seskeylen
    + 2 /* checksum */;

  /* Firstly, build the literal data packet.  */
  rc = tgpg_data_new (&plainpacket);
  if (rc)
    return rc;

  rc = _tgpg_encode_plaintext_message (plainpacket,
				       'b',
				       "",
				       0,
				       plain->image,
				       plain->length);
  if (rc)
    goto leave;

  /* Allocate a buffer for the session key and PKCS1 encoding.  */
  buffer = p = xtrymalloc (bufferlen);
  if (buffer == NULL)
    {
      rc = TGPG_SYSERROR;
      goto leave;
    }

  /* Prepend encoding.  */
  rc = _tgpg_eme_pkcs1_encode (p, padding);
  if (rc)
    goto leave;
  p += padding;

  /* The cipher.  */
  write_u8 (&p, algo);

  /* The session key.  */
  seskey = (char *) p;
  p += seskeylen;

  /* Generate session key.  */
  _tgpg_randomize ((unsigned char *) seskey, seskeylen);

  /* The checksum.  */
  _tgpg_checksum (seskey, seskeylen, &csum);
  write_u16 (&p, csum);

  assert ((char *) p - buffer == bufferlen);

  /* Encrypt the session key.  */
  rc = _tgpg_pk_encrypt (key->algo, key->mpis,
			 buffer, bufferlen,
			 &encdat, &enclen);
  if (rc)
    goto leave;

  /* Compute the length of the cipher message, and resize the buffer
     accordingly.  */
  length =
    /* The pubkey packet,  */
    + _tgpg_write_pubkey_enc_packet (NULL, &keyinfo, encdat, enclen)
    /* and the encrypted data packet.  */
    + _tgpg_write_sym_enc_packet (NULL, blocksize + 2 + plainpacket->length);

  rc = tgpg_data_resize (cipher, length);
  if (rc)
    goto leave;

  p = cipher->buffer;
#define WRITTEN	(p - (unsigned char *) cipher->buffer)

  /* The Public-Key Encrypted Session Key Packet.  */
  _tgpg_write_pubkey_enc_packet (&p, &keyinfo, encdat, enclen);
  for (i = 0; i < enclen; i++)
    {
      wipememory (encdat[i].value, encdat[i].valuelen);
      xfree (encdat[i].value);
    }
  xfree (encdat);
  encdat = NULL;

  /* The Symmetrically Encrypted Data Packet.  */
  _tgpg_write_sym_enc_packet (&p, blocksize + 2 + plainpacket->length);

  /* Encrypt body.  */
  rc = _tgpg_cipher_encrypt (algo, CIPHER_MODE_CFB_PGP,
                             seskey, seskeylen,
                             iv, blocksize,
                             p,
                             cipher->length - WRITTEN,
                             plainpacket->buffer, plainpacket->length);
  if (rc)
    goto leave;

  p += plainpacket->length + blocksize + 2;
  assert (WRITTEN == length);
#undef WRITTEN

 leave:
  if (buffer != NULL)
    {
      /* This buffer contains the seskey.  */
      wipememory (buffer, bufferlen);
      xfree (buffer);
    }

  tgpg_data_release (plainpacket);
  assert (encdat == NULL);
  return rc;
}
