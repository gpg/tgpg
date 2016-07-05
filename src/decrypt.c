/* decrypt.c - Decrypt operation
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
#include <time.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "pktparser.h"
#include "keystore.h"
#include "cryptglue.h"
#include "pkcs1.h"


static int
decrypt_session_key (keyinfo_t keyinfo, tgpg_mpi_t encdat,
                     int *r_algo, char **r_seskey, size_t *r_seskeylen)
{
  int rc;
  tgpg_mpi_t seckey;
  char *plain;
  size_t plainlen;

  *r_seskey = NULL;
  *r_seskeylen = 0;
  *r_algo = 0;

  rc = _tgpg_get_secret_key (keyinfo, &seckey);
  if (rc)
    {
      fprintf (stderr, "DBG: error getting secret key: %s\n",
               tgpg_strerror (rc));
      return rc;
    }

  rc = _tgpg_pk_decrypt (keyinfo->pubkey_algo, seckey, encdat,
                         &plain, &plainlen);
  _tgpg_free_secret_key (seckey);
  if (rc)
    fprintf (stderr, "DBG: decrypting session key failed: %s\n",
             tgpg_strerror (rc));
  else
    {
      const char *body;
      size_t bodylen;
      rc = _tgpg_eme_pkcs1_decode (plain, plainlen, &body, &bodylen);
      if (! rc)
        {
          /* body -> <algobyte> <keybytes> <2bytes checksum> */
          int algo;
          size_t seskeylen;
          const char *seskey;
          unsigned short csum, csum2;

          algo = ((unsigned char*)body)[0];
          seskey = body + 1;
          seskeylen = bodylen - 1 - 2;
          csum = ((((unsigned char *)body)[bodylen-2] << 8)
                  | ((unsigned char *)body)[bodylen-1]);
          _tgpg_checksum (seskey, seskeylen, &csum2);
          if (csum != csum2)
            rc = TGPG_WRONG_KEY;
          else if (!(*r_seskey = xtrymalloc (seskeylen)))
            rc = TGPG_SYSERROR;
          else
            {
              memcpy (*r_seskey, seskey, seskeylen);
              *r_seskeylen = seskeylen;
              *r_algo = algo;
            }
        }
    }

  if (plain)
    {
      wipememory (plain, plainlen);
      xfree (plain);
    }

  return rc;
}

/* Assume that CIPHER is a data object holding a complete encrypted
   message.  Decrypt the message and store the result into PLAIN.
   CTX is the usual context.  Returns 0 on success.  */
int
tgpg_decrypt (tgpg_t ctx, tgpg_data_t cipher, tgpg_data_t plain)
{
  int rc;
  size_t startoff;
  size_t length;

  /* Asymmetric cipher parameters.  */
  keyinfo_t keyinfo;
  tgpg_mpi_t encdat;

  /* Block cipher parameters.  */
  int mdc = 0;
  int algo;
  char *seskey = NULL;
  size_t seskeylen;
  size_t blocksize = 8;
  const char iv[16] = { 0 };
  char prefix[18];

  /* The decrypted literal data packet.  */
  char *buffer = NULL;
  size_t bufferlen;
  tgpg_data_t plainpacket = NULL;
  tgpg_msg_type_t msgtype;

  /* Plaintext data.  */
  unsigned char format;
  char filename[0xff + 1];
  time_t date;
  size_t start;

  keyinfo = xtrycalloc (1, sizeof *keyinfo);
  if (!keyinfo)
    return TGPG_SYSERROR;
  encdat = xtrycalloc (MAX_PK_NENC, sizeof *encdat);
  if (!encdat)
    {
      xfree (keyinfo);
      return TGPG_SYSERROR;
    }

  rc = _tgpg_parse_encrypted_message (cipher, &mdc,
                                      &startoff, &length,
                                      keyinfo, encdat);
  if (rc)
    goto leave;

  if (! mdc)
    {
      int mandatory = _tgpg_flags & TGPG_FLAG_MANDATORY_MDC;
      fprintf (stderr, "tgpg: %s: message was not integrity protected\n",
               mandatory ? "ERROR" : "WARNING");
      if (mandatory)
        {
          rc = TGPG_MDC_FAILED;
          goto leave;
        }
    }

  rc = decrypt_session_key (keyinfo, encdat, &algo, &seskey, &seskeylen);
  if (rc)
    goto leave;

  blocksize = _tgpg_cipher_blocklen (algo);

  /* Allocate buffer for the plaintext.  */
  bufferlen = length - blocksize - 2;
  buffer = xtrymalloc (bufferlen);
  if (buffer == NULL)
    {
      rc = TGPG_SYSERROR;
      goto leave;
    }

  /* Decrypt body.  */
  rc = _tgpg_cipher_decrypt (algo,
                             ! mdc ? CIPHER_MODE_CFB_PGP : CIPHER_MODE_CFB_MDC,
                             seskey, seskeylen,
                             iv, blocksize,
                             prefix, sizeof prefix,
                             buffer, bufferlen,
                             &cipher->image[startoff], length);
  if (rc)
    goto leave;

  /* Put it in a container so that we can parse it.  */
  rc = tgpg_data_new_from_mem (&plainpacket, buffer, bufferlen, 1);
  if (rc)
    goto leave;

  rc = tgpg_identify (plainpacket, &msgtype);
  if (rc)
    goto leave;

  if (msgtype != TGPG_MSG_PLAINTEXT)
    {
      rc = TGPG_INV_MSG;
      goto leave;
    }

  /* Finally, parse the decrypted data...  */
  rc = _tgpg_parse_plaintext_message (plainpacket,
                                      mdc,
                                      prefix, sizeof prefix,
                                      &format,
                                      filename,
                                      &date,
                                      &start,
                                      &length);
  if (rc)
    goto leave;
  fprintf (stderr, "DBG: format %c, filename %s, length %zd, date %s",
           format, filename, length, ctime (&date));

  /* ... and present the content to the user.  */
  rc = tgpg_data_resize (plain, length);
  if (rc)
    goto leave;

  memcpy (plain->buffer, &plainpacket->buffer[start], length);

 leave:
  if (seskey)
    {
      wipememory (seskey, seskeylen);
      xfree (seskey);
    }
  tgpg_data_release (plainpacket);
  xfree (buffer);
  xfree (encdat);
  xfree (keyinfo);
  return rc;
}


