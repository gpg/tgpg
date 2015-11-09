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


static int
decrypt_session_key (keyinfo_t keyinfo, tgpg_mpi_t encdat,
                     int *r_algo, char **r_seskey, size_t *r_seskeylen)
{
  int rc;
  tgpg_mpi_t seckey;
  char *plain;
  size_t plainlen, n;

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
      {
        int i;

        fprintf (stderr, "DBG: session key frame: ");
        for (i=0; i < plainlen; i++)
          fprintf (stderr, "%02X", ((unsigned char*)plain)[i]);
        putc ('\n', stderr);
      }

      if (plainlen < 7 || plain[0] != 2)
        rc = TGPG_WRONG_KEY; /* Too short or not a type 2 block.  */
      else
        {
          /* Skip random part.  */
          for (n=1; n < plainlen && plain[n]; n++)
            ;
          n++; /* Skip the terminating 0.  */
          /* PLAIN+N -> <algobyte> <keybytes> <2byteschecksum> */
          if (n + 4 > plainlen || n < 10 )
            rc = TGPG_WRONG_KEY; /* Too short or not enough random bytes. */
          else
            {
              int algo;
              size_t seskeylen;
              char *seskey;
              unsigned short csum, csum2;

              algo = ((unsigned char*)plain)[n++];
              seskey = plain + n;
              seskeylen = plainlen - n - 2;
              csum = ((((unsigned char *)plain)[plainlen-2] << 8)
                      | ((unsigned char *)plain)[plainlen-1]);
              for (csum2=0, n=0; n < seskeylen; n++ )
                csum2 = ((csum2 + ((unsigned char *)seskey)[n]) & 0xffff);
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
tgpg_decrypt (tgpg_t ctx, tgpg_data_t cipher, tgpg_data_t *plain)
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
  char *seskey;
  size_t seskeylen;
  size_t blocksize = 8;
  const char iv[16] = { 0 };

  /* The decrypted literal data packet.  */
  char *buffer = NULL, *buf;
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

  rc = decrypt_session_key (keyinfo, encdat, &algo, &seskey, &seskeylen);
  if (rc)
    goto leave;

  blocksize = _tgpg_cipher_blocklen (algo);

  /* Allocate buffer for the plaintext.  */
  buffer = buf = xtrymalloc (length);
  if (buffer == NULL)
    {
      rc = TGPG_SYSERROR;
      goto leave;
    }

  /* Session key quick check.  */
  rc = _tgpg_cipher_decrypt (algo, CIPHER_MODE_CFB,
                             seskey, seskeylen,
                             iv, blocksize,
                             buf, length,
                             &cipher->image[startoff], blocksize+2);
  if (rc)
    goto leave;

  /* The last two octets are repeated.  */
  if (buf[blocksize-2] != buf[blocksize]
      || buf[blocksize-1] != buf[blocksize+1])
    {
      rc = TGPG_INV_MSG;
      goto leave;
    }

  /* Re-synchronize with previous ciphertext.  */
  startoff += 2, length -= 2;

  /* Decrypt body.  */
  rc = _tgpg_cipher_decrypt (algo, CIPHER_MODE_CFB,
                             seskey, seskeylen,
                             iv, blocksize,
                             buf, length,
                             &cipher->image[startoff], length);
  if (rc)
    goto leave;

  /* Skip random data.  */
  buf += blocksize, length -= blocksize;

  /* Put it in a container so that we can parse it.  */
  rc = tgpg_data_new_from_mem (&plainpacket, buf, length, 1);
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
  rc = tgpg_data_new_from_mem (plain,
                               &plainpacket->buffer[start],
                               length,
                               1);

 leave:
  tgpg_data_release (plainpacket);
  xfree (buffer);
  xfree (encdat);
  xfree (keyinfo);
  return rc;
}


