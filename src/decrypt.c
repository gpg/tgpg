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
#include <assert.h>

#include "tgpgdefs.h"
#include "pktparser.h"
#include "keystore.h"
#include "cryptglue.h"


static int
decrypt_session_key (keyinfo_t keyinfo, mpidesc_t encdat,
                     int *r_algo, char **r_seskey, size_t *r_seskeylen)
{
  int rc;
  mpidesc_t seckey;
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
   message.  Decrypt thet message and store the result into PLAIN.
   CTX is the usual context.  Returns 0 on success.  */
int
tgpg_decrypt (tgpg_t ctx, tgpg_data_t cipher, tgpg_data_t plain)
{
  int rc;
  size_t startoff;
  keyinfo_t keyinfo;
  mpidesc_t encdat;
  int algo;
  char *seskey;
  size_t seskeylen;

  keyinfo = xtrycalloc (1, sizeof *keyinfo);
  if (!keyinfo)
    return TGPG_SYSERROR;
  encdat = xtrycalloc (MAX_PK_NENC, sizeof *encdat);
  if (!encdat)
    {
      xfree (keyinfo);
      return TGPG_SYSERROR;
    }

  rc = _tgpg_parse_encrypted_message (cipher, &startoff, keyinfo, encdat);
  if (rc)
    goto leave;

  rc = decrypt_session_key (keyinfo, encdat, &algo, &seskey, &seskeylen);
  if (!rc)
    {
      size_t n;
      int i;
      
      fprintf (stderr, "DBG: algo: %d session key: ", algo);
      for (i=0; i < seskeylen; i++)
        fprintf (stderr, "%02X", ((unsigned char*)seskey)[i]);
      putc ('\n', stderr);
      fprintf (stderr, "DBG: pky_encrypted at off %lu rest of data:\n",
               (unsigned long)startoff);
      
      for (n=startoff, i=0; n < cipher->length; n++)
        {
          fprintf (stderr, "%02X", ((unsigned char*)cipher->image)[n]);
          if (!(++i%32))
            putc ('\n', stderr);
        }
      if ((i%32))
        putc ('\n', stderr);
    }

  
 leave:
  xfree (encdat);
  xfree (keyinfo);
  return rc;
}


