/* s2k.c - String to key functions
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
#include "cryptglue.h"
#include "s2k.h"



/* Transform the string PASSPHRASE into a suitable key of length
   KEYLEN and stores it at the caller provided buffer KEY.  Required
   arguments are an OpenPGP hash ALGO, a valid MODE and depending on
   that mode a SALT of 8 random bytes and a COUNT.  See RFC-2440 for
   details.  Returns 0 on success.  */
int
_tgpg_s2k_hash (const char *passphrase, int algo,
                int mode, const unsigned char *salt, unsigned long count,
                unsigned char *key, size_t keylen)
{
  int rc;
  hash_t md;
  int pass, i;
  int used = 0;
  int pwlen = strlen (passphrase);

  if ( !passphrase 
       || !algo
       || (mode != 0 && mode != 1 && mode != 3)
       || ((mode == 1 || mode == 3) && !salt)
       || !key || !keylen ) 
    return TGPG_INV_VAL;
  
  rc = _tgpg_hash_open (&md, algo, HASH_FLAG_SECURE);
  if (rc)
    return rc;

  for (pass=0; used < keylen; pass++)
    {
      if (pass)
        {
          _tgpg_hash_reset (md);
          for (i=0; i < pass; i++)
             hash_putc (md, 0);
	}

      if (mode == 1 || mode == 3)
        {
          int len2 = pwlen + 8;
          unsigned long nbytes = len2;

          if (mode == 3)
            {
              nbytes = (16ul + (count & 15)) << ((count >> 4) + 6);
              if (nbytes < len2)
                nbytes = len2;
            }

          while (nbytes > len2)
            {
              hash_putbuf (md, salt, 8);
              hash_putbuf (md, passphrase, pwlen);
              nbytes -= len2;
            }
          if (nbytes < 8)
            hash_putbuf (md, salt, nbytes);
          else 
            {
              hash_putbuf (md, salt, 8);
              nbytes -= 8;
              hash_putbuf (md, passphrase, nbytes);
            }
        }
      else
        hash_putbuf (md, passphrase, pwlen);
      
      i = hash_digestlen (md);
      if (i > keylen - used)
        i = keylen - used;
      memcpy  (key+used, _tgpg_hash_read (md), i);
      used += i;
    }
  _tgpg_hash_close (md);
  return 0;
}

