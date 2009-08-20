/* protect.c - Un/Protect a secret key
   Copyright (C) 2002, 2007 g10 Code GmbH

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
   MA 02110-1301, USA.  


   Note: This code has orginally been written for NewPG and then in
   turn integrated into GnuPG 1.9.  It has entirely been written by
   g10 Code staff.  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "s2k.h"
#include "cryptglue.h"
#include "protect.h"

#define PROT_CIPHER        CIPHER_ALGO_AES
#define PROT_CIPHER_STRING "aes"
#define PROT_CIPHER_KEYLEN (128/8)


/* A table containing the information needed to create a protected
   private key */
static struct 
{
  const char *algo;
  const char *parmlist;
  int prot_from, prot_to;
} protect_info[] = {
  { "rsa",  "nedpqu", 2, 5 },
  { "dsa",  "pqgyx", 4, 4 },
  { "elg",  "pgyx", 3, 3 },
  { NULL }
};


/* Return the length of the next canonical S-expression part and
   update the pointer to the first data byte.  0 is returned on
   error.  */
static size_t
snext (unsigned char const **buf)
{
  const unsigned char *s;
  int n;

  s = *buf;
  for (n=0; *s && *s != ':' && (*s >= '0' && *s <= '9'); s++)
    n = n*10 + (*s - '0');
  if (!n || *s != ':')
    return 0; /* we don't allow empty lengths */
  *buf = s+1;
  return n;
}

/* Skip over the S-expression BUF points to and update BUF to point to
   the character right behind.  DEPTH gives the initial number of open
   lists and may be passed as a positive number to skip over the
   remainder of an S-expression if the current position is somewhere
   within an S-expression.  This function returns 0 on success.  */
static int
sskip (unsigned char const **buf, int *depth)
{
  const unsigned char *s = *buf;
  size_t n;
  int d = *depth;
  
  while (d > 0)
    {
      if (*s == '(')
        {
          d++;
          s++;
        }
      else if (*s == ')')
        {
          d--;
          s++;
        }
      else
        {
          if (!d)
            return TGPG_INV_DATA;
          n = snext (&s);
          if (!n)
            return TGPG_INV_DATA;
          s += n;
        }
    }
  *buf = s;
  *depth = d;
  return 0;
}


/* Check whether the string at the address BUF points to, matches the
   string TOKEN.  Returns true on match and updates BUF to point
   behind the token string.  Return false and does not update the
   buffer if tehre is no match. */
static int
smatch (unsigned char const **buf, size_t buflen, const char *token)
{
  size_t toklen = strlen (token);

  if (buflen != toklen || memcmp (*buf, token, toklen))
    return 0;
  *buf += toklen;
  return 1;
}




/* Calculate the MIC for a private key S-Exp.  SHA1HASH should point
   to a 20 byte buffer.  */
static int 
calculate_mic (const unsigned char *plainkey, unsigned char *sha1hash)
{
  const unsigned char *hash_begin, *hash_end;
  const unsigned char *s;
  size_t n;

  s = plainkey;
  if (*s != '(')
    return TGPG_INV_DATA;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  if (!smatch (&s, n, "private-key"))
    return TGPG_UNEXP_DATA; 
  if (*s != '(')
    return TGPG_UNEXP_DATA;
  hash_begin = s;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  s += n; /* Skip the algorithm name. */

  while (*s == '(')
    {
      s++;
      n = snext (&s);
      if (!n)
        return TGPG_INV_DATA; 
      s += n;
      n = snext (&s);
      if (!n)
        return TGPG_INV_DATA; 
      s += n;
      if ( *s != ')' )
        return TGPG_INV_DATA; 
      s++;
    }
  if (*s != ')')
    return TGPG_INV_DATA; 
  s++;
  hash_end = s;

  _tgpg_hash_buffer (MD_ALGO_SHA1, sha1hash, 20,
                     hash_begin, hash_end - hash_begin);

  return 0;
}



/* Do the actual decryption and check the return list for
   consistency.  */
static int
do_decryption (const unsigned char *protected, size_t protectedlen, 
               const char *passphrase, 
               const unsigned char *s2ksalt, unsigned long s2kcount,
               const unsigned char *iv, size_t ivlen,
               unsigned char **result)
{
  int rc;
  int blklen;
  unsigned char *outbuf;
  size_t reallen;

  blklen = _tgpg_cipher_blocklen (PROT_CIPHER);
  if (protectedlen < 4 || (protectedlen%blklen))
    return TGPG_INV_DATA;  /* Corrupted protection.  */

  outbuf = xtrymalloc (protectedlen);
  if (!outbuf)
    return TGPG_SYSERROR;

  {
    unsigned char *key;
    size_t keylen;
    
    keylen = PROT_CIPHER_KEYLEN;
    key = xtrymalloc (keylen);
    if (!key)
      {
        xfree (outbuf);
        return TGPG_SYSERROR;
      }

    rc = _tgpg_s2k_hash (passphrase, MD_ALGO_SHA1, 3, s2ksalt, s2kcount,
                         key, keylen);
    if (!rc)
      rc = _tgpg_cipher_decrypt (PROT_CIPHER, CIPHER_MODE_CBC,
                                 key, keylen,
                                 iv, ivlen,
                                 outbuf, protectedlen,
                                 protected, protectedlen);
    wipememory (key, keylen);
    xfree (key);
  }
  if (rc)
    {
      xfree (outbuf);
      return rc;
    }
  
  /* Check that rge result is a valid S-expression. */
  if ( (*outbuf != '(' && outbuf[1] != '(')
       || !(reallen = _tgpg_canonsexp_len (outbuf, protectedlen)) 
       || (reallen + blklen < protectedlen) )
    {
      xfree (outbuf);
      return TGPG_INV_PASS;
    }

  *result = outbuf;
  return 0;
}


/* Merge the parameter list contained in CLEARTEXT with the original
   protect lists PROTECTEDKEY by replacing the list at REPLACEPOS.
   Return the new list in RESULT and the MIC value in the 20 byte
   buffer SHA1HASH. */
static int
merge_lists (const unsigned char *protectedkey,
             size_t replacepos, 
             const unsigned char *cleartext,
             unsigned char *sha1hash,
             unsigned char **result, size_t *resultlen)
{
  size_t n, newlistlen;
  unsigned char *newlist, *p;
  const unsigned char *s;
  const unsigned char *startpos, *endpos;
  int i;
  
  *result = NULL;
  *resultlen = 0;

  if (replacepos < 26)
    return TGPG_BUG;

  /* Estimate the required size of the resulting list.  We have a
     large safety margin of >20 bytes (MIC hash from CLEARTEXT and the
     removed "protected-".  We already now that this is a valid one,
     thus there is no need to pass the length.  */
  newlistlen = _tgpg_canonsexp_len (protectedkey, 0);
  if (!newlistlen)
    return TGPG_BUG;
  n = _tgpg_canonsexp_len (cleartext, 0);
  if (!n)
    return TGPG_BUG;
  newlistlen += n;
  newlist = xtrymalloc (newlistlen);
  if (!newlist)
    return TGPG_SYSERROR;

  /* Copy the initial segment.  (10 == strlen("protected-"))  */
  memcpy (newlist, "(11:private-key", 15);
  p = newlist + 15;
  memcpy (p, protectedkey+15+10, replacepos-15-10);
  p += replacepos-15-10;

  /* Copy the cleartext. */
  s = cleartext;
  if (*s != '(' && s[1] != '(')
    return TGPG_BUG;  /* We already checked this. */
  s += 2;
  startpos = s;
  while ( *s == '(' )
    {
      s++;
      n = snext (&s);
      if (!n)
        goto invalid_sexp;
      s += n;
      n = snext (&s);
      if (!n)
        goto invalid_sexp;
      s += n;
      if ( *s != ')' )
        goto invalid_sexp;
      s++;
    }
  if ( *s != ')' )
    goto invalid_sexp;
  endpos = s;
  s++;

  /* Now get the MIC. */
  if (*s != '(')
    goto invalid_sexp;
  s++;
  n = snext (&s);
  if (!smatch (&s, n, "hash"))
    goto invalid_sexp;
  n = snext (&s);
  if (!smatch (&s, n, "sha1"))
    goto invalid_sexp; 
  n = snext (&s);
  if (n != 20)
    goto invalid_sexp;
  memcpy (sha1hash, s, 20);
  s += n;
  if (*s != ')')
    goto invalid_sexp;

  /* Append the parameter list. */
  memcpy (p, startpos, endpos - startpos);
  p += endpos - startpos;
  
  /* Skip the protected list element from the original list. */
  s = protectedkey + replacepos;
  assert (*s == '(');
  s++;
  i = 1;
  if ( sskip (&s, &i) )
    goto invalid_sexp;
  startpos = s;
  i = 2; /* We are at this level. */
  if ( sskip (&s, &i) )
    goto invalid_sexp;
  assert (s[-1] == ')');
  endpos = s; /* Now one behind the end of the list. */

  /* Append the rest.  */
  memcpy (p, startpos, endpos - startpos);
  p += endpos - startpos;

  /* That's it. */
  *result = newlist;
  *resultlen = newlistlen;
  return 0;

 invalid_sexp:
  wipememory (newlist, newlistlen);
  xfree (newlist);
  return TGPG_INV_DATA;
}


/* Check whether SECKEY is a protected secret key and return 0 in this
   case.  */
int 
_tgpg_is_protected (const unsigned char *seckey)
{
  const unsigned char *s;
  size_t n;

  s = seckey;
  if (*s != '(')
    return TGPG_INV_DATA;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  if (!smatch (&s, n, "protected-private-key"))
    return 0; 
  return TGPG_NO_DATA;
}



/* Unprotect the key encoded in canonical format.  We assume a valid
   S-expression here. */
int 
_tgpg_unprotect (const unsigned char *protectedkey, const char *passphrase,
                 unsigned char **result, size_t *resultlen)
{
  int rc;
  const unsigned char *s;
  size_t n;
  int infidx, i;
  unsigned char sha1hash[20], sha1hash2[20];
  const unsigned char *s2ksalt;
  unsigned long s2kcount;
  const unsigned char *iv;
  const unsigned char *prot_begin;
  unsigned char *cleartext;
  unsigned char *final;
  size_t finallen;

  s = protectedkey;
  if (*s != '(')
    return TGPG_INV_DATA;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  if (!smatch (&s, n, "protected-private-key"))
    return TGPG_UNEXP_DATA; 
  if (*s != '(')
    return TGPG_UNEXP_DATA;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 

  for (infidx=0; (protect_info[infidx].algo
                  && !smatch (&s, n, protect_info[infidx].algo)); infidx++)
    ;
  if (!protect_info[infidx].algo)
    return TGPG_INV_ALGO;

  /* Now find the list with the protected information.  Here is an
     example for such a list:
     (protected openpgp-s2k3-sha1-aes-cbc 
        ((sha1 <salt> <count>) <Initialization_Vector>)
        <encrypted_data>)
   */
  for (;;)
    {
      if (*s != '(')
        return TGPG_INV_DATA;
      prot_begin = s;
      s++;
      n = snext (&s);
      if (!n)
        return TGPG_INV_DATA; 
      if (smatch (&s, n, "protected"))
        break;
      s += n;
      i = 1;
      rc = sskip (&s, &i);
      if (rc)
        return rc;
    }
  /* Found. */
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  if (!smatch (&s, n, "openpgp-s2k3-sha1-" PROT_CIPHER_STRING "-cbc"))
    return TGPG_NOT_IMPL;
  if (*s != '(' || s[1] != '(')
    return TGPG_INV_DATA;
  s += 2;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  if (!smatch (&s, n, "sha1"))
    return TGPG_NOT_IMPL;
  n = snext (&s);
  if (n != 8)
    return TGPG_INV_DATA; /* Corrupted protection.  */
  s2ksalt = s;
  s += n;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; /* Corrupted protection.  */
  /* We expect a list close as next item, so we can simply use
     strtoul() here.  We might want to check that we only have digits
     - but this is nothing we should worry about */
  if (s[n] != ')' )
    return TGPG_INV_DATA;
  s2kcount = strtoul ((const char*)s, NULL, 10);
  if (!s2kcount)
    return TGPG_INV_DATA; /* Corrupted protection.  */
  s += n;
  s++; /* Skip list end.  */

  n = snext (&s);
  if (n != 16) /* Wrong blocksize for IV (we support only aes-128). */
    return TGPG_INV_DATA; /* Corrupted protection.  */
  iv = s;
  s += n;
  if (*s != ')' )
    return TGPG_INV_DATA;
  s++;
  n = snext (&s);
  if (!n)
    return TGPG_INV_DATA; 
  
  rc = do_decryption (s, n,
                      passphrase, s2ksalt, s2kcount,
                      iv, 16,
                      &cleartext);
  if (rc)
    return rc;

  rc = merge_lists (protectedkey, prot_begin-protectedkey, cleartext,
                    sha1hash, &final, &finallen);
  wipememory (cleartext, n);
  xfree (cleartext);
  if (rc)
    return rc;

  rc = calculate_mic (final, sha1hash2);
  if (!rc && memcmp (sha1hash, sha1hash2, 20))
    rc = TGPG_INV_DATA; /* Corrupted protection.  */
  if (rc)
    {
      wipememory (final, finallen);
      xfree (final);
      return rc;
    }

  *result = final;
  *resultlen = _tgpg_canonsexp_len (final, 0);
  return 0;
}
