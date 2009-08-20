/* pktparser.c - OpenPGP packet parsing functions.
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
#include <errno.h>
#include <locale.h>
#include <assert.h>

#include "tgpgdefs.h"
#include "cryptglue.h"
#include "keystore.h"
#include "pktparser.h"

/* Convert the 1 byte unsigned value a BUFFER and return the value.  */
#define get_u8(buffer)  (*(const unsigned char*)(buffer))

/* Convert the 32 bit OpenPGP value at BUFFER and return the value.  */
static unsigned long
get_u32 (const char *buffer)
{
  const unsigned char *s = (const unsigned char*)buffer;
  unsigned long val;

  val  = (*s++) << 24;
  val |= (*s++) << 16;
  val |= (*s++) << 8;
  val |= (*s++);

  return val;
}

/* Convert the 16 bit OpenPGP value at BUFFER and return the value.  */
static unsigned int
get_u16 (const char *buffer)
{
  const unsigned char *s = (const unsigned char*)buffer;
  unsigned int val;

  val  = (*s++) << 8;
  val |= (*s++);

  return val;
}

/* Convert the MPI stored at *BUFFER into a our internal format and
   set BUFFER and BUFLEN to point right behind the end of the MPI.  In
   case of an error (e.g. buffer shorter than indicated by the MPI's
   length byte) the pointer are not updated and an error is
   returned.  */
int
get_mpi (char const **buffer, size_t *buflen, mpidesc_t mpi)
{
  const char *buf = *buffer;
  size_t len = *buflen;
  unsigned int nbits, nbytes;

  if (len < 2)
    return TGPG_INV_MPI;
  nbits = get_u16 (buf);
  buf += 2; len -= 2;
  nbytes = (nbits+7)/8;
  if (len < nbytes)
    return TGPG_INV_MPI;
  mpi->nbits = nbits;
  mpi->valuelen = nbytes;
  mpi->value = buf;
  buf += nbytes;
  len -= nbytes;
  *buffer = buf;
  *buflen = len;
  return 0;
}


/* The core packet header parser.  An OpenPGP packet is assumed at the
   address pointed to by BUFPTR which is of a maximum length as stored
   at BUFLEN.  Return the header information of that packet and
   advance the pointer stored at BUFPTR to the next packet; also
   adjust the length stored at BUFLEN to match the remaining bytes. If
   there are no more packets, store NULL at BUFPTR.  Return an error
   code on failure.  Only on success the following addresses are
   updated:

   R_DATA    = Stores a pointer to the begin of the packet content.
   R_DATALEN = Length of the packet content.  This value has already been
               checked to fit into the buffer as desibed by BUFLEN.
   R_PKTTYPE = Received type of the packet.
   R_NTOTAL  = Received the total number of bytes in this packet including 
               the header.
*/
static int
next_packet (char const **bufptr, size_t *buflen,
             char const **r_data, size_t *r_datalen, int *r_pkttype,
             size_t *r_ntotal)
{
  const char *buf, *bufstart;
  size_t len;
  int c, ctb, pkttype;
  unsigned long pktlen;

  bufstart = buf = *bufptr;
  len = *buflen;
  if (!len)
    return TGPG_NO_DATA;
  
  ctb = get_u8 (buf++); len--;
  if ( !(ctb & 0x80) )
    return TGPG_INV_PKT;  /* The CTB is not valid.  */
  
  pktlen = 0;
  if ((ctb & 0x40))  /* New style CTB.  */
    {
      pkttype = (ctb & 0x3f);
      if (!len)
        return TGPG_INV_PKT; /* First length byte missing. */
      c = get_u8 (buf++); len--;
      if ( c < 192 )
        pktlen = c;
      else if ( c < 224 )
        { 
          pktlen = (c - 192) * 256;
          if (!len)
            return TGPG_INV_PKT; /* Second length byte missing.  */
          c = get_u8 (buf++); len--;
          pktlen += c + 192;
        }
      else if (c == 255)
        {
          if (len < 4 )
            return TGPG_INV_PKT; /* Length bytes missing. */
          pktlen = get_u32 (buf);
          buf += 4; len -= 4;
        }
      else /* Partial length encoding.  */
        {
          switch (pkttype)
            {
            case PKT_COMPRESSED:
            case PKT_ENCRYPTED:
            case PKT_PLAINTEXT:
            case PKT_ENCRYPTED_MDC:
              break;
            default:
              return TGPG_INV_PKT; /* Partial length encoding not allowed.  */
            }

          /* FIXME:  We need to support it.  */
          return TGPG_NOT_IMPL;
        }
    }
  else /* Old style CTB.  */
    {
      int lenbytes;

      pktlen = 0;
      pkttype = (ctb>>2)&0xf;
      lenbytes = ((ctb&3)==3)? 0 : (1<<(ctb & 3));
      if (!lenbytes) /* No length bytes as used by old comressed packets.  */
        {
          /* FIXME: we need to implemnted it. */
          return TGPG_NOT_IMPL;
        }
      if (len < lenbytes)
        return TGPG_INV_PKT; /* Not enough length bytes.  */
      for (; lenbytes; lenbytes--)
        {
          pktlen <<= 8;
          pktlen |= get_u8 (buf++); len--;
	}
    }

  /* Some basic sanity checks.  */
  if ( pkttype < 1 || pkttype > 110
       || pktlen == 0xffffffff
       || pktlen > len )
    return TGPG_INV_PKT;

  /* Return information. */
  *r_data = buf;
  *r_datalen = pktlen;
  *r_pkttype = pkttype;
  *r_ntotal = (buf - bufstart) + pktlen;

  *bufptr = buf + pktlen;
  *buflen = len - pktlen;

  if (!*buflen)
    *bufptr = NULL;  /* No more packets. */

  return 0;
}


/* Parse a message to identify its type.  Returns 0 on success,
   meaning that this message can be further processed (decrypted or
   verfied) by tgpg.  On success the type of the message is stored at
   r_type. */
int
_tgpg_identify_message (bufdesc_t msg, tgpg_msg_type_t *r_type)
{
  int rc;
  const char *image, *data;
  size_t imagelen, datalen, n;
  int pkttype;
  int any_packets;

  image = msg->image;
  imagelen = msg->length;

  any_packets = 0;
  while (image)
    {
      rc = next_packet (&image, &imagelen, &data, &datalen, &pkttype, &n);
      if (rc)
        return rc;

      if (!any_packets && pkttype == PKT_MARKER)
        continue; /* We ignore leading marker packets.  */
      any_packets = 1;

      switch (pkttype)
        {
        case PKT_ENCRYPTED:
          /* We do not support old style symmetric encrypted messages.  */
          return TGPG_NOT_IMPL;  

        case PKT_SYMKEY_ENC:
          /* We do not yet support symmetrical encryption, thus we
             need to skip these packets to and hope for public key
             encrypted packets.  */
          break;

        case PKT_PUBKEY_ENC:
          /* This looks like an encrypted message.  */
          *r_type = TGPG_MSG_ENCRYPTED;
          return 0;

        case PKT_ONEPASS_SIG:
        case PKT_SIGNATURE:
          /* This is a signed message.  */
          *r_type = TGPG_MSG_SIGNED;
          return 0;

        case PKT_PLAINTEXT:
        case PKT_COMPRESSED:
          /* We do not support simple compressed or plaintext OpenPGP
             messages. */
          return TGPG_NOT_IMPL;


        case PKT_PUBLIC_KEY:
        case PKT_SECRET_KEY:
          /* This seems to be a keyring.  */
          *r_type = TGPG_MSG_KEYDATA;
          return 0;

        default:
          /* We don't expect any other packets. */
          return TGPG_UNEXP_PKT;
        }
    }

  return TGPG_NO_DATA;
}




/* Parse a public key encrypted packet.  KI will receive the
   information about the key and the array ENCDAT the actual values
   with the encrypted key.  The caller needs to allocate ENCDAT with
   at least MAX_PK_NENC.  On error the values returned are not
   defined.  */
static int
parse_pubkey_enc_packet (const char *data, size_t datalen,
                         keyinfo_t ki, mpidesc_t encdat)
{
  int rc, nenc, idx;

  if (datalen < 10)
    return TGPG_INV_PKT;

  if (*data != 2 && *data != 3)
    return TGPG_INV_PKT;  /* We require packet version 2 or 3.  */
  ki->keyid[1] = get_u32 (data+1);         
  ki->keyid[0] = get_u32 (data+5);         
  ki->pubkey_algo = get_u8 (data+9);
  data += 10; datalen -= 10;
  nenc = _tgpg_pk_get_nenc (ki->pubkey_algo);
  assert (nenc <= MAX_PK_NENC); 
  if (!nenc)
    return TGPG_INV_ALGO;
  for (idx=0; idx < nenc; idx++)
    {
      rc = get_mpi (&data, &datalen, encdat + idx);
      if (rc)
        return rc;
    }
  if (datalen)
    return TGPG_INV_PKT;  /* Trailing garbage.  */
  return 0;
}


/* Given an encrypted message, parse it and return the key information
   required to actually decrypt it.  To achive this the function will
   callback to the keystorage to see whether an encrypted key exists.
   On success the key information is returned as well as a pointer to
   the begin of the encrypted message data.  It may modify the
   original message to remove partial length encoding and compact it
   to one large packet.  On success the function returns an offset
   to the begin of the actual encrypted data packet at R_START and the
   information required to decrypt the message at R_KEYINFO and
   R_ENCDAT.  The caller must provide these structures and allocate
   space for at least MAX_PK_ENC items for R_ENCDAT.  The return
   values are not defined on error.  */
int
_tgpg_parse_encrypted_message (bufdesc_t msg, size_t *r_start,
                               keyinfo_t r_keyinfo, mpidesc_t r_encdat )
{
  int rc;
  const char *image, *data;
  size_t imagelen, datalen, n;
  int pkttype;
  int any_packets = 0;
  int any_enc_seen = 0;
  int got_key = 0;

  image = msg->image;
  imagelen = msg->length;

  while (image)
    {
      rc = next_packet (&image, &imagelen, &data, &datalen, &pkttype, &n);
      if (rc)
        return rc;

      if (!any_packets && pkttype == PKT_MARKER)
        continue; /* We ignore leading marker packets.  */
      any_packets = 1;

      switch (pkttype)
        {
        case PKT_SYMKEY_ENC:
          /* We do not yet support symmetrical encryption, thus we
             need to skip these packets to and hope for public key
             encrypted packets.  */
          any_enc_seen = 1;;
          break;

        case PKT_PUBKEY_ENC:
          /* This looks like an encrypted message.  */
          any_enc_seen = 1;
          if (!got_key)
            {
              rc = parse_pubkey_enc_packet (data, datalen,
                                            r_keyinfo, r_encdat);
              if (rc)
                return rc;
              if (!_tgpg_have_secret_key (r_keyinfo))
                got_key = 1;
            }
          break;

        case PKT_ENCRYPTED:
        case PKT_ENCRYPTED_MDC:
          /* We are right at the start of the encrypted stuff.  Make
             sure that it is only one packet and remove any partial
             headers. */
          if (!any_enc_seen)
            return TGPG_NOT_IMPL; /* Old style symmetric message. */
          if (!got_key)
            return TGPG_NO_SECKEY;
          /* TODO: compresss partial headers and return it. */
          
          return 0;

        default:
          /* We don't expect any other packets. */
          return TGPG_UNEXP_PKT;
        }
    }

  return any_enc_seen? TGPG_INV_MSG : TGPG_NO_DATA;
}
