/* tgpgdefs.h - Internal declarations for Tiny GPG
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

#ifndef TGPGDEFS_H
#define TGPGDEFS_H

#include <config.h>

#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if defined UINT32_MAX || defined uint32_t
typedef uint32_t keyid_t;
#else
# error "No uint32_t."
#endif

/* Include the public header. */
#include "tgpg.h"


/* The packet types we need to know about. */
enum packet_types
  {
    PKT_NONE	      = 0,
    PKT_PUBKEY_ENC    = 1,  /* Public key encrypted packet.  */
    PKT_SIGNATURE     = 2,  /* Secret key encrypted packet.  */
    PKT_SYMKEY_ENC    = 3,  /* Session key packet.  */
    PKT_ONEPASS_SIG   = 4,  /* One pass signature packet.  */
    PKT_SECRET_KEY    = 5,  /* Secret key packet.  */
    PKT_PUBLIC_KEY    = 6,  /* Public key packet.  */
    PKT_SECRET_SUBKEY = 7,  /* Secret subkey packet.  */
    PKT_COMPRESSED    = 8,  /* Compressed data packet.  */
    PKT_ENCRYPTED     = 9,  /* Conventional encrypted data packet.  */
    PKT_MARKER	      = 10, /* Marker packet. */
    PKT_PLAINTEXT     = 11, /* Plaintext data with filename and mode.  */
    PKT_RING_TRUST    = 12, /* Keyring trust packet. */
    PKT_USER_ID	      = 13, /* User id packet. */
    PKT_PUBLIC_SUBKEY = 14, /* Public subkey packet. */
    PKT_ATTRIBUTE     = 17, /* Attribute packet. */
    PKT_ENCRYPTED_MDC = 18, /* Integrity protected encrypted data packet. */
    PKT_MDC 	      = 19  /* Manipulation detection code packet. */
  };


/* Constants for OpenPGP public key algorithms.  */
enum openpgp_pk_algos
  {
    PK_ALGO_RSA = 1,
    PK_ALGO_ELG = 16,
    PK_ALGO_DSA = 17
  };

/* Constants for OpenPGP hash algorithms.  */
enum openpgp_md_algos
  {
    MD_ALGO_MD5    = 1,
    MD_ALGO_SHA1   = 2,
    MD_ALGO_RMD160 = 3,
    MD_ALGO_SHA256 = 8
  };

/* Constants for OpenPGP cipher algorithms.  */
enum openpgp_cipher_algos
  {
    CIPHER_ALGO_3DES   = 2,
    CIPHER_ALGO_CAST5  = 3,
    CIPHER_ALGO_AES    = 7,
    CIPHER_ALGO_AES192 = 8,
    CIPHER_ALGO_AES256 = 9
  };


/* A buffer descriptor is used to keep track of memory buffers. */
struct tgpg_data_s
{
  size_t length;      /* Used length of the buffer or image.  */
  const char *image;  /* The actual R/O image of the buffer.  This
                         either points to some external buffer or our
                         own BUFFER (below).  */
  size_t allocated;   /* Allocated size of the buffer.  */
  char *buffer;       /* The allocated buffer.  If a R/W buffer has
                         not been allocated this may be NULL.  */
};
typedef struct tgpg_data_s *bufdesc_t;


/* A descriptor for an MPI.  We do not store the actual value but let
   it point to a buffer, this avoids an extra copy.  */
struct mpidesc_s
{
  unsigned int nbits; /* The length of the MPI measured in bits.      */
  size_t valuelen;    /* The length of this value measured in bytes.  */
  const char *value;  /* The value of the MPI. */
};
typedef struct mpidesc_s *mpidesc_t;


/* Information pertaining to a public key.  */
struct keyinfo_s
{
  /* The key ID as defined by OpenPGP.  */
  uint32_t keyid[2];
  /* The public key algorithm used. */
  int pubkey_algo;
};
typedef struct keyinfo_s *keyinfo_t;


/* The context structure used with all TPGP operations. */
struct tgpg_context_s
{
  int foo;

};




/*-- tgpg.c --*/
int _tgpg_make_buffer_mutable (bufdesc_t buf);


/*-- util.c --*/
size_t _tgpg_canonsexp_len (const unsigned char *sexp, size_t length);




/* Memory allocation should always be done using these macros.  */
#define xtrymalloc(a)   malloc ((a))
#define xtrycalloc(a,b) calloc ((a),(b))
#define xfree(a)        do { void *a_ = (a); if (a_) free (a_); } while (0)

/* Macro to wipe out the memory without allowing the compiler to
   remove it. */
#define wipememory(_ptr,_len)                                             \
                        do {                                              \
                          volatile char *_vptr = (volatile char *)(_ptr); \
                          size_t _vlen=(_len);                            \
                          while(_vlen)                                    \
                            {                                             \
                              *_vptr = 0; _vptr++; _vlen--;               \
                            }                                             \
                        } while(0)


#endif /*TGPGDEFS_H*/
