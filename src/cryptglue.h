/* cryptglue.h - Internal interface to crypto layer.
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

#ifndef CRYPTGLUE_H
#define CRYPTGLUE_H

/* P u b k e y */

/* The maximum nuber of parameters required in a public key encrypted
   packet.  */
#define MAX_PK_NENC 2

unsigned int _tgpg_pk_get_nenc (int algo);
unsigned int _tgpg_pk_get_nsig (int algo);

int _tgpg_pk_decrypt (int algo, tgpg_mpi_t seckey, tgpg_mpi_t encdat,
                      char **r_plain, size_t *r_plainlen);

int _tgpg_pk_encrypt (int algo, tgpg_mpi_t pubkey,
                      char *plain, size_t plainlen,
                      tgpg_mpi_t *r_encdat, size_t *r_enclen);


/*  C i p h er (symmetric)  */

enum cipher_modes
  {
    CIPHER_MODE_CBC	= 1,
    CIPHER_MODE_CFB	= 2,
    CIPHER_MODE_CFB_PGP	= 3,
    CIPHER_MODE_CFB_MDC	= 4,
  };

unsigned int _tgpg_cipher_blocklen (int algo);
unsigned int _tgpg_cipher_keylen (int algo);
int _tgpg_cipher_decrypt (int algo, enum cipher_modes mode,
                          const void *key, size_t keylen,
                          const void *iv, size_t ivlen,
                          char *prefix, size_t prefixlen,
                          void *outbuf, size_t outbufsize,
                          const void * inbuf, size_t inbuflen);
int _tgpg_cipher_encrypt (int algo, enum cipher_modes mode,
                          const void *key, size_t keylen,
                          const void *iv, size_t ivlen,
                          char *prefix, size_t prefixlen,
                          void *outbuf, size_t outbufsize,
                          const void *inbuf, size_t inbuflen);


/*  H a s h  */

#define HASH_FLAG_SECURE 1

/* The context used for hash functions.  It needs to be poublic, so
   that we can do some buffer using macros.  */
struct hash_context_s
{
  void *handle;         /* Internal handle.  */
  int secure;           /* Secure mode.  */
  size_t digestlen;     /* Length of the resulting digest.  */
  size_t buffersize;    /* The allocated size of the buffer.  */
  size_t bufferpos;     /* Offset to the next write position.  */
  unsigned char buffer[1]; /* the buffer is actually of size BUFFERSIZE.  */
};
typedef struct hash_context_s *hash_t;

/* Update the hash context CTX with the byte B. */
#define hash_putc(ctx,b)  \
            do {                                        \
              hash_t c_ = (ctx);                        \
              if ( c_->bufferpos == c_->buffersize )    \
                _tgpg_hash_write ( c_, NULL, 0 );       \
              c_->buffer[c_->bufferpos++] = (b);        \
            } while (0)
/* Update the ash context CTX with L bytes from buffer B.  */
#define hash_putbuf(ctx,b,l)  \
            do {                                                   \
              hash_t c_ = (ctx);                                   \
              const unsigned char *p_ = (const unsigned char*)(b); \
              size_t l_ = (l);                                     \
              for ( ;l_; l_--, p_++)                               \
                {                                                  \
                  if ( c_->bufferpos == c_->buffersize )           \
                    _tgpg_hash_write ( c_, NULL, 0 );              \
                  c_->buffer[c_->bufferpos++] = *p_;               \
                }                                                  \
            } while (0)
/* Return the length of the resulting digest of context CTX.  */
#define hash_digestlen(ctx)  ((ctx)->digestlen)

void _tgpg_hash_buffer (int algo, unsigned char *digest, size_t digestlen,
                        const void *buffer, size_t length);
int  _tgpg_hash_open (hash_t *rctx, int algo, unsigned int flags);
void _tgpg_hash_close (hash_t ctx);
void _tgpg_hash_reset (hash_t ctx);
void _tgpg_hash_write (hash_t ctx, const void *buffer, size_t length);
const void *_tgpg_hash_read (hash_t ctx);

/* Random data. */

/* Fill BUFFER of given LENGTH with random data suitable for session
   keys.  */
void _tgpg_randomize (unsigned char *buffer, size_t length);

#endif /*CRYPTGLUE_H*/
