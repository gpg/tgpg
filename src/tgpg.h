/* tgpg.h - Public interface to Tiny GPG
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

#ifndef TGPG_H
#define TGPG_H


/*
    Opaque data types used by TGPG.
*/


/* Error codes.  */
enum tgpg_error_codes
  {
    /* FIXME: Assign fixed values once we are ready. */
    TGPG_SYSERROR = -1,  /* The error is further described by ERRNO. */
    TGPG_NO_ERROR = 0,   /* No error.  Needs to have a value of 0.  */
    TGPG_NO_DATA,        /* No data for processing available. */
    TGPG_INV_VAL,        /* Invalid value.  */
    TGPG_INV_PKT,        /* Invalid OpenPGP packet detected. */
    TGPG_INV_MSG,        /* Invalid OpenPGP message.  */
    TGPG_INV_MPI,        /* An MPI value in a packet is malformed.  */
    TGPG_INV_DATA,       /* Invalid data.  */
    TGPG_INV_ALGO,       /* Algorithm is invalid or not supported.  */
    TGPG_INV_PASS,       /* Invalid passphrase.  */
    TGPG_UNEXP_PKT,      /* Unexpected packet.  */
    TGPG_UNEXP_DATA,     /* Unexpected data.  */
    TGPG_NO_PUBKEY,      /* No public key found.  */
    TGPG_NO_SECKEY,      /* No secret key found.  */
    TGPG_CRYPT_ERR,      /* Error from the crypto layer.  */
    TGPG_WRONG_KEY,      /* Wrong key; can't decrypt using this key.  */

    TGPG_NOT_IMPL,       /* Not implemented.  */
    TGPG_BUG             /* Internal error.  */
  };


/* Type of a message.  */
typedef enum
  {
    TGPG_MSG_UNKNOWN = 0,     /* Unknown type of the message (e.g. not
                                 OpenPGP). */
    TGPG_MSG_INVALID = 1,     /* The message is not valid, though it
                                 looks like an OpenPGP one.  */
    TGPG_MSG_ENCRYPTED = 2,   /* The message is encrypted.  */
    TGPG_MSG_SIGNED = 3,      /* The message is signed.  */
    TGPG_MSG_CLEARSIGNED = 4, /* The message is clearsigned.  */
    TGPG_MSG_KEYDATA = 5,     /* The message contains key data.  */
    TGPG_MSG_PLAINTEXT = 6,   /* The message contains plain text data.  */
  }
tgpg_msg_type_t;


/* The context is the main anchor for all operations.  It is used by
   almost all functions to keep a state. */
struct tgpg_context_s;
typedef struct tgpg_context_s *tgpg_t;

/* The structure used to identify an memory object passed to or from
   tgpg.  */
struct tgpg_data_s;
typedef struct tgpg_data_s *tgpg_data_t;




/*
   Prototypes
*/

/*-- tgpg.c --*/

/* Create a new context as an environment for all operations.  Returns
   0 on success and stores the new context at R_CTX. */
int tgpg_new (tgpg_t *r_ctx);

/* Release all resources associated with the given context.  Passing
   NULL is allowed to do nothing.  */
void tgpg_release (tgpg_t ctx);


/* Create a new and empty data buffer.  */
int tgpg_data_new (tgpg_data_t *r_data);

/* Create a new data buffer filled with LENGTH bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  In this
   case the caller needs to make sure that he does not release or
   modify the memory at BUFFER as long as the returned handle is
   valid.  */
int tgpg_data_new_from_mem (tgpg_data_t *r_data,
                            const char *buffer, size_t length, int copy);

/* Release all the memory associated with the DATA object.  Passing
   NULL as an no-op is allowed.  If the caller has allocated the
   object using a shallow copy (i.e. tgpg_data_new_from_mem with the
   copy flag cleared), he has full control over the provided memory
   after this function has returned.  */
void tgpg_data_release (tgpg_data_t data);

/* Return a pointer to the actual data, and its length.  Note that the
   data is not copied, and the pointer will turn stale if the DATA
   object is modified or destroyed.  */
void
tgpg_data_get (tgpg_data_t data, const char **ptr, size_t *length);

/* Given a data object holding an OpenPGP message, identify the type
   of the message.  On success R_TYPE will receive on the TGPG_MSG
   values. R_TYPE may be passed as NULL to just run a basic check. */
int tgpg_identify (tgpg_data_t data, tgpg_msg_type_t *r_type);


/*-- strerror.c --*/

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  This function may not be thread-safe.  */
const char *tgpg_strerror (int err);


/*-- decrypt.c --*/

int tgpg_decrypt (tgpg_t ctx, tgpg_data_t cipher, tgpg_data_t *plain);





#endif /*TGPG_H*/
