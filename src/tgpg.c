/* tgpg.c - Tiny GPG
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
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tgpg.h"
#include "tgpgdefs.h"
#include "pktparser.h"
#include "keystore.h"

/* Initialization.  */
int
tgpg_init (const tgpg_key_t keytable)
{
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (! gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr, "libtgpg: libgcrypt version mismatch\n");
      return TGPG_BUG;
    }
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  seckey_table = keytable;
  return TGPG_NO_ERROR;
}

/* Create a new context as an environment for all operations.  Returns
   0 on success and stores the new context at R_CTX. */
int
tgpg_new (tgpg_t *r_ctx)
{
  tgpg_t ctx;

  ctx = xtrycalloc (1, sizeof *ctx);
  if (!ctx)
    return TGPG_SYSERROR;

  *r_ctx = ctx;
  return 0;
}


/* Release all resources associated with the given context.  Passing
   NULL is allowed as a no operation.  */
void
tgpg_release (tgpg_t ctx)
{
  if (!ctx)
    return;
  xfree (ctx);
}


/* Make sure that BUF can be modified.  This is done by taking a copy
   of the image.  The function may return with an error to indicate an
   out of core condition.  */
int
_tgpg_make_buffer_mutable (bufdesc_t buf)
{
  size_t len;

  if (buf->buffer)
    return 0;
  assert (buf->image);

  /* Make sure to allocate at least 1 one for the sake of broken
     malloc implementations.  */
  len = buf->length;
  if (!len)
    len = 1;
  buf->buffer = xtrymalloc (len);
  if (!buf->buffer)
    return TGPG_SYSERROR;
  buf->allocated = len;
  memcpy (buf->buffer, buf->image, buf->length);
  buf->image = buf->buffer;

  return 0;
}


/* Create a new and empty data buffer.  */
int
tgpg_data_new (tgpg_data_t *r_data)
{
  bufdesc_t bufdesc;

  bufdesc = xtrycalloc (1, sizeof *bufdesc);
  if (!bufdesc)
    return TGPG_SYSERROR;

  bufdesc->length = 0;
  bufdesc->image = "";

  *r_data = bufdesc;
  return 0;
}




/* Create a new data buffer filled with LENGTH bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  In this
   case the caller needs to make sure that he does not release or
   modify the memory at BUFFER as long as the returned handle is
   valid.  */
int
tgpg_data_new_from_mem (tgpg_data_t *r_data,
                        const char *buffer, size_t length, int copy)
{
  int rc;
  bufdesc_t bufdesc;

  if (!length || !buffer)
    return TGPG_INV_VAL;

  bufdesc = xtrycalloc (1, sizeof *bufdesc);
  if (!bufdesc)
    return TGPG_SYSERROR;

  bufdesc->length = length;
  bufdesc->image = buffer;

  if (copy)
    {
      rc = _tgpg_make_buffer_mutable (bufdesc);
      if (rc)
        {
          xfree (bufdesc);
          return rc;
        }
    }

  *r_data = bufdesc;
  return 0;
}


/* Make sure the given buffer is writable and at least SIZE long.  */
int
tgpg_data_resize (tgpg_data_t data, size_t size)
{
  void *buf;

  buf = xtryrealloc (data->buffer, size);
  if (buf == NULL)
    return TGPG_SYSERROR;

  data->buffer = buf;
  if (data->image != data->buffer)
    {
      memcpy (data->buffer, data->image, data->length);
      data->image = data->buffer;
    }

  data->length = size;
  return TGPG_NO_ERROR;
}


/* Release all the memory associated with the DATA object.  Passing
   NULL as an no-op is allowed.  If the caller has allocated the
   object using a shallow copy (i.e. tgpg_data_new_from_mem with the
   copy flag cleared), he has full control over the provided memory
   after this function has returned.  */
void
tgpg_data_release (tgpg_data_t data)
{
  if (!data)
    return;
  xfree (data->buffer);
  xfree (data);
}

/* Return a pointer to the actual data, and its length.  Note that the
   data is not copied, and the pointer will turn stale if the DATA
   object is modified or destroyed.  */
void
tgpg_data_get (tgpg_data_t data, const char **ptr, size_t *length)
{
  if (!data)
    {
      *ptr = NULL;
      *length = 0;
    }
  else
    {
      *ptr = data->image;
      *length = data->length;
    }
}


/* Given a data object holding an OpenPGP message, identify the type
   of the message.  On success R_TYPE will receive on the TGPG_MSG
   values. R_TYPE may be passed as NULL to just run a basic check. */
int
tgpg_identify (tgpg_data_t data, tgpg_msg_type_t *r_type)
{
  int rc;
  tgpg_msg_type_t typ;

  if (!data)
    return TGPG_INV_VAL;
  rc = _tgpg_identify_message (data, &typ);
  switch (rc)
    {
    case TGPG_NO_DATA:
      typ = TGPG_MSG_UNKNOWN;
      rc = 0;
      break;
    case TGPG_UNEXP_PKT:
      typ = TGPG_MSG_INVALID;
      rc = 0;
      break;
    default:
      break;
    }
  if (r_type)
    *r_type = typ;
  return rc;
}

