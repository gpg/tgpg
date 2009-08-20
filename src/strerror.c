/* strerror.c - Error strings
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
#include <errno.h>

#include "tgpgdefs.h"

/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  This function may not be thread-safe.  */
const char *
tgpg_strerror (int err)
{
  switch (err)
    {
    case TGPG_SYSERROR:  return strerror (errno);
    case TGPG_NO_ERROR:  return "No error";
    case TGPG_NO_DATA:   return "No data for processing available";
    case TGPG_INV_VAL:   return "Invalid value";
    case TGPG_INV_PKT:   return "Invalid OpenPGP packet detected";
    case TGPG_INV_MSG:   return "Invalid OpenPGP message";
    case TGPG_INV_MPI:   return "An MPI value in a packet is malformed";
    case TGPG_INV_DATA:  return "Invalid data";
    case TGPG_INV_ALGO:  return "Algorithm is invalid or not supported";
    case TGPG_INV_PASS:  return "Invalid passphrase";
    case TGPG_UNEXP_PKT: return "Unexpected packet";
    case TGPG_UNEXP_DATA:return "Unexpected data";
    case TGPG_NO_PUBKEY: return "No public key found";
    case TGPG_NO_SECKEY: return "No secret key found";
    case TGPG_CRYPT_ERR: return "Crypto error";
    case TGPG_WRONG_KEY: return "Wrong key";
    case TGPG_NOT_IMPL:  return "Not implemented by TGPG";
    case TGPG_BUG:       return "Internal error in TGPG";
    default:             return "Unknown TGPG error code";
    }
}

