/* pktwriter.h - OpenPGP packet writing functions.
   Copyright (C) 2015 g10 Code GmbH

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

#ifndef PKTWRITER_H
#define PKTWRITER_H

#include "tgpgdefs.h"

/* Write the 8 bit unsigned value V as an OpenPGP value to *P, and
   advance *P accordingly.  */
static inline void
write_u8 (unsigned char **p, unsigned char v)
{
  *(*p)++ = v;
}

/* Write the 16 bit unsigned value V as an OpenPGP value to *P, and
   advance *P accordingly.  */
static inline void
write_u16 (unsigned char **p, uint16_t v)
{
  *(*p)++ = (v >>  8) & 0xff;
  *(*p)++ = (v >>  0) & 0xff;
}

/* Write the 32 bit unsigned value V as an OpenPGP value to *P, and
   advance *P accordingly.  */
static inline void
write_u32 (unsigned char **p, uint32_t v)
{
  *(*p)++ = (v >> 24) & 0xff;
  *(*p)++ = (v >> 16) & 0xff;
  *(*p)++ = (v >>  8) & 0xff;
  *(*p)++ = (v >>  0) & 0xff;
}

/* Write the MPI value V as an OpenPGP value to *P, and advance *P
   accordingly.  */
static inline void
write_mpi (unsigned char **p, tgpg_mpi_t mpi)
{
  write_u16 (p, mpi->nbits);
  memcpy (*p, mpi->value, mpi->valuelen);
  *p += mpi->valuelen;
}

/* Write an OpenPGP public key encrypted packet to *P, and advance *P
   accordingly.  Return the size of the packet.  If P is NULL, no data
   is actually written.  */
size_t
_tgpg_write_pubkey_enc_packet (unsigned char **p,
			       keyinfo_t ki,
			       tgpg_mpi_t encdat, size_t enclen);

/* Write an OpenPGP symmetrically encrypted packet to *P, and advance
   *P accordingly.  If MDC is non-zero, write an integrity protected
   packet of the given version.  As the body is merely appended to
   this header, this function is not concerned with the body itself.
   Return the size of the packet.  If P is NULL, no data is actually
   written.  */
size_t
_tgpg_write_sym_enc_packet (unsigned char **p, int mdc, size_t length);

/* Construct a plaintext message in MSG, with the given FORMAT,
   FILENAME (which must not be larger than 0xff bytes), DATE, and
   containing the literal data PAYLOAD of given LENGTH.  If MDC is
   non-zero, create a Modification Detection Code Packet of the given
   version.  In that case, PREFIX of length PREFIXLEN must be the
   block cipher initialization data.  */
int
_tgpg_encode_plaintext_message (bufdesc_t msg,
                                int mdc,
                                const char *prefix,
                                size_t prefixlen,
				unsigned char format,
				const char *filename,
				time_t date,
				const char *payload,
				size_t length);
#endif /*PKTWRITER_H*/
