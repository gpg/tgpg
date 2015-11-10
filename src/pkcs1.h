/* pkcs1.h - PKCS#1 EME-PKCS1-v1_5 encoding and decoding.
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

#ifndef PKCS1_H
#define PKCS1_H

/* Encode a message as specified in OpenPGPs version of the PKCS#1
   functions EME-PKCS1-v1_5 described in RFC4880.  As data is merely
   appended in this encoding, this function is not concerned with the
   body itself.  The to-be-prepended data is written to EM which must
   be at least 11 bytes long.  */
int
_tgpg_eme_pkcs1_encode (char *em, size_t emlen);

/* Decode the message EM of length EMLEN as specified in OpenPGPs
   version of the PKCS#1 functions EME-PKCS1-v1_5 described in
   RFC4880.  A pointer to the embedded body of the message is returned
   in R_M, the length of the body is returned in R_MLEN.  */
int
_tgpg_eme_pkcs1_decode (const char *em, size_t emlen,
			const char **r_m, size_t *r_mlen);

#endif /*PKCS1_H*/
