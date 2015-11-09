/* pktparser.h - Internal interface to the packet parser
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

#ifndef PKTPARSER_H
#define PKTPARSER_H

int _tgpg_identify_message (bufdesc_t msg, tgpg_msg_type_t *r_type);

int _tgpg_parse_encrypted_message (bufdesc_t msg, int *r_mdc,
                                   size_t *r_start, size_t *r_length,
                                   keyinfo_t r_keyinfo, tgpg_mpi_t r_encdat);

int _tgpg_parse_plaintext_message (bufdesc_t msg,
				   unsigned char *r_format,
				   char *r_filename,
				   time_t *r_date,
				   size_t *r_start,
				   size_t *r_length);
#endif /*PKTPARSER_H*/
