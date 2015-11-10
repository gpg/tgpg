/* util.c - Utility functions
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

#include "tgpgdefs.h"


/* Return the length of the canonical encoded S-expression in BUFFER
   of LENGTH.  LENGTH may be 0 if it is assured that the S-expression
   is valid. Returns 0 on error.  */
size_t
_tgpg_canonsexp_len (const unsigned char *sexp, size_t length)
{
  const unsigned char *p = sexp;
  size_t count = 0;
  int level = 0;
  const unsigned char *disphint = NULL;
  unsigned int datalen = 0;

  if (!p || *p != '(')
    return 0; /* Not a canonical S-expression.  */

  for ( ; ; p++, count++ )
    {
      if (length && count >= length)
        break; /* Expression longer than buffer.  */

      if (datalen)
        {
          if (*p == ':')
            {
              if (length && (count+datalen) >= length)
                break;
              count += datalen;
              p += datalen;
              datalen = 0;
	    }
          else if (*p >= '0' && *p <= '9')
            datalen = 10 * datalen + (*p - '0');
          else
            break; /* Bad length specification.  */
	}
      else if (*p == '(')
        {
          if (disphint)
            break; /* Not closed.  */
          level++;
	}
      else if (*p == ')')
        {
          if (!level)
            break; /* No opening parenthesis.  */
          if (disphint)
            break; /* Not closed.  */
          if (!--level)
            {
              return ++count; /* End of expression - return count.  */
            }
	}
      else if (*p == '[')
        {
          if (disphint)
            break;  /* Nested display hints are not allowed.  */
          disphint = p;
	}
      else if (*p == ']')
        {
          if ( !disphint )
            break; /* Not in a display hint.  */
          disphint = NULL;
	}
      else if ( *p >= '1' && *p <= '9' )
        {
          /* Note that leading zeroes are not allowed.  */
          datalen = (*p - '0');
	}
      else
        break;  /* Unexpected characters  */
    }

  return 0; /* Error.  */
}


/* Compute the sum modulo 2**16 over DATA of LENGTH storing the result
   in R_CSUM.  */
void
_tgpg_checksum (const char *data, size_t length,
		unsigned short *r_csum)
{
  size_t n;
  unsigned short sum = 0;

  for (n = 0; n < length; n++)
    sum = (sum + ((const unsigned char *) data)[n]) & 0xffff;

  *r_csum = sum;
}
