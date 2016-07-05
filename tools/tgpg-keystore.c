/* tgpg-keystore.c - Utility to produce the static keystore for TGPG.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gcrypt.h>

#define PGM "tgpg-keystore"
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))

static const char *name = "keystore";
static int verbose;
static int debug;
static FILE *stream;

/* Read the file with name FNAME into a buffer and return a pointer to
   the buffer as well as the length of the file.  A file name of "-"
   indiocates reading from stdin.  Returns NULL on error after
   printing a diagnostic. */
static char *
read_file (const char *fname, size_t *r_length)
{
  FILE *fp;
  char *buf, *newbuf;
  size_t buflen;

  if (!strcmp (fname, "-"))
    {
      size_t nread, bufsize = 0;

      fp = stdin;
#ifdef HAVE_DOSISH_SYSTEM
      setmode ( fileno (fp), O_BINARY );
#endif
      buf = NULL;
      buflen = 0;
#define NCHUNK 8192
      do
        {
          bufsize += NCHUNK;
          if (!buf)
            newbuf = malloc (bufsize);
          else
            newbuf = realloc (buf, bufsize);
          if (!newbuf)
            {
              fprintf (stderr, PGM": malloc or realloc failed: %s\n",
                       strerror (errno));
              free (buf);
              return NULL;
            }
          buf = newbuf;

          nread = fread (buf+buflen, 1, NCHUNK, fp);
          if (nread < NCHUNK && ferror (fp))
            {
              fprintf (stderr, PGM ": error reading `[stdin]': %s\n",
                       strerror (errno));
              free (buf);
              return NULL;
            }
          buflen += nread;
        }
      while (nread == NCHUNK);
#undef NCHUNK

    }
  else
    {
      struct stat st;

      fp = fopen (fname, "rb");
      if (!fp)
        {
          fprintf (stderr, PGM": can't open `%s': %s\n",
                   fname, strerror (errno));
          return NULL;
        }

      if (fstat (fileno(fp), &st))
        {
          fprintf (stderr, PGM": can't stat `%s': %s\n",
                   fname, strerror (errno));
          fclose (fp);
          return NULL;
        }

      buflen = st.st_size;
      buf = malloc (buflen+1);
      if (!buf)
        {
          fprintf (stderr, PGM": malloc failed (file too large?): %s\n",
                   strerror (errno));
          fclose (fp);
          return NULL;
        }
      if (fread (buf, buflen, 1, fp) != 1)
        {
          fprintf (stderr, PGM ": error reading `%s': %s\n",
                   fname, strerror (errno));
          fclose (fp);
          free (buf);
          return NULL;
        }
      fclose (fp);
    }

  *r_length = buflen;
  return buf;
}

struct keyid {
  unsigned long high, low;
};

int
parse_keyid (const char *s, struct keyid *id)
{
  char buf[9];
  char *endptr;

  if (strlen (s) != 16)
    goto errout;

  strncpy (buf, s, 8);
  buf[8] = 0;
  id->high = strtoul (buf, &endptr, 16);
  if (*endptr != 0)
    goto errout;

  strncpy (buf, s+8, 8);
  buf[8] = 0;
  id->low = strtoul (buf, &endptr, 16);
  if (*endptr != 0)
    goto errout;

  return 0;

 errout:
  fprintf (stderr, "Invalid key id '%s'", s);
  return 1;
}



static void
process_file (const struct keyid *keyid, const char *fname, FILE *stream)
{
  char *inpfile;
  size_t inplen;
  gcry_sexp_t sexp = NULL;
  gcry_error_t err;
  unsigned int keysize;
  const char *keys = "nedpqu";
  const int shifts[] = {0, 0, 0, 1, 1, 1};
  gcry_mpi_t mpis[7] = {};
  int i;

  inpfile = read_file (fname, &inplen);
  if (!inpfile)
    goto leave;
  if (verbose)
    fprintf (stderr, PGM": file `%s' of size %lu read\n",
             fname, (unsigned long)inplen);

  err = gcry_sexp_new (&sexp, inpfile, inplen, 1);
  if (err)
    goto leave;

  err = gcry_sexp_extract_param (sexp, "private-key", keys,
				 &mpis[0],
				 &mpis[1],
				 &mpis[2],
				 &mpis[3],
				 &mpis[4],
				 &mpis[5],
                                 NULL);
  if (err)
    goto leave;

  keysize = gcry_pk_get_nbits (sexp);

  fprintf (stream,
           "  {\n"
           "    1 /* PK_ALGO_RSA */, 0x%08lx, 0x%08lx,\n"
           "    {\n",
           keyid->high, keyid->low);

  for (i = 0; i < 6; i++)
    {
      unsigned char *buf, *data;
      int size_delta;
      size_t len;

      err = gcry_mpi_aprint (GCRYMPI_FMT_HEX, &buf, &len, mpis[i]);
      if (err)
	goto leave;

      data = buf;
      len -= 1;	/* trailing zero */
      assert (len % 2 == 0);

      if (keys[i] != 'e')
        {
          /* Normalize data.  */
          size_delta = (keysize >> (3 + shifts[i])) - (len / 2);

          /* Skip leading zeroes.  */
          while (size_delta < 0
                 && strncmp ((const char *) data, "00", 2) == 0)
            data += 2, len -= 2;

          /* Fill up with leading zeroes.  */
          if (size_delta > 0)
            {
              size_t new_len = keysize >> (3 + shifts[i] - 1 /* hex */);
              char *p, *new = malloc (new_len);
              if (! new)
                goto leave;

              fprintf (stderr, "%d %d\n", size_delta, 0);
              for (p = new; p - new < size_delta * 2 /* hex */; p++)
                *p = '0';

              memcpy (p, data, len);
              free (buf);

              buf = data = new, len = new_len;
            }
          size_delta = (keysize >> (3 + shifts[i])) - (len / 2);
          assert (size_delta == 0);
        }

#define INDENT	"        "
      fprintf (stream,
               "      { /* %c: */ %u /* bits */, %u /* bytes */,\n"
               INDENT "\"",
               keys[i], len << 2, len / 2);

      const unsigned char *c;
      for (c = data; c - data < len; c += 2)
        {
          ptrdiff_t d = c - data;
          if (d > 0 && d % 16 == 0)
            fprintf (stream, "\"\n" INDENT "\"");

          fprintf (stream, "\\x%.2s", c);
        }
#undef INDENT

      fprintf (stream, "\" },\n");

      free (buf);
    }

  fprintf (stream,
           "    },\n"
           "  },\n");

 leave:
  free (inpfile);
  gcry_sexp_release (sexp);
  for (i = 0; i < DIM (mpis); i++)
    gcry_mpi_release (mpis[i]);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;

  if (argc)
    {
      argc--; argv++;
    }

  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr, PGM ": libgcrypt version mismatch\n");
      exit (1);
    }
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          puts (
                "Usage: " PGM " [OPTION] KEYID PRIVATE-KEY-FILE [KEYID PKF...]\n"
                "Simple tool to generate static keystores for TGPG.\n\n"
                "  --name NAME specify name of the symbol [default: keystore]\n"
                "  --verbose   enable extra informational output\n"
                "  --debug     enable additional debug output\n"
                "  --help      display this help and exit\n\n"
                "Report bugs to <" PACKAGE_BUGREPORT ">.");
          exit (0);
        }
      else if (!strcmp (*argv, "--name"))
        {
          if (! argc)
            {
              fprintf (stderr, "expected a name\n");
              exit (1);
            }
          name = argv[1];
          argc -= 2, argv += 2;
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
    }

  if (argc < 2 || argc % 2 == 1)
    {
      fprintf (stderr, "usage: " PGM
               " [OPTION] KEYID PRIVATE-KEY-FILE [KEYID PKF...]\n"
               "       (try --help for more information)\n");
      exit (1);
    }

  stream = stdout;

  fprintf (stream,
           "#include <stdio.h>\n"
           "#include <tgpg.h>\n"
           "\n"
           "struct tgpg_key_s %s[] = {\n",
           name);

  for (; argc; argc -= 2, argv += 2)
    {
      struct keyid id;
      if (parse_keyid (argv[0], &id))
        return EXIT_FAILURE;

      process_file (&id, argv[1], stream);
    }
  fprintf (stream,
           "  { /* sentinel */ 0 },\n"
           "};\n");

  return EXIT_SUCCESS;
}
