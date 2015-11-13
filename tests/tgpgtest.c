/* tgpgtest.c - Test driver for TGPG.
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

#include <tgpg.h>  /* Obviously we only include the public header. */

#define PGM "tgpgtest"
#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT "nobody@example.net"
#endif /*PACKAGE_BUGREPORT*/

/* The keystore is linked in.  */
extern struct tgpg_key_s keystore[];

static int opt_encrypt;
static int verbose;
static int debug;



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


static int
do_decrypt (tgpg_t ctx, tgpg_data_t inpdata, tgpg_data_t outdata)
{
  int rc;
  tgpg_msg_type_t msgtype;

  rc = tgpg_identify (inpdata, &msgtype);
  if (rc)
    {
      fprintf (stderr, PGM": can't identify file: %s\n",
               tgpg_strerror (rc));
      goto leave;
    }

  if (msgtype == TGPG_MSG_ENCRYPTED)
    rc = tgpg_decrypt (ctx, inpdata, outdata);
  else
    rc = TGPG_MSG_INVALID;

 leave:
  return rc;
}

static int
do_encrypt (tgpg_t ctx, tgpg_data_t inpdata, tgpg_data_t outdata)
{
  int rc;

  rc = tgpg_encrypt (ctx, inpdata, &keystore[0], outdata);
  if (rc)
    goto leave;

 leave:
  return rc;
}


static int
process_file (const char *fname)
{
  char *inpfile;
  size_t inplen;
  int rc;
  tgpg_data_t inpdata = NULL;
  tgpg_data_t outdata = NULL;
  tgpg_t ctx = NULL;
  const char *data;
  size_t length;

  inpfile = read_file (fname, &inplen);
  if (!inpfile)
    return TGPG_SYSERROR;

  if (verbose)
    fprintf (stderr, PGM": file `%s' of size %lu read\n",
             fname, (unsigned long)inplen);

  rc = tgpg_data_new_from_mem (&inpdata, inpfile, inplen, 0);
  if (rc)
    {
      fprintf (stderr, PGM": can't create data object for `%s': %s\n",
               fname, tgpg_strerror (rc));
      goto leave;
    }

  rc = tgpg_data_new (&outdata);
  if (rc)
    goto leave;

  rc = tgpg_new (&ctx);
  if (rc)
    {
      fprintf (stderr, PGM": can't create context object: %s\n",
               tgpg_strerror (rc));
      goto leave;
    }

  rc = (opt_encrypt ? do_encrypt : do_decrypt) (ctx, inpdata, outdata);
  if (rc)
    {
      fprintf (stderr, PGM": %scryption failed: %s\n",
               opt_encrypt ? "en" : "de", tgpg_strerror (rc));
      goto leave;
    }

  tgpg_data_get (outdata, &data, &length);
  write (fileno (stdout), data, length);

 leave:
  tgpg_release (ctx);
  tgpg_data_release (outdata);
  tgpg_data_release (inpdata);
  free (inpfile);
  return rc;
}




int
main (int argc, char **argv)
{
  int err;
  int last_argc = -1;
  int flags = 0;

  if (argc)
    {
      argc--; argv++;
    }

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
                "Usage: " PGM " [OPTION] [FILE]\n"
                "Simple tool to test TGPG.\n\n"
                "  --encrypt   encrypt rather than decrypt (the default)\n"
                "  --verbose   enable extra informational output\n"
                "  --debug     enable additional debug output\n"
                "  --help      display this help and exit\n\n"
                "With no FILE, or when FILE is -, read standard input.\n\n"
                "Report bugs to <" PACKAGE_BUGREPORT ">.");
          exit (0);
        }
      else if (!strcmp (*argv, "--encrypt"))
        {
          opt_encrypt = 1;
          argc--; argv++;
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

  if (argc > 1)
    {
      fprintf (stderr, "usage: " PGM
               " [OPTION] [FILE] (try --help for more information)\n");
      exit (1);
    }

  err = tgpg_init (keystore, flags);
  if (err)
    exit (1);

  if (argc)
    err = process_file (*argv);
  else
    err = process_file ("-");

  return err ? EXIT_FAILURE : EXIT_SUCCESS;
}
