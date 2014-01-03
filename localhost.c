/* A slightly more convenient wrapper for gethostname

   Copyright (C) 1996 Free Software Foundation, Inc.

   Written by Miles Bader <miles@gnu.ai.mit.edu>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "localhost.h"
/* Return the name of the localhost.  This is just a wrapper for gethostname,
   which takes care of allocating a big enough buffer, and caches the result
   after the first call (so the result should be copied before modification).
   If something goes wrong, 0 is returned, and errno set.  */
char *
localhost (void)
{
	static char *buf = 0;
	static size_t buf_len = 0;
	int myerror = 0;

	if (! buf) {
		do {
			errno = 0;
			if (buf) {
				buf_len += buf_len;
				buf = realloc (buf, buf_len);
			} else {
				buf_len = 128;        /* Initial guess */
				buf = malloc (buf_len);
			}
			if (! buf) {
				errno = ENOMEM;
				return 0;
			}
		} while ( (
			 	(myerror = gethostname(buf, buf_len)) == 0
					&& !memchr (buf, '\0', buf_len))
				|| errno == ENAMETOOLONG
			);

		if (myerror) {
			/* gethostname failed, abort.  */
			free (buf);
			buf = "(unknown host)";
		}
	}
	return buf;
}
