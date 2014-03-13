/*
 * Copyright (c) 1996, 1997, 1999, 2000, 2004
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */
#ifndef lint
static const char rcsid[] =
    "@(#) $Id: util.c,v 1.10 2004/01/22 22:25:27 leres Exp $ (LBL)";
#endif

/*
 * util - arpwatch utility routines
 */

#include <sys/types.h>
#include <sys/file.h>

#include <fcntl.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "db.h"
#include "ec.h"
#include "file.h"
#include "util.h"

char *arpdir = ARPDIR;
char *arpfile = ARPFILE;
char *ethercodes = ETHERCODES;

/* Broadcast ethernet addresses */
u_char zero[6] = { 0, 0, 0, 0, 0, 0 };
u_char allones[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

int debug = 0;
int initializing = 1;			/* true if initializing */

/* syslog() helper routine */
void
dosyslog(register int p, register char *s, register u_int32_t a,
    register u_char *ea, register u_char *ha)
{
	char xbuf[64];

	/* No report until we're initialized */
	if (initializing)
		return;

	/* Display both ethernet addresses if they don't match */
	(void)strcpy(xbuf, e2str(ea));
	if (ha != NULL && MEMCMP(ea, ha, 6) != 0) {
		(void)strcat(xbuf, " (");
		(void)strcat(xbuf, e2str(ha));
		(void)strcat(xbuf, ")");
	}

	if (debug)
		fprintf(stderr, "%s: %s %s %s\n", prog, s, intoa(a), xbuf);
	else
		syslog(p, "%s %s %s", s, intoa(a), xbuf);
}

static FILE *dumpf;

void
dumpone(register u_int32_t a, register u_char *e, register time_t t,
    register char *h)
{
	(void)fprintf(dumpf, "%s\t%s", e2str(e), intoa(a));
	if (t != 0 || h != NULL)
		(void)fprintf(dumpf, "\t%u", (u_int32_t)t);
	if (h != NULL && *h != '\0')
		(void)fprintf(dumpf, "\t%s", h);
	(void)putc('\n', dumpf);
}

int
dump(void)
{
	register int fd;
	char oldarpfile[256], newarpfile[256];

	(void)sprintf(oldarpfile, "%s-", arpfile);
	(void)sprintf(newarpfile, "%s.new", arpfile);

	if ((fd = creat(newarpfile, 0644)) < 0) {
		syslog(LOG_ERR, "creat(%s): %m", newarpfile);
		return(0);
	}
	if ((dumpf = fdopen(fd, "w")) == NULL) {
		syslog(LOG_ERR, "fdopen(%s): %m", newarpfile);
		return(0);
	}

	(void)ent_loop(dumpone);
	if (ferror(dumpf)) {
		syslog(LOG_ERR, "ferror %s: %m", newarpfile);
		return(0);
	}

	(void)fclose(dumpf);
	if (rename(arpfile, oldarpfile) < 0) {
		syslog(LOG_ERR, "rename %s -> %s: %m", arpfile, oldarpfile);
		return(0);
	}
	if (rename(newarpfile, arpfile) < 0) {
		syslog(LOG_ERR, "rename %s -> %s: %m", newarpfile, arpfile);
		return(0);
	}
	return(1);
}

/* Initialize the databases */
int
readdata(void)
{
	register FILE *f;

	if ((f = fopen(arpfile, "r")) == NULL) {
		syslog(LOG_ERR, "fopen(%s): %m", arpfile);
		return(0);
	}
	if (!file_loop(f, ent_add, arpfile)) {
		(void)fclose(f);
		return(0);
	}
	(void)fclose(f);

	/* It's not fatal if we can't open the ethercodes file */
	if ((f = fopen(ethercodes, "r")) != NULL) {
		(void)ec_loop(f, ec_add, ethercodes);
		(void)fclose(f);
	}

	return(1);
}

char *
savestr(register const char *str)
{
	register int i;
	register char *cp;
	static char *strptr = NULL;
	static int strsize = 0;

	i = strlen(str) + 1;
	if (i > strsize) {
		strsize = 512;
		strptr = malloc(strsize);
		if (strptr == NULL) {
			syslog(LOG_ERR, "savestr(): malloc: %m");
			exit(1);
		}
		memset(strptr, 0, strsize);
	}
	(void)strcpy(strptr, str);
	cp = strptr;
	strptr += i;
	strsize -= i;
	return (cp);
}
