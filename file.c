/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997, 1998
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
    "@(#) $Header: file.c,v 1.22 98/02/09 16:35:17 leres Exp $ (LBL)";
#endif

/*
 * file - arpwatch file i/o routines
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
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
#include "ec.h"
#include "file.h"

int
file_loop(register FILE *f, file_process fn)
{
	register int n;
	register char *cp, *cp2, *h;
	u_int32_t a;
	register u_char *e;
	register time_t t;
	register struct hostent *hp;
	char line[1024];

	n = 0;
	while (fgets(line, sizeof(line), f)) {
		++n;
		cp = line;
		cp2 = cp + strlen(cp) - 1;
		if (cp2 >= cp && *cp2 == '\n')
			*cp2++ = '\0';
		if (*cp == '#')
			continue;
		if ((cp2 = strchr(cp, '\t')) == NULL) {
			syslog(LOG_ERR,
			    "file_loop(): syntax error #1 line %d", n);
			continue;
		}

		/* Ethernet address comes first */
		*cp2++ = '\0';
		if ((e = str2e(cp)) == NULL) {
			syslog(LOG_ERR,
			    "file_loop(): bad ether addr \"%s\" at line %d",
			    cp, n);
			continue;
		}

		/* ip address is next */
		cp = cp2;
		if ((cp2 = strchr(cp, '\t')) != NULL)
			*cp2++ = '\0';
		if (!isdigit(*cp) || (int32_t)(a = inet_addr(cp)) == -1) {
			if ((hp = gethostbyname(cp)) == NULL) {
				syslog(LOG_ERR,
			    "file_loop(): bad hostname \"%s\" at line %d",
				    cp, n);
				continue;
			}
			BCOPY(hp->h_addr, &a, 4);
		}

		/* timestamp and hostname are optional */
		if (cp2 == NULL) {
			t = 0;
			h = NULL;
		} else {
			t = atoi(cp2);
			h = strchr(cp2, '\t');
			if (h != NULL) {
				++h;
				++cp2;
				while (*cp2 != '\n' && *cp2 != '\t' &&
				    *cp2 != '\0')
					++cp2;
				*cp2 = '\0';
			}
		}

		if (!(*fn)(a, e, t, h))
			return(0);
	}

	return(1);
}
