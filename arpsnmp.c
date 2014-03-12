/*
 * Copyright (c) 1996, 1997, 1999, 2004
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

/*
 * arpsnmp - keep track of ethernet/ip address pairings, report changes
 */

#include <sys/param.h>
#include <sys/types.h>		/* concession to AIX */
#include <sys/file.h>

#include <ctype.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "db.h"
#include "ec.h"
#include "file.h"
#include "machdep.h"
#include "util.h"

/* Forwards */
int main(int, char **);
int readsnmp(char *);
int snmp_add(u_int32_t, u_char *, time_t, char *);
__dead void usage(void) __attribute__ ((volatile));

char *prog;

extern int optind;
extern int opterr;
extern char *optarg;

int main(int argc, char **argv)
{
	char *cp;
	int op, i;
	char errbuf[256];

	if((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	if(abort_on_misalignment(errbuf) < 0) {
		fprintf(stderr, "%s: %s\n", prog, errbuf);
		exit(1);
	}

	opterr = 0;
	while((op = getopt(argc, argv, "df:")) != EOF)
		switch (op) {

		case 'd':
			++debug;
#ifndef DEBUG
			fprintf(stderr, "%s: Warning: Not compiled with -DDEBUG\n", prog);
#endif
			break;

		case 'f':
			arpfile = optarg;
			break;

		default:
			usage();
		}

	if(optind == argc)
		usage();

	openlog(prog, 0, LOG_DAEMON);

	/* Read in database */
	initializing = 1;
	/* XXX todo: file locking */
	if(!readdata())
		exit(1);
	sorteinfo();
#ifdef DEBUG
	if(debug > 2) {
		debugdump();
		exit(0);
	}
#endif
	initializing = 0;

	/* Suck files in then exit */
	for(i = optind; i < argc; ++i)
		readsnmp(argv[i]);
	if(!dump())
		exit(1);
	exit(0);
}

static time_t now;

int snmp_add(u_int32_t a, u_char * e, time_t t, char *h)
{
	/* Watch for ethernet broadcast */
	if(MEMCMP(e, zero, 6) == 0 || MEMCMP(e, allones, 6) == 0) {
		dosyslog(LOG_INFO, "ethernet broadcast", a, e, NULL);
		return (1);
	}

	/* Watch for some ip broadcast addresses */
	if(a == 0 || a == 1) {
		dosyslog(LOG_INFO, "ip broadcast", a, e, NULL);
		return (1);
	}

	/* Use current time (although it would be nice to subtract idle time) */
	return (ent_add(a, e, now, h));
}

/* Process an snmp file */
int readsnmp(char *file)
{
	FILE *f;

	if(debug > 2)
		fprintf(stderr, "%s: reading %s\n", prog, file);
	if((f = fopen(file, "r")) == NULL) {
		syslog(LOG_ERR, "fopen(%s): %m", file);
		return (0);
	}
	now = time(NULL);
	if(!file_loop(f, snmp_add, file)) {
		fclose(f);
		return (0);
	}
	fclose(f);
	return (1);
}

__dead void usage(void)
{
	extern char version[];

	fprintf(stderr, "Version %s\n", version);
	fprintf(stderr, "usage: %s [-d] [-f datafile] file [...]\n", prog);
	exit(1);
}
