/*
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 2000
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
    "@(#) $Id: report.c,v 1.46 2000/09/30 23:41:04 leres Exp $ (LBL)";
#endif

/*
 * report - arpwatch report generating routines
 */

#include <sys/param.h>
#include <sys/types.h>				/* concession to AIX */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "addresses.h"
#include "arpwatch.h"
#include "dns.h"
#include "ec.h"
#include "report.h"
#include "setsignal.h"
#include "util.h"

#define PLURAL(n) ((n) == 1 || (n) == -1 ? "" : "s")

static int cdepth;	/* number of outstanding children */

static char *fmtdate(time_t);
static char *fmtdelta(time_t);
RETSIGTYPE reaper(int);
static int32_t gmt2local(void);

static char *
fmtdelta(register time_t t)
{
	register char *cp;
	register int minus;
	static char buf[132];

	minus = 0;
	if (t < 0) {
		t = -t;
		++minus;
	}
	if (t < 60) {
		cp = "second";
	} else if (t < 60 * 60) {
		t /= 60;
		cp = "minute";
	} else if (t < 24 * 60 * 60) {
		t /= (60 * 60);
		cp = "hour";
	} else {
		t /= (24 * 60 * 60);
		cp = "day";
	}
	if (minus)
		t = -t;
	(void)sprintf(buf, "%u %s%s", (u_int32_t)t, cp, PLURAL(t));
	return(buf);
}

static char *dow[7] = {
	"Sunday",
	"Monday",
	"Tuesday",
	"Wednesday",
	"Thursday",
	"Friday",
	"Saturday"
};

static char *moy[12] = {
	"January",
	"February",
	"March",
	"April",
	"May",
	"June",
	"July",
	"August",
	"September",
	"October",
	"November",
	"December"
};

#define DOW(d) ((d) < 0 || (d) >= 7 ? "?" : dow[d])
#define MOY(m) ((m) < 0 || (m) >= 12 ? "?" : moy[(m)])

static char *
fmtdate(time_t t)
{
	register struct tm *tm;
	register int32_t mw;
	register char ch;
	static int init = 0;
	static char zone[32], buf[132];

	if (t == 0)
		return("<no date>");

	if (!init) {
		mw = gmt2local() / 60;
		if (mw < 0) {
			ch = '-';
			mw = -mw;
		} else {
			ch = '+';
		}
		(void)sprintf(zone, "%c%02d%02d", ch, mw / 60, mw % 60);
	}

	tm = localtime(&t);
	(void)sprintf(buf, "%s, %s %d, %d %d:%02d:%02d %s",
	    DOW(tm->tm_wday),
	    MOY(tm->tm_mon),
	    tm->tm_mday,
	    tm->tm_year + 1900,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec,
	    zone);
	return(buf);
}

/*
 * Returns the difference between gmt and local time in seconds.
 * Use gmtime() and localtime() to keep things simple.
 */
static int32_t
gmt2local(void)
{
	register int dt, dir;
	register struct tm *gmt, *loc;
	time_t t;
	struct tm sgmt;

	t = time(NULL);
	gmt = &sgmt;
	*gmt = *gmtime(&t);
	loc = localtime(&t);
	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
	    (loc->tm_min - gmt->tm_min) * 60;

	/*
	 * If the year or julian day is different, we span 00:00 GMT
	 * and must add or subtract a day. Check the year first to
	 * avoid problems when the julian day wraps.
	 */
	dir = loc->tm_year - gmt->tm_year;
	if (dir == 0)
		dir = loc->tm_yday - gmt->tm_yday;
	dt += dir * 24 * 60 * 60;

	return (dt);
}

RETSIGTYPE
reaper(int signo)
{
	register pid_t pid;
	DECLWAITSTATUS status;

	for (;;) {
		pid = waitpid((pid_t)0, &status, WNOHANG);
		if ((int)pid < 0) {
			/* ptrace foo */
			if (errno == EINTR)
				continue;
			/* ECHILD means no one left */
			if (errno != ECHILD)
				syslog(LOG_ERR, "reaper: %m");
			break;
		}
		/* Already got everyone who was done */
		if (pid == 0)
			break;
		--cdepth;
		if (WEXITSTATUS(status))
			syslog(LOG_DEBUG, "reaper: pid %d, exit status %d",
			    pid, WEXITSTATUS(status));
	}
	return RETSIGVAL;
}

void
report(register char *title, register u_int32_t a, register u_char *e1,
    register u_char *e2, register time_t *t1p, register time_t *t2p)
{
	register char *cp, *hn;
	register int fd, pid;
	register FILE *f;
	char tempfile[64], cpu[64], os[64];
	char *fmt = "%20s: %s\n";
	char *watcher = WATCHER;
	char *watchee = WATCHEE;
	char *sendmail = PATH_SENDMAIL;
	char *unknown = "<unknown>";
	char buf[132];
	static int init = 0;

	/* No report until we're initialized */
	if (initializing)
		return;

	if (debug) {
		if (debug > 1) {
			dosyslog(LOG_NOTICE, title, a, e1, e2);
			return;
		}
		f = stdout;
		(void)putc('\n', f);
	} else {
		/* Setup child reaper if we haven't already */
		if (!init) {
			(void)setsignal(SIGCHLD, reaper);
			++init;
		}
		while (cdepth >= 3) {
			syslog(LOG_ERR, "report: pausing (cdepth %d)", cdepth);
			pause();
		}

		/* Syslog this event too */
		dosyslog(LOG_NOTICE, title, a, e1, e2);

		/* Update child depth */
		++cdepth;

		/* Fork off child to send mail */
		pid = fork();
		if (pid) {
			/* Parent */
			if (pid < 0)
				syslog(LOG_ERR, "report: fork() 1: %m");
			return;
		}

		/* Child */
		closelog();
		(void)strcpy(tempfile, "/tmp/arpwatch.XXXXXX");
		if ((fd = mkstemp(tempfile)) < 0) {
			syslog(LOG_ERR, "mkstemp(%s) %m", tempfile);
			exit(1);
		}
		if ((f = fdopen(fd, "w+")) == NULL) {
			syslog(LOG_ERR, "child fdopen(%s): %m", tempfile);
			exit(1);
		}
		/* Cheap delete-on-close */
		if (unlink(tempfile) < 0)
			syslog(LOG_ERR, "unlink(%s): %m", tempfile);
	}

	(void)fprintf(f, "From: %s\n", watchee);
	(void)fprintf(f, "To: %s\n", watcher);
	hn = gethname(a);
	if (!isdigit(*hn))
		(void)fprintf(f, "Subject: %s (%s)\n", title, hn);
	else {
		(void)fprintf(f, "Subject: %s\n", title);
		hn = unknown;
	}
	(void)putc('\n', f);
	(void)fprintf(f, fmt, "hostname", hn);
	(void)fprintf(f, fmt, "ip address", intoa(a));
	(void)fprintf(f, fmt, "ethernet address", e2str(e1));
	if ((cp = ec_find(e1)) == NULL)
		cp = unknown;
	(void)fprintf(f, fmt, "ethernet vendor", cp);
	if (hn != unknown && gethinfo(hn, cpu, sizeof(cpu), os, sizeof(os))) {
		(void)sprintf(buf, "%s %s", cpu, os);
		(void)fprintf(f, fmt, "dns cpu & os", buf);
	}
	if (e2) {
		(void)fprintf(f, fmt, "old ethernet address", e2str(e2));
		if ((cp = ec_find(e2)) == NULL)
			cp = unknown;
		(void)fprintf(f, fmt, "old ethernet vendor", cp);
	}
	if (t1p)
		(void)fprintf(f, fmt, "timestamp", fmtdate(*t1p));
	if (t2p)
		(void)fprintf(f, fmt, "previous timestamp", fmtdate(*t2p));
	if (t1p && t2p && *t1p && *t2p)
		(void)fprintf(f, fmt, "delta", fmtdelta(*t1p - *t2p));

	if (debug) {
		fflush(f);
		return;
	}

	(void)rewind(f);
	if (dup2(fileno(f), fileno(stdin)) < 0) {
		syslog(LOG_ERR, "dup2: %m");
		exit(1);
	}
	/* XXX Need to freopen()? */
	/* Always Deliver interactively (pause when child depth gets large) */
	execl(sendmail, "sendmail", "-odi", watcher, NULL);
	syslog(LOG_ERR, "execl: %s: %m", sendmail);
	exit(1);
}
