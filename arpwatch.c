/*
 * Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 2000
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
static const char copyright[] =
    "Copyright (c) 1990, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Id: arpwatch.c,v 1.63 2000/10/14 02:07:28 leres Exp $ (LBL)";
#endif

/*
 * arpwatch - keep track of ethernet/ip address pairings, report changes
 */

#include <sys/param.h>
#include <sys/types.h>				/* concession to AIX */
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#if __STDC__
struct mbuf;
struct rtentry;
#endif
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <pcap.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"
#include "db.h"
#include "ec.h"
#include "fddi.h"
#include "file.h"
#include "machdep.h"
#include "setsignal.h"
#include "util.h"

/* Some systems don't define these */
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035
#endif

#ifndef REVARP_REQUEST
#define REVARP_REQUEST		3
#define REVARP_REPLY		4
#endif

#ifndef ETHERTYPE_TRAIL
#define ETHERTYPE_TRAIL		0x1000
#endif

#ifndef ETHERTYPE_APOLLO
#define ETHERTYPE_APOLLO	0x8019
#endif

#ifndef IN_CLASSD_NET
#define IN_CLASSD_NET		0xf0000000
#endif

#ifndef max
#define max(a,b) ((b)>(a)?(b):(a))
#endif

char *prog;

int can_checkpoint;
int swapped;
int nobogons;

static u_int32_t net;
static u_int32_t netmask;

struct nets {
	u_int32_t net;
	u_int32_t netmask;
};

static struct nets *nets;
static int nets_ind;
static int nets_size;

extern int optind;
extern int opterr;
extern char *optarg;

/* Forwards */
int	addnet(const char *);
RETSIGTYPE checkpoint(int);
RETSIGTYPE die(int);
int	isbogon(u_int32_t);
int	main(int, char **);
void	process_ether(u_char *, const struct pcap_pkthdr *, const u_char *);
void	process_fddi(u_char *, const struct pcap_pkthdr *, const u_char *);
int	readsnmp(char *);
int	snmp_add(u_int32_t, u_char *, time_t, char *);
int	sanity_ether(struct ether_header *, struct ether_arp *, int);
int	sanity_fddi(struct fddi_header *, struct ether_arp *, int);
__dead	void usage(void) __attribute__((volatile));

int
main(int argc, char **argv)
{
	register char *cp;
	register int op, pid, snaplen, timeout, linktype, status;
#ifdef TIOCNOTTY
	register int fd;
#endif
	register pcap_t *pd;
	register char *interface, *rfilename;
	struct bpf_program code;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (argv[0] == NULL)
		prog = "arpwatch";
	else if ((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	if (abort_on_misalignment(errbuf) < 0) {
		(void)fprintf(stderr, "%s: %s\n", prog, errbuf);
		exit(1);
	}

	opterr = 0;
	interface = NULL;
	rfilename = NULL;
	pd = NULL;
	while ((op = getopt(argc, argv, "df:i:n:Nr:")) != EOF)
		switch (op) {

		case 'd':
			++debug;
#ifndef DEBUG
			(void)fprintf(stderr,
			    "%s: Warning: Not compiled with -DDEBUG\n", prog);
#endif
			break;

		case 'f':
			arpfile = optarg;
			break;

		case 'i':
			interface = optarg;
			break;

		case 'n':
			if (!addnet(optarg))
				usage();
			break;

		case 'N':
			++nobogons;
			break;

		case 'r':
			rfilename = optarg;
			break;

		default:
			usage();
		}

	if (optind != argc)
		usage();

	if (rfilename != NULL) {
		net = 0;
		netmask = 0;
	} else {
		/* Determine interface if not specified */
		if (interface == NULL &&
		    (interface = pcap_lookupdev(errbuf)) == NULL) {
			(void)fprintf(stderr, "%s: lookup_device: %s\n",
			    prog, errbuf);
			exit(1);
		}

		/* Determine network and netmask */
		if (pcap_lookupnet(interface, &net, &netmask, errbuf) < 0) {
			(void)fprintf(stderr, "%s: bad interface %s: %s\n",
			    prog, interface, errbuf);
			exit(1);
		}

		/* Drop into the background if not debugging */
		if (!debug) {
			pid = fork();
			if (pid < 0) {
				syslog(LOG_ERR, "main fork(): %m");
				exit(1);
			} else if (pid != 0)
				exit(0);
			(void)close(fileno(stdin));
			(void)close(fileno(stdout));
			(void)close(fileno(stderr));
#ifdef TIOCNOTTY
			fd = open("/dev/tty", O_RDWR);
			if (fd >= 0) {
				(void)ioctl(fd, TIOCNOTTY, 0);
				(void)close(fd);
			}
#else
			(void) setsid();
#endif
		}
	}

	openlog(prog, 0, LOG_DAEMON);

	if (chdir(arpdir) < 0) {
		syslog(LOG_ERR, "chdir(%s): %m", arpdir);
		syslog(LOG_ERR, "(using current working directory)");
	}

	if (rfilename != NULL) {
		pd = pcap_open_offline(rfilename, errbuf);
		if (pd == NULL) {
			syslog(LOG_ERR, "pcap open %s: %s", rfilename,  errbuf);
			exit(1);
		}
		swapped = pcap_is_swapped(pd);
	} else {
		snaplen = max(sizeof(struct ether_header),
		    sizeof(struct fddi_header)) + sizeof(struct ether_arp);
		timeout = 1000;
		pd = pcap_open_live(interface, snaplen, 1, timeout, errbuf);
		if (pd == NULL) {
			syslog(LOG_ERR, "pcap open %s: %s", interface, errbuf);
			exit(1);
		}
#ifdef WORDS_BIGENDIAN
		swapped = 1;
#endif
	}

	/*
	 * Revert to non-privileged user after opening sockets
	 * (not needed on most systems).
	 */
	setgid(getgid());
	setuid(getuid());

	/* Must be ethernet or fddi */
	linktype = pcap_datalink(pd);
	if (linktype != DLT_EN10MB && linktype != DLT_FDDI) {
		syslog(LOG_ERR, "Link layer type %d not ethernet or fddi",
		    linktype);
		exit(1);
	}

	/* Compile and install filter */
	if (pcap_compile(pd, &code, "arp or rarp", 1, netmask) < 0) {
		syslog(LOG_ERR, "pcap_compile: %s", pcap_geterr(pd));
		exit(1);
	}
	if (pcap_setfilter(pd, &code) < 0) {
		syslog(LOG_ERR, "pcap_setfilter: %s", pcap_geterr(pd));
		exit(1);
	}
	if (rfilename == NULL)
		syslog(LOG_INFO, "listening on %s", interface);

	/* Read in database */
	initializing = 1;
	if (!readdata())
		exit(1);
	sorteinfo();
#ifdef DEBUG
	if (debug > 2) {
		debugdump();
		exit(0);
	}
#endif
	initializing = 0;

	(void)setsignal(SIGINT, die);
	(void)setsignal(SIGTERM, die);
	(void)setsignal(SIGHUP, die);
	if (rfilename == NULL) {
		(void)setsignal(SIGQUIT, checkpoint);
		(void)setsignal(SIGALRM, checkpoint);
		(void)alarm(CHECKPOINT);
	}

	switch (linktype) {

	case DLT_EN10MB:
		status = pcap_loop(pd, 0, process_ether, NULL);
		break;

	case DLT_FDDI:
		status = pcap_loop(pd, 0, process_fddi, NULL);
		break;

	default:
		syslog(LOG_ERR, "bad linktype %d (can't happen)", linktype);
		exit(1);
	}
	if (status < 0) {
		syslog(LOG_ERR, "pcap_loop: %s", pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	if (!dump())
		exit(1);
	exit(0);
}

/* Process an ethernet arp/rarp packet */
void
process_ether(register u_char *u, register const struct pcap_pkthdr *h,
    register const u_char *p)
{
	register struct ether_header *eh;
	register struct ether_arp *ea;
	register u_char *sea, *sha;
	register time_t t;
	u_int32_t sia;

	eh = (struct ether_header *)p;
	ea = (struct ether_arp *)(eh + 1);

	if (!sanity_ether(eh, ea, h->caplen))
		return;

	/* Source hardware ethernet address */
	sea = (u_char *)ESRC(eh);

	/* Source ethernet address */
	sha = (u_char *)SHA(ea);

	/* Source ip address */
	BCOPY(SPA(ea), &sia, 4);

	/* Watch for bogons */
	if (isbogon(sia)) {
		dosyslog(LOG_INFO, "bogon", sia, sea, sha);
		return;
	}

	/* Watch for ethernet broadcast */
	if (MEMCMP(sea, zero, 6) == 0 || MEMCMP(sea, allones, 6) == 0 ||
	    MEMCMP(sha, zero, 6) == 0 || MEMCMP(sha, allones, 6) == 0) {
		dosyslog(LOG_INFO, "ethernet broadcast", sia, sea, sha);
		return;
	}

	/* Double check ethernet addresses */
	if (MEMCMP(sea, sha, 6) != 0) {
		dosyslog(LOG_INFO, "ethernet mismatch", sia, sea, sha);
		return;
	}

	/* Got a live one */
	t = h->ts.tv_sec;
	can_checkpoint = 0;
	if (!ent_add(sia, sea, t, NULL))
		syslog(LOG_ERR, "ent_add(%s, %s, %ld) failed",
		    intoa(sia), e2str(sea), t);
	can_checkpoint = 1;
}

/* Perform sanity checks on an ethernet arp/rarp packet, return true if ok */
int
sanity_ether(register struct ether_header *eh, register struct ether_arp *ea,
    register int len)
{
	/* XXX use bsd style ether_header to avoid messy ifdef's */
	struct bsd_ether_header {
		u_char  ether_dhost[6];
		u_char  ether_shost[6];
		u_short ether_type;
	};
	register u_char *shost = ((struct bsd_ether_header *)eh)->ether_shost;

	eh->ether_type = ntohs(eh->ether_type);
	ea->arp_hrd = ntohs(ea->arp_hrd);
	ea->arp_pro = ntohs(ea->arp_pro);
	ea->arp_op = ntohs(ea->arp_op);

	if (len < sizeof(*eh) + sizeof(*ea)) {
		syslog(LOG_ERR, "short (want %d)\n", sizeof(*eh) + sizeof(*ea));
		return(0);
	}

	/* XXX sysv r4 seems to use hardware format 6 */
	if (ea->arp_hrd != ARPHRD_ETHER && ea->arp_hrd != 6) {
		syslog(LOG_ERR, "%s sent bad hardware format 0x%x\n",
		    e2str(shost), ea->arp_hrd);
		return(0);
	}

	/* XXX hds X terminals sometimes send trailer arp replies */
	if (ea->arp_pro != ETHERTYPE_IP && ea->arp_pro != ETHERTYPE_TRAIL) {
		syslog(LOG_ERR, "%s sent packet not ETHERTYPE_IP (0x%x)\n",
		    e2str(shost), ea->arp_pro);
		return(0);
	}

	if (ea->arp_hln != 6 || ea->arp_pln != 4) {
		syslog(LOG_ERR, "%s sent bad addr len (hard %d, prot %d)\n",
		    e2str(shost), ea->arp_hln, ea->arp_pln);
		return(0);
	}

	/*
	 * We're only interested in arp requests, arp replies
	 * and reverse arp replies
	 */
	if (eh->ether_type == ETHERTYPE_ARP) {
		if (ea->arp_op != ARPOP_REQUEST &&
		    ea->arp_op != ARPOP_REPLY) {
			syslog(LOG_ERR, "%s sent wrong arp op %d\n",
			     e2str(shost), ea->arp_op);
			return(0);
		}
	} else if (eh->ether_type == ETHERTYPE_REVARP) {
		if (ea->arp_op == REVARP_REQUEST) {
			/* no useful information here */
			return(0);
		} else if (ea->arp_op != REVARP_REPLY) {
			if (debug)
				syslog(LOG_ERR, "%s sent wrong revarp op %d\n",
				    e2str(shost), ea->arp_op);
			return(0);
		}
	} else {
		syslog(LOG_ERR, "%s sent bad type 0x%x\n",
		    e2str(shost), eh->ether_type);
		return(0);
	}

	return(1);
}

static void
bit_reverse(u_char *p, unsigned len)
{
	unsigned i;
	u_char b;

	for (i = len; i; i--, p++) {
		b = (*p & 0x01 ? 0x80 : 0)
			| (*p & 0x02 ? 0x40 : 0)
			| (*p & 0x04 ? 0x20 : 0)
			| (*p & 0x08 ? 0x10 : 0)
			| (*p & 0x10 ? 0x08 : 0)
			| (*p & 0x20 ? 0x04 : 0)
			| (*p & 0x40 ? 0x02 : 0)
			| (*p & 0x80 ? 0x01 : 0);
		*p = b;
	}
}

void
process_fddi(register u_char *u, register const struct pcap_pkthdr *h,
    register const u_char *p)
{
	register struct fddi_header *fh;
	register struct ether_arp *ea;
	register u_char *sea, *sha;
	register time_t t;
	u_int32_t sia;

	fh = (struct fddi_header *)p;
	ea = (struct ether_arp *)(fh + 1);

	if (!swapped) {
		bit_reverse(fh->src, 6);
		bit_reverse(fh->dst, 6);
	}
	if (!sanity_fddi(fh, ea, h->caplen))
		return;

	/* Source MAC hardware ethernet address */
	sea = (u_char *)fh->src;

	/* Source ARP ethernet address */
	sha = (u_char *)SHA(ea);

	/* Source ARP ip address */
	BCOPY(SPA(ea), &sia, 4);

	/* Watch for bogons */
	if (isbogon(sia)) {
		dosyslog(LOG_INFO, "bogon", sia, sea, sha);
		return;
	}

	/* Watch for ethernet broadcast */
	if (MEMCMP(sea, zero, 6) == 0 || MEMCMP(sea, allones, 6) == 0 ||
	    MEMCMP(sha, zero, 6) == 0 || MEMCMP(sha, allones, 6) == 0) {
		dosyslog(LOG_INFO, "ethernet broadcast", sia, sea, sha);
		return;
	}

	/* Double check ethernet addresses */
	if (MEMCMP(sea, sha, 6) != 0) {
		dosyslog(LOG_INFO, "ethernet mismatch", sia, sea, sha);
		return;
	}

	/* Got a live one */
	t = h->ts.tv_sec;
	can_checkpoint = 0;
	if (!ent_add(sia, sea, t, NULL))
		syslog(LOG_ERR, "ent_add(%s, %s, %ld) failed",
		    intoa(sia), e2str(sea), t);
	can_checkpoint = 1;
}

/* Perform sanity checks on arp/rarp packet, return true if ok */
int
sanity_fddi(register struct fddi_header *fh, register struct ether_arp *ea,
    register int len)
{
	u_char *shost = fh->src;
	u_short type, hrd, pro, op;

	/* This rather clunky copy stuff is needed because the fddi header
	 * has an odd (i.e. not even) length, causing memory alignment
	 * errors when attempts are made to access the arp header fields
	 * as shorts */
	BCOPY(fh->snap.snap_type, &type, sizeof(u_short));
	BCOPY(&(ea->arp_hrd), &hrd, sizeof(hrd));
	BCOPY(&(ea->arp_pro), &pro, sizeof(pro));
	BCOPY(&(ea->arp_op), &op, sizeof(op));
	type = ntohs(type);
	hrd = ntohs(hrd);
	pro = ntohs(pro);
	op = ntohs(op);

	if (len < sizeof(*fh) + sizeof(*ea)) {
		syslog(LOG_ERR, "short (want %d)\n", sizeof(*fh) + sizeof(*ea));
		return(0);
	}

	/* XXX sysv r4 seems to use hardware format 6 */
	if (hrd != ARPHRD_ETHER && hrd != 6) {
		syslog(LOG_ERR, "%s sent bad hardware format 0x%x\n",
		    e2str(shost), hrd);
		return(0);
	}


	/* XXX hds X terminals sometimes send trailer arp replies */
	if (pro != ETHERTYPE_IP &&
	    pro != ETHERTYPE_TRAIL &&
	    pro != ETHERTYPE_APOLLO) {
		syslog(LOG_ERR, "%s sent packet not ETHERTYPE_IP (0x%x)\n",
		    e2str(shost), pro);
		return(0);
	}

	if (ea->arp_hln != 6 || ea->arp_pln != 4) {
		syslog(LOG_ERR, "%s sent bad addr len (hard %d, prot %d)\n",
		    e2str(shost), ea->arp_hln, ea->arp_pln);
		return(0);
	}

	/*
	 * We're only interested in arp requests, arp replies
	 * and reverse arp replies
	 */
	if (type == ETHERTYPE_ARP) {
		if (op != ARPOP_REQUEST &&
		    op != ARPOP_REPLY) {
			syslog(LOG_ERR, "%s sent wrong arp op %d\n",
			     e2str(shost), op);
			return(0);
		}
	} else if (type == ETHERTYPE_REVARP) {
		if (op == REVARP_REQUEST) {
			/* no useful information here */
			return(0);
		} else if (op != REVARP_REPLY) {
			if (debug)
				syslog(LOG_ERR, "%s sent wrong revarp op %d\n",
				    e2str(shost), op);
			return(0);
		}
	} else {
		syslog(LOG_ERR, "%s sent bad type 0x%x\n",
		    e2str(shost), type);
		return(0);
	}
	return(1);
}

int
addnet(register const char *str)
{
	register char *cp;
	register int width;
	register u_int32_t n, m;
	register struct nets *np;
	char *cp2;
	char tstr[64];

	if (strlen(str) > sizeof(tstr) - 1)
		return(0);

	if (nets_size <= 0) {
		nets_size = 8;
		nets = malloc(nets_size * sizeof(*nets));
	} else if (nets_size <= nets_ind) {
		/* XXX debugging */
		nets_size <<= 1;
		nets = realloc(nets, nets_size * sizeof(*nets));
	}
	if (nets == NULL) {
		(void)fprintf(stderr, "%s: addnet: malloc/realloc: %s\n",
		    prog, strerror(errno));
		exit(1);
	}
	np = nets + nets_ind;

	width = 0;
	strcpy(tstr, str);
	cp = strchr(tstr, '/');
	if (cp != NULL) {
		*cp++ = '\0';
		width = strtol(cp, &cp2, 10);
		/* Trailing garbage */
		if (*cp2 != '\0')
			    return (0);
		if (width > 32)
			    return (0);
	}

	/* XXX hack */
	n = ntohl(inet_addr(tstr));
	while ((n & 0xff000000) == 0) {
		n <<= 8;
		if (n == 0)
			return (0);
	}
	n = htonl(n);

	if (width != 0) {
		m = ~0;
		m <<= 32 - width;
	} else if (IN_CLASSA(n))
		m = IN_CLASSA_NET;
	else if (IN_CLASSB(n))
		m = IN_CLASSB_NET;
	else if (IN_CLASSC(n))
		m = IN_CLASSC_NET;
	else if (IN_CLASSD(n))
		m = IN_CLASSD_NET;
	else
		return (0);
	m = htonl(m);

	np->net = n;
	np->netmask = m;
	++nets_ind;

	return (1);
}

int
isbogon(register u_int32_t sia)
{
	register int i;
	register struct nets *np;

	if (nobogons)
		return (0);
	if ((sia & netmask) == net)
		return (0);
	for (i = 0, np = nets; i < nets_ind; ++i, ++np)
		if ((sia & np->netmask) == np->net)
			return (0);
	return (1);
}

RETSIGTYPE
die(int signo)
{

	syslog(LOG_DEBUG, "exiting");
	checkpoint(0);
	exit(1);
}

RETSIGTYPE
checkpoint(int signo)
{

	if (!can_checkpoint)
		(void)alarm(1);
	else {
		(void)alarm(0);
		(void)dump();
		(void)alarm(CHECKPOINT);
	}
	return RETSIGVAL;
}

__dead void
usage(void)
{
	extern char version[];

	(void)fprintf(stderr, "Version %s\n", version);
	(void)fprintf(stderr, "usage: %s [-dN] [-f datafile] [-i interface]"
	    " [-n net[/width]] [-r file]\n", prog);
	exit(1);
}
