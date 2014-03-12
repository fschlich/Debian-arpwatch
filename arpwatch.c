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

/*
 arpwatch NG has been forked by and is copyrighted by freek
 numerous changes have been made - please consult the CHANGES file in
 this distribution

 arpwatch NG is distributed under the GPL
 */

#include <sys/param.h>
#include <sys/types.h>		/* concession to AIX */
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

#include <pwd.h>
#include <grp.h>

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
#include "report.h"

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
static void process_ether(u_char *, const struct pcap_pkthdr *, const u_char *);
static void process_fddi(u_char *, const struct pcap_pkthdr *, const u_char *);
static int sanity_ether(struct ether_header *, struct ether_arp *, int, time_t *);
static int sanity_fddi(struct fddi_header *, struct ether_arp *, int, time_t *);
static int isbogon(u_int32_t);
static int addnet(const char *);

__dead void usage(void) __attribute__ ((volatile));
static void drop_privileges(const char* user);
static void go_daemon(void);
RETSIGTYPE checkpoint(int);
RETSIGTYPE die(int);


int main(int argc, char **argv)
{
	char *cp;
	int op, snaplen, timeout, linktype, status;

	pcap_t *pd;
	char *interface, *rfilename;
	struct bpf_program code;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	/* this is the default filter: only arp or rarp traffic */
	char pcap_filter[512]={"(arp or rarp)"};
	
	/* default report mode is 0 == old style */
	int report_mode=0;
        char *drop_username=NULL;

	if(argv[0] == NULL)
		prog = "arpwatch";
	else if((cp = strrchr(argv[0], '/')) != NULL)
		prog = cp + 1;
	else
		prog = argv[0];

	if(abort_on_misalignment(errbuf) < 0) {
		fprintf(stderr, "%s: %s\n", prog, errbuf);
		exit(1);
	}

	interface = NULL;
	rfilename = NULL;
	pd = NULL;
	while((op = getopt(argc, argv, "df:i:n:Nr:m:ps:t:F:u:P:")) != EOF) {
		switch (op) {

		case 'd':
			++debug;
			break;

		case 'f':
			arpfile = optarg;
			break;

		case 'i':
			interface = optarg;
			break;

		case 'n':
			if(!addnet(optarg))
				usage();
			break;

		case 'N':
			++nobogons;
			break;

		case 'r':
			rfilename = optarg;
                        break;

                case 'm':
			/*
			 set the report function pointer to whatever is requested
			 the original mode remains default
			 */
			report_mode=atoi(optarg);
			if(setup_reportmode(report_mode)) {
                                fprintf(stderr, "%s: Unknown report mode %d, exiting\n", prog, report_mode);
                                exit(1);
                        }
			break;

                case 't':
                        mailto=optarg;
                        break;
			
		case 'F':
			mailfrom=optarg;
			break;

                case 'p':
			++nopromisc;
                        break;

                case 's':
			sendmail=optarg;
			break;

                case 'u':
			drop_username=optarg;
			break;
			
		case 'P':
			sprintf(pcap_filter, "%s and %s", "(arp or rarp)", optarg);
			//printf("arpwatch: using pcap filter: %s\n", pcap_filter);
			break;

		default:
			usage();
		}
	}

	if(optind != argc) {
		usage();
	}

	openlog(prog, 0, LOG_DAEMON);

	if(chdir(arpdir) < 0) {
		fprintf(stderr, "%s: chdir(%s) failed, using cwd for data.\n", prog, arpdir);
	}

	/* run in offline mode, no fork, analyze file */
	if(rfilename != NULL) {
		pd = pcap_open_offline(rfilename, errbuf);
		if(pd == NULL) {
			fprintf(stderr, "pcap open %s (%s)", rfilename, errbuf);
			exit(1);
		}
		swapped = pcap_is_swapped(pd);

	} else {

		/* Determine interface if not specified */
		if(interface == NULL && (interface = pcap_lookupdev(errbuf)) == NULL) {
			fprintf(stderr, "%s: lookup_device (%s)\n", prog, errbuf);
			exit(1);
		}

		/* Determine network and netmask */
		if(pcap_lookupnet(interface, &net, &netmask, errbuf) < 0) {
			fprintf(stderr, "%s: assuming unconfigured interface %s (%s), continuing\n", prog, interface, errbuf);
                        net=0;
                        netmask=0;
		}

		snaplen = max(sizeof(struct ether_header), sizeof(struct fddi_header)) + sizeof(struct ether_arp);
		timeout = 1000;

		pd = pcap_open_live(interface, snaplen, !nopromisc, timeout, errbuf);
		if(pd == NULL) {
			fprintf(stderr, "%s: pcap open %s (%s)\n", prog, interface, errbuf);
			exit(1);
		}
#ifdef WORDS_BIGENDIAN
		swapped = 1;
#endif
	}

        /*
         Revert to non-privileged user after opening sockets
         Just to be safe
         */
	if(drop_username) {
		drop_privileges(drop_username);
	} else {
		setgid(getgid());
		setuid(getuid());
	}

	/* Must be ethernet or fddi */
	linktype = pcap_datalink(pd);
	if(linktype != DLT_EN10MB && linktype != DLT_FDDI) {
		fprintf(stderr, "%s: Link layer type %d not ethernet or fddi", prog, linktype);
		exit(1);
	}

	/* Compile and install filter */
	if(pcap_compile(pd, &code, pcap_filter, 1, netmask) < 0) {
		fprintf(stderr, "%s: pcap_compile %s for: %s\n", prog, pcap_geterr(pd), pcap_filter);
		exit(1);
	}
	if(pcap_setfilter(pd, &code) < 0) {
		fprintf(stderr, "%s: pcap_setfilter: %s\n", prog, pcap_geterr(pd));
		exit(1);
	}
	if(rfilename == NULL)
		syslog(LOG_INFO, "listening on %s", interface);

	/* Read in database */
	initializing = 1;
	if(!readdata())
		exit(1);
	sorteinfo();

        if(debug > 2) {
		debugdump();
		exit(0);
	}

        initializing = 0;

        /* Drop into daemon mode the latest time possible */
	if(!debug && report_mode==REPORT_NORMAL) {
		go_daemon();
	}

	/*
	 setup signals after we dropped into daemon mode
	 else they're out of effect, dumb me
	 Fixes bug with arp.dat not being updated
	 */
	setsignal(SIGINT, die);
	setsignal(SIGTERM, die);
	setsignal(SIGHUP, die);
	if(rfilename == NULL) {
		setsignal(SIGQUIT, checkpoint);
		setsignal(SIGALRM, checkpoint);
		alarm(CHECKPOINT);
	}

	switch (linktype) {

	case DLT_EN10MB:
		status = pcap_loop(pd, 0, process_ether, NULL);
		break;

	case DLT_FDDI:
		status = pcap_loop(pd, 0, process_fddi, NULL);
		break;

	default:
		fprintf(stderr, "%s: bad linktype %d (can't happen)\n", prog, linktype);
                syslog(LOG_ERR, "bad linktype %d (can't happen)", linktype);
		exit(1);
	}

        if(status < 0) {
		fprintf(stderr, "%s: pcap_loop: %s\n", prog, pcap_geterr(pd));
		syslog(LOG_ERR, "pcap_loop: %s", pcap_geterr(pd));
		exit(1);
	}

        pcap_close(pd);
	if(!dump())
		exit(1);
	exit(0);
}


/* Process an ethernet arp/rarp packet */
static void process_ether(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
	struct ether_header *eh;
	struct ether_arp *ea;
	u_char *sea, *sha;
	time_t t;
	u_int32_t sia;

	eh = (struct ether_header *)p;
	ea = (struct ether_arp *)(eh + 1);

        /* extract time of observation */
        t=h->ts.tv_sec;

	if(!sanity_ether(eh, ea, h->caplen, &t))
		return;

	/* Source hardware ethernet address */
	sea = (u_char *) ESRC(eh);

	/* Source ethernet address */
	sha = (u_char *) SHA(ea);

	/* Source ip address */
	BCOPY(SPA(ea), &sia, 4);


	/* Watch for bogons */
	if(isbogon(sia)) {
                report(ACTION_BOGON, sia, sea, sha, &t, NULL);
		return;
	}

	/* Watch for ethernet broadcast */
        if(MEMCMP(sea, zero, 6) == 0 || MEMCMP(sea, allones, 6) == 0
           || MEMCMP(sha, zero, 6) == 0 || MEMCMP(sha, allones, 6) == 0) {
                report(ACTION_ETHER_BROADCAST, sia, sea, sha, &t, NULL);
		return;
	}

	/* Double check ethernet addresses */
	if(MEMCMP(sea, sha, 6) != 0) {
                report(ACTION_ETHER_MISMATCH, sia, sea, sha, &t, NULL);
		return;
	}

	/* when all checks have been passed add(check) the entry into the arp db */
	can_checkpoint = 0;
	if(!ent_add(sia, sea, t, NULL))
		syslog(LOG_ERR, "ent_add(%s, %s, %ld) failed", intoa(sia), e2str(sea), t);
	can_checkpoint = 1;
}

/* Perform sanity checks on an ethernet arp/rarp packet, return true if ok */
static int sanity_ether(struct ether_header *eh, struct ether_arp *ea, int len, time_t *t)
{
	/* XXX use bsd style ether_header to avoid messy ifdef's */
	struct bsd_ether_header {
		u_char ether_dhost[6];
		u_char ether_shost[6];
		u_short ether_type;
	};
	u_char *shost = ((struct bsd_ether_header *)eh)->ether_shost;

	eh->ether_type = ntohs(eh->ether_type);
	ea->arp_hrd = ntohs(ea->arp_hrd);
	ea->arp_pro = ntohs(ea->arp_pro);
	ea->arp_op = ntohs(ea->arp_op);

        /* these are cheap, but maybe don't do them twice */
	u_char *sea, *sha;
	u_int32_t sia;
	/* Source addresses */
	sea = (u_char *) ESRC(eh);
	sha = (u_char *) SHA(ea);
	/* Source ip address */
	BCOPY(SPA(ea), &sia, 4);

	if(len < sizeof(*eh) + sizeof(*ea)) {
		//syslog(LOG_ERR, "short (want %d)\n", sizeof(*eh) + sizeof(*ea));
                report(ACTION_ETHER_TOOSHORT, sia, sea, sha, t, NULL);
		return (0);
	}

	/* XXX sysv r4 seems to use hardware format 6 */
	if(ea->arp_hrd != ARPHRD_ETHER && ea->arp_hrd != 6) {
		//syslog(LOG_ERR, "%s sent bad hardware format 0x%x\n", e2str(shost), ea->arp_hrd);
                report(ACTION_ETHER_BADFORMAT, sia, sea, sha, t, NULL);
		return (0);
	}

	/* XXX hds X terminals sometimes send trailer arp replies */
	if(ea->arp_pro != ETHERTYPE_IP && ea->arp_pro != ETHERTYPE_TRAIL) {
		//syslog(LOG_ERR, "%s sent packet not ETHERTYPE_IP (0x%x)\n", e2str(shost), ea->arp_pro);
		report(ACTION_ETHER_WRONGTYPE_IP, sia, sea, sha, t, NULL);
		return (0);
	}

	if(ea->arp_hln != 6 || ea->arp_pln != 4) {
		//syslog(LOG_ERR, "%s sent bad addr len (hard %d, prot %d)\n", e2str(shost), ea->arp_hln, ea->arp_pln);
		report(ACTION_ETHER_BADLENGTH, sia, sea, sha, t, NULL);
		return (0);
	}

	/*
	 * We're only interested in arp requests, arp replies
	 * and reverse arp replies
	 */
	if(eh->ether_type == ETHERTYPE_ARP) {
		if(ea->arp_op != ARPOP_REQUEST && ea->arp_op != ARPOP_REPLY) {
			//syslog(LOG_ERR, "%s sent wrong arp op %d\n", e2str(shost), ea->arp_op);
			report(ACTION_ETHER_WRONGOP, sia, sea, sha, t, NULL);
			return (0);
		}
	} else if(eh->ether_type == ETHERTYPE_REVARP) {
		if(ea->arp_op == REVARP_REQUEST) {
			/* no useful information here */
			return (0);
		} else if(ea->arp_op != REVARP_REPLY) {
			report(ACTION_ETHER_WRONGRARP, sia, sea, sha, t, NULL);
			if(debug)
				syslog(LOG_ERR, "%s sent wrong revarp op %d\n", e2str(shost), ea->arp_op);
			return (0);
		}
	} else {
		//syslog(LOG_ERR, "%s sent bad type 0x%x\n", e2str(shost), eh->ether_type);
		report(ACTION_ETHER_WRONGTYPE, sia, sea, sha, t, NULL);
		return (0);
	}

	return (1);
}

static void bit_reverse(u_char *p, unsigned len)
{
	unsigned i;
	u_char b;

	for(i = len; i; i--, p++) {
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

static void process_fddi(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
	struct fddi_header *fh;
	struct ether_arp *ea;
	u_char *sea, *sha;
	time_t t;
	u_int32_t sia;

	fh = (struct fddi_header *)p;
	ea = (struct ether_arp *)(fh + 1);

	if(!swapped) {
		bit_reverse(fh->src, 6);
		bit_reverse(fh->dst, 6);
	}
        /* extract time of observation */
	t = h->ts.tv_sec;

	if(!sanity_fddi(fh, ea, h->caplen, &t))
		return;

	/* Source MAC hardware ethernet address */
	sea = (u_char *) fh->src;

	/* Source ARP ethernet address */
	sha = (u_char *) SHA(ea);

	/* Source ARP ip address */
	BCOPY(SPA(ea), &sia, 4);

	/* Watch for bogons */
	if(isbogon(sia)) {
                report(ACTION_BOGON, sia, sea, sha, &t, NULL);
		return;
	}

	/* Watch for ethernet broadcast */
	if(MEMCMP(sea, zero, 6) == 0 || MEMCMP(sea, allones, 6) == 0 || MEMCMP(sha, zero, 6) == 0 || MEMCMP(sha, allones, 6) == 0) {
                report(ACTION_ETHER_BROADCAST, sia, sea, sha, &t, NULL);
		return;
	}

	/* Double check ethernet addresses */
	if(MEMCMP(sea, sha, 6) != 0) {
                report(ACTION_ETHER_MISMATCH, sia, sea, sha, &t, NULL);
		return;
	}

	/* Got a live one */
	can_checkpoint = 0;
	if(!ent_add(sia, sea, t, NULL))
		syslog(LOG_ERR, "ent_add(%s, %s, %ld) failed", intoa(sia), e2str(sea), t);
	can_checkpoint = 1;
}

/* Perform sanity checks on arp/rarp packet, return true if ok */
static int sanity_fddi(struct fddi_header *fh, struct ether_arp *ea, int len, time_t *t)
{
	u_char *shost = fh->src;
	u_short type, hrd, pro, op;

        /* these are cheap, but maybe don't do them twice */
	u_char *sea, *sha;
	u_int32_t sia;
	/* Source MAC hardware ethernet address */
	sea = (u_char *) fh->src;
	/* Source ARP ethernet address */
	sha = (u_char *) SHA(ea);
	/* Source ARP ip address */
	BCOPY(SPA(ea), &sia, 4);

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

	if(len < sizeof(*fh) + sizeof(*ea)) {
		//syslog(LOG_ERR, "short (want %d)\n", sizeof(*fh) + sizeof(*ea));
		report(ACTION_ETHER_TOOSHORT, sia, sea, sha, t, NULL);
		return (0);
	}

	/* XXX sysv r4 seems to use hardware format 6 */
	if(hrd != ARPHRD_ETHER && hrd != 6) {
		//syslog(LOG_ERR, "%s sent bad hardware format 0x%x\n", e2str(shost), hrd);
		report(ACTION_ETHER_BADFORMAT, sia, sea, sha, t, NULL);
		return (0);
	}


	/* XXX hds X terminals sometimes send trailer arp replies */
	if(pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL && pro != ETHERTYPE_APOLLO) {
		//syslog(LOG_ERR, "%s sent packet not ETHERTYPE_IP (0x%x)\n", e2str(shost), pro);
		report(ACTION_ETHER_WRONGTYPE_IP, sia, sea, sha, t, NULL);
		return (0);
	}

	if(ea->arp_hln != 6 || ea->arp_pln != 4) {
		//syslog(LOG_ERR, "%s sent bad addr len (hard %d, prot %d)\n", e2str(shost), ea->arp_hln, ea->arp_pln);
		report(ACTION_ETHER_BADLENGTH, sia, sea, sha, t, NULL);
		return (0);
	}

	/*
	 * We're only interested in arp requests, arp replies
	 * and reverse arp replies
	 */
	if(type == ETHERTYPE_ARP) {
		if(op != ARPOP_REQUEST && op != ARPOP_REPLY) {
			//syslog(LOG_ERR, "%s sent wrong arp op %d\n", e2str(shost), op);
			report(ACTION_ETHER_WRONGOP, sia, sea, sha, t, NULL);
			return (0);
		}
	} else if(type == ETHERTYPE_REVARP) {
		if(op == REVARP_REQUEST) {
			/* no useful information here */
			return (0);
		} else if(op != REVARP_REPLY) {
			report(ACTION_ETHER_WRONGRARP, sia, sea, sha, t, NULL);
			if(debug)
				syslog(LOG_ERR, "%s sent wrong revarp op %d\n", e2str(shost), op);
			return (0);
		}
	} else {
		//syslog(LOG_ERR, "%s sent bad type 0x%x\n", e2str(shost), type);
		report(ACTION_ETHER_WRONGTYPE, sia, sea, sha, t, NULL);
		return (0);
	}
	return (1);
}

static int addnet(const char *str)
{
	char *cp;
	int width;
	u_int32_t n, m;
	struct nets *np;
	char *cp2;
	char tstr[64];

	if(strlen(str) > sizeof(tstr) - 1)
		return (0);

	if(nets_size <= 0) {
		nets_size = 8;
		nets = malloc(nets_size * sizeof(*nets));
	} else if(nets_size <= nets_ind) {
		/* XXX debugging */
		nets_size <<= 1;
		nets = realloc(nets, nets_size * sizeof(*nets));
	}
	if(nets == NULL) {
		fprintf(stderr, "%s: addnet: malloc/realloc: %s\n", prog, strerror(errno));
		exit(1);
	}
	np = nets + nets_ind;

	width = 0;
	strcpy(tstr, str);
	cp = strchr(tstr, '/');
	if(cp != NULL) {
		*cp++ = '\0';
		width = strtol(cp, &cp2, 10);
		/* Trailing garbage */
		if(*cp2 != '\0')
			return (0);
		if(width > 32)
			return (0);
	}

	/* XXX hack */
	n = ntohl(inet_addr(tstr));
	while((n & 0xff000000) == 0) {
		n <<= 8;
		if(n == 0)
			return (0);
	}
	n = htonl(n);

	if(width != 0) {
		m = ~0;
		m <<= 32 - width;
	} else if(IN_CLASSA(n))
		m = IN_CLASSA_NET;
	else if(IN_CLASSB(n))
		m = IN_CLASSB_NET;
	else if(IN_CLASSC(n))
		m = IN_CLASSC_NET;
	else if(IN_CLASSD(n))
		m = IN_CLASSD_NET;
	else
		return (0);
	m = htonl(m);

	np->net = n;
	np->netmask = m;
	++nets_ind;

	return (1);
}

static int isbogon(u_int32_t sia)
{
	int i;
	struct nets *np;

	if(nobogons)
		return (0);
	if((sia & netmask) == net)
		return (0);
	for(i = 0, np = nets; i < nets_ind; ++i, ++np)
		if((sia & np->netmask) == np->net)
			return (0);
	return (1);
}

RETSIGTYPE die(int signo)
{

	syslog(LOG_DEBUG, "exiting");
	checkpoint(0);
	exit(1);
}

RETSIGTYPE checkpoint(int signo)
{

	if(!can_checkpoint)
		alarm(1);
	else {
		alarm(0);
		dump();
		alarm(CHECKPOINT);
	}
	return RETSIGVAL;
}

__dead void usage(void)
{
	extern char version[];

	printf("%s version %s\n", prog, version);
	printf("    -d                increase debugging level\n" \
	       "    -i if             only listen on interface if\n" \
	       "    -m report_mode    run in mode:\n" \
	       "                          0 - arpwatch daemon, syslog+mail (DEFAULT)\n" \
	       "                          1 - print reports to stdout, no daemon\n" \
	       "                          2 - print comma-separated to stdout, no daemon\n" \
	       "    -u username       drop privileges to username after opening interface\n"
	       "    -p                do NOT put interface into promisc mode\n" \
	       "    -P \"pcap_filter\"  attach pcap filter; see tcpdump(8) for expressions\n" \
	       "    -n net[/width]    add networks to watch\n" \
               "    -N                do NOT report bogons\n" \
	       "    -f data_file      write arp DB to file instead of default arp.dat\n" \
	       "    -r pcap_dump      read in data from captured pcap file instead of network\n" \
	       "    -t mail_to        send mail reports To:\n" \
	       "    -F mail_from      set mail From: header\n" \
	       "    -s prog           use prog instead of sendmail to send mail\n" \
	      );
	exit(1);
}


static void drop_privileges(const char *user)
{
	struct passwd* pw;
	pw=getpwnam(user);
	if(pw) {
		if( initgroups(pw->pw_name, 0) != 0 ||
		    setgid(pw->pw_gid) != 0 ||
		    setuid(pw->pw_uid) != 0
		  ){
			fprintf(stderr, "%s: could not change to %.32s uid=%d gid=%d; exiting", prog, user,pw->pw_uid, pw->pw_gid);
			exit(1);
		}

	} else {
		fprintf(stderr, "%s: could not find user '%.32s'; exiting\n", prog, user);
		exit(1);
	}

	//syslog(LOG_INFO, "Running as uid=%d gid=%d", getuid(), getgid());
}


static void go_daemon()
{
	pid_t pid;
        int fd;

	pid = fork();
	if(pid < 0) {
		syslog(LOG_ERR, "main fork(): %m");
		exit(1);
	} else if(pid != 0) {
		exit(0);
	}

	close(fileno(stdin));
	close(fileno(stdout));
	close(fileno(stderr));
#ifdef TIOCNOTTY
	fd = open("/dev/tty", O_RDWR);
	if(fd >= 0) {
		ioctl(fd, TIOCNOTTY, 0);
		close(fd);
	}
#else
	setsid();
#endif

}
