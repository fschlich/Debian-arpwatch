/* @(#) $Header: arpwatch.h,v 1.28 98/02/09 16:35:15 leres Exp $ (LBL) */

#define ARPFILE "arp.dat"

/* 1999-04-12	KELEMEN Peter <fuji@debian.org> */
/*	See Makefile.in for ETHERCODES definition. */
/* #define ETHERCODES "ethercodes.dat" */
#define CHECKPOINT (15*60)		/* Checkpoint time in seconds */

#define MEMCMP(a, b, n) memcmp((char *)a, (char *)b, n)
#define BCOPY(a, b, n) bcopy((char *)a, (char *)b, n)
#define MEMSET(s, c, n) memset((char *)s, c, n)

char	*intoa(u_int32_t);

#ifndef HAVE_BCOPY
void bcopy(const void *, void *, size_t);
#endif

extern char *prog;

#ifdef ETHER_HEADER_HAS_EA
#define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
#else
#define ESRC(ep) ((ep)->ether_shost)
#define EDST(ep) ((ep)->ether_dhost)
#endif

#ifdef ETHER_ARP_HAS_X
#define SHA(ap) ((ap)->arp_xsha)
#define THA(ap) ((ap)->arp_xtha)
#define SPA(ap) ((ap)->arp_xspa)
#define TPA(ap) ((ap)->arp_xtpa)
#else
#ifdef ETHER_ARP_HAS_EA
#define SHA(ap) ((ap)->arp_sha.ether_addr_octet)
#define THA(ap) ((ap)->arp_tha.ether_addr_octet)
#else
#define SHA(ap) ((ap)->arp_sha)
#define THA(ap) ((ap)->arp_tha)
#endif
#define SPA(ap) ((ap)->arp_spa)
#define TPA(ap) ((ap)->arp_tpa)
#endif
