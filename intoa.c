/* @(#) $Header: intoa.c,v 1.4 96/06/07 20:02:09 leres Exp $ (LBL) */

#include <sys/types.h>

#include <netinet/in.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "arpwatch.h"

/*
 * A faster replacement for inet_ntoa().
 */
char *
intoa(register u_int32_t addr)
{
	register char *cp;
	register u_int byte;
	register int n;
	static char buf[sizeof(".xxx.xxx.xxx.xxx")];

#ifdef NTOHL
	NTOHL(addr);
#else
	addr = ntohl(addr);
#endif
	cp = &buf[sizeof buf];
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	return cp + 1;
}
