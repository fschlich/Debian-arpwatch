#include <sys/types.h>

/* strndup() may be useful, but is a GNU extension */
#ifndef HAVE_STRNDUP
char *strndup( const char *s, size_t n )
{
	size_t nAvail;
	char *p;
	if ( !s )
		return 0;
	//  nAvail = min( strlen(s)+1, n+1 );
	nAvail = ((strlen(s)+1) > (n+1)) ? n+1 : strlen(s)+1;
	p      = malloc( nAvail );
	memcpy( p, s, nAvail );
	p[nAvail - 1] = '\0';
	return p;
}
#endif

