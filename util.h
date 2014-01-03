/* @(#) $Header: util.h,v 1.2 96/10/06 03:22:13 leres Exp $ (LBL) */

void	dosyslog(int, char *, u_int32_t, u_char *, u_char *);
int	dump(void);
void	dumpone(u_int32_t, u_char *, time_t, char *);
int	readdata(void);
char	*savestr(const char *);

extern char *arpdir;
extern char *newarpfile;
extern char *arpfile;
extern char *oldarpfile;
extern char *ethercodes;

extern u_char zero[6];
extern u_char allones[6];

extern int debug;
extern int initializing;
