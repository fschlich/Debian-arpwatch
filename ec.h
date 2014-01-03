/* @(#) $Header: ec.h,v 1.7 96/06/04 22:39:24 leres Exp $ (LBL) */

typedef int (*ec_process)(u_int32_t, char *);

char	*e2str(u_char *);
int	ec_add(u_int32_t, char *);
char	*ec_find(u_char *);
int	ec_loop(FILE *, ec_process);
int	isdecnet(u_char *);
u_char	*str2e(char *);
