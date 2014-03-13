/* @(#) $Header: db.h,v 1.8 96/06/04 22:39:29 leres Exp $ (LBL) */

typedef void (*ent_process)(u_int32_t, u_char *, time_t, char *);

#ifdef	DEBUG
void	debugdump(void);
#endif
int	ent_add(u_int32_t, u_char *, time_t, char *);
int	ent_loop(ent_process);
void	sorteinfo(void);
