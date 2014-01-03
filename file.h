/* @(#) $Header: file.h,v 1.3 96/06/04 22:39:48 leres Exp $ (LBL) */

typedef int (*file_process)(u_int32_t, u_char *, time_t, char *);

int file_loop(FILE *, file_process);
