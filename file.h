/* @(#) $Header: file.h,v 1.4 99/01/17 17:46:03 leres Exp $ (LBL) */

typedef int (*file_process)(u_int32_t, u_char *, time_t, char *);

int file_loop(FILE *, file_process, const char *);
