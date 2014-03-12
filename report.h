#ifndef REPORT_H
#define REPORT_H

#define REPORT_NORMAL 0
#define REPORT_STDOUT 1


/* the reporting function pointer */
extern void (*report)(char *, u_int32_t, u_char *, u_char *, time_t *, time_t *);

void report_orig(char *, u_int32_t, u_char *, u_char *, time_t *, time_t *);
void report_stdout(char *, u_int32_t, u_char *, u_char *, time_t *, time_t *);
void report_dotted(char *, u_int32_t, u_char *, u_char *, time_t *, time_t *);

#endif
