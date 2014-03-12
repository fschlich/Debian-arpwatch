#ifndef REPORT_H
#define REPORT_H

#define REPORT_NORMAL 0
#define REPORT_STDOUT 1
#define REPORT_RAW 2

#define ACTION_ACTIVITY 0
#define ACTION_NEW 1
#define ACTION_REUSED 2
#define ACTION_CHANGED 3
#define ACTION_FLIPFLOP 4
#define ACTION_MAX ACTION_FLIPFLOP

void report(int, u_int32_t, u_char *, u_char *, time_t *, time_t *);
int setup_reportmode(int mode);

#endif
