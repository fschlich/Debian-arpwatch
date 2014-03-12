#ifndef REPORT_H
#define REPORT_H

#define REPORT_NORMAL 0
#define REPORT_STDOUT 1
#define REPORT_RAW 2

enum {
        ACTION_ACTIVITY=0,
        ACTION_NEW,
        ACTION_REUSED,
        ACTION_CHANGED,
        ACTION_FLIPFLOP,
        ACTION_BOGON,
        ACTION_ETHER_BROADCAST,
        ACTION_ETHER_MISMATCH,
        ACTION_ETHER_TOOSHORT,
        ACTION_ETHER_BADFORMAT,
        ACTION_ETHER_WRONGTYPE_IP,
        ACTION_ETHER_BADLENGTH,
        ACTION_ETHER_WRONGOP,
	ACTION_ETHER_WRONGRARP,
	ACTION_ETHER_WRONGTYPE,
};

#define ACTION_MAX ACTION_ETHER_WRONGTYPE

void report(int, u_int32_t, u_char *, u_char *, time_t *, time_t *);
int setup_reportmode(int mode);

#endif
