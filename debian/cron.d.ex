#
# Regular cron jobs for the arpwatch package
#
0 4	* * *	root	[ -x /usr/bin/arpwatch_maintenance ] && /usr/bin/arpwatch_maintenance
