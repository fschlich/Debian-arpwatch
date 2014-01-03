#!/bin/sh
# /etc/init.d/arpwatch: v0.05 2001/12/17 KELEMEN Peter <fuji@debian.org>
# Based on /etc/init.d/skeleton (1.8  03-Mar-1998  miquels@cistron.nl)
# 2001/10/26	fuji@debian.org		Support multiple instances.
# 2001/11/24	fuji@debian.org		Use POSIX-style functions.
# 2001/12/17	fuji@debian.org		Use --pidfile on startup, fix restart.

PATH=/sbin:/bin:/usr/sbin:/usr/bin
NAME=arpwatch
DAEMON=/usr/sbin/$NAME
DESC="Ethernet/FDDI station monitor daemon"
DATADIR=/var/lib/$NAME

test -f $DAEMON || exit 0

# Decide if we have to deal with multiple interfaces.
CONF=/etc/arpwatch.conf
MULTIPLE=0
if [ -r $CONF ]; then
	grep -c '^[a-z]' $CONF 2>&1 >/dev/null
	[ $? = 0 ] && MULTIPLE=1
fi
if [ "$MULTIPLE" -gt 0 ]; then
	# Put global args for all instances here:
	ARGS=""
else
	# Debian: don't report bogons, don't use PROMISC.
	ARGS="-N -p"
fi

### You shouldn't touch anything below unless you know what you are doing.

start_instance () {
	IFACE=$1
	INSTANCE=${NAME}-${IFACE}
	IFACE_OPTS="-i ${IFACE} -f ${IFACE}.dat $2"
	DATAFILE=$DATADIR/${IFACE}.dat
	if [ ! -f $DATAFILE ]; then
		echo "N: Creating arpwatch data file $DATAFILE for ${IFACE}."
		:> $DATAFILE
	fi
	echo -n "Starting $DESC: "
	start-stop-daemon --start --quiet \
		--pidfile /var/run/${INSTANCE}.pid \
		--exec $DAEMON -- $IFACE_OPTS $ARGS
	echo "${INSTANCE}."
	ps h -C $NAME -o pid,args | \
		awk "/$IFACE/ { print \$1 }" > /var/run/${INSTANCE}.pid
}

stop_instance () {
	IFACE=$1
	INSTANCE=${NAME}-${IFACE}
	[ -f /var/run/${INSTANCE}.pid ] || return 0
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --oknodo \
		--pidfile /var/run/${INSTANCE}.pid
	echo "${INSTANCE}."
	rm -f /var/run/${INSTANCE}.pid
}

process_loop_break_line () {
	__IFACE=$1
	shift
	__IOPTS="$@"
}

process_loop () {
	OPERATION=$1
	grep '^[a-z]' $CONF 2>/dev/null | \
	while read LINE
	do
		process_loop_break_line $LINE
		I=$__IFACE
		I_OPTS="$__IOPTS"
		$OPERATION $I "$I_OPTS"
	done
}

start_default () {
	echo -n "Starting $DESC: "
	start-stop-daemon --start --quiet \
		--exec $DAEMON -- $ARGS
	echo "$NAME."
}

stop_default () {
	echo -n "Stopping $DESC: "
	start-stop-daemon --stop --quiet --oknodo \
		--exec $DAEMON
	echo "$NAME."
	rm -f /var/run/$NAME.pid
}

startup () {
	if [ "$MULTIPLE" -gt 0 ]; then
  		process_loop start_instance
	else
		start_default
	fi
}

shutdown () {
	if [ "$MULTIPLE" -gt 0 ]; then
		process_loop stop_instance
	else
		stop_default
	fi
}

case "$1" in
  start)
  	startup
	;;
  stop)
  	shutdown
	;;
  reload)
  	echo "Reload operation not supported -- use restart."
	exit 1
	;;
  restart|force-reload)
	#
	#	If the "reload" option is implemented, move the "force-reload"
	#	option to the "reload" entry above. If not, "force-reload" is
	#	just the same as "restart".
	#
	shutdown
	sleep 1
	startup
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
