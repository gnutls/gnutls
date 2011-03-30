fail() {
   echo "Failure: $1" >&2
   exit 1
}

launch_server() {
       PARENT=$1;
       shift;
       $SERV $DEBUG -p $PORT $* >/dev/null 2>&1 &
       LOCALPID="$!";
       trap "[ ! -z \"${LOCALPID}\" ] && kill ${LOCALPID};" 15
       wait "${LOCALPID}"
       LOCALRET="$?"
       if [ "${LOCALRET}" != "0" -a "${LOCALRET}" != "143" ] ; then
               # Houston, we'v got a problem...
               echo "Failed to launch a gnutls-serv server !"
               kill -10 ${PARENT}
       fi
}

wait_server() {
	trap "kill $1" 1 15 2
	sleep 2
}

trap "fail \"Failed to launch a gnutls-serv server, aborting test... \"" 10 
