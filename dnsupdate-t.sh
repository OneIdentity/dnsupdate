#!/bin/sh

WRKDIR=${TMPDIR:-/tmp}/dnsupdate-t$$
mkdir -p $WRKDIR || exit 
cleanup () { if $PASSED_ALL; then rm -rf $WRKDIR; fi; }
#trap 'cleanup' 0

PASSED_ALL=true
GDB=false	    # Wraps dnsupdate in a gdb process
VERBOSE=false	    # Adds -vvvv to server-t

ip=127.0.0.1
iprev="'1.0.0.127.in-addr.arpa"	# leading quote to force a dname
localns=127.0.0.2
domain=example.com
domainrev=127.in-addr.arpa
authns=ns.example.com
authip=127.0.0.3
hostname=host.example.com
hostmaster=hostmaster.example.com
ttl=900

DNS_RESOLV_CONF=$WRKDIR/resolv.conf; export DNS_RESOLV_CONF
cat <<-. >$DNS_RESOLV_CONF
    nameserver $localns
.

# Runs dnsupdate with the given arguments, but wraps it
# in the server-t wrapper which checks outgoing DNS packets
# as described on standard input to this function
test_dnsupdate () {
    set -- ./dnsupdate "$@"
    $GDB && set -- gdb --args "$@"
    set -- -u "$@" ';'
    $GDB && set -- -N "$@"
    $VERBOSE && set -- -vvvv "$@"
    set -- ./server-t "$@"
    while read request; do
	case "$request" in
	    ""|"#"*) :;;
	    *) read response
	       case "$response" in
		   ""|"#"*)  echo "responses must come after request" >&2
		             exit 1;;
		   *) set -- "$@" "$request" "$response";;
	       esac;;
	esac
    done
    $VERBOSE && echo "$@"
    "$@" 0<&1
}

test_dnsupdate -h $hostname $ip <<.
    [$localns]Q:$hostname SOA
    OK::$domain SOA $authns $hostmaster 0:$authns A $authip

    [$authns]U:$domain SOA:$hostname 0 NONE CNAME ~:\
	$hostname 0 ANY A ~,$hostname $ttl IN A $ip
    OK::$hostname 0 NONE CNAME ~:$hostname 0 ANY A ~,$hostname $ttl IN A $ip

    [$localns]Q:$iprev SOA
    OK::$domainrev SOA $authns $hostmaster 0:$authns A $authip

    [$authns]U:$domainrev SOA:$iprev 0 NONE CNAME ~:\
	$iprev 0 ANY PTR ~,$iprev $ttl IN PTR $hostname
    OK::$iprev 0 NONE CNAME ~:\
	$iprev 0 ANY PTR ~,$iprev $ttl IN PTR $hostname
.


$PASSED_ALL
