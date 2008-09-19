#!/bin/sh

XLATOR="./quest-dnsupdate-xlator -test"
WRKTMP=${TMPDIR:-/tmp}/.xlator-t$$

mkdir -p $WRKTMP
#trap 'rm -rf $WRKTMP' 0
VERBOSE=false
PASSED_ALL=true

# XXX tests go here

verbose () { $VERBOSE && echo "$*"; :; }
start () { TESTNAME="$*"; }
result () { if test $? = 0; then pass; else fail; fi; }
invert () { test $? != 0; "$@"; }
pass () { echo " ok  $TESTNAME"; }
fail () { echo "FAIL $TESTNAME"; PASSED_ALL=false; }

#-- runs the given command, and returns true if the here-document on
#   file descriptor 3 matches the output from the given command
check () {
    expected_ec=0
    case $1 in -exit) shift; expected_ec=$1; shift;; esac

    cat <&3 > $WRKTMP/expected
    "$@" > $WRKTMP/out; ec=$?

    if test $ec != $expected_ec; then
	echo "unexpected exit code from '$*'" >&2
        echo "   was $ec, expected $expected_ec" >&2
	return 1
    fi

    if cmp -s $WRKTMP/expected $WRKTMP/out; then
	:
    else
	{ echo "unexpected output from '$*'" 
	  echo "-----  actual output:" 
	  cat $WRKTMP/out
	  echo "-----  expected output:" 
	  cat $WRKTMP/expected
	} >&2
	return 1
    fi
    return 0
}

cat <<-. > $WRKTMP/input
Software\Policies\Microsoft\Windows NT\DNSClient;RegistrationEnabled;REG_DWORD;1
Software\Policies\Microsoft\Windows NT\DNSClient;RegisterReverseLookup;REG_DWORD;2
Software\Policies\Microsoft\Windows NT\DNSClient;RegistrationOverwritesInConflict;REG_DWORD;0
Software\Policies\Microsoft\Windows NT\DNSClient;RegistrationTtl;REG_DWORD;600
Software\Policies\Microsoft\Windows NT\DNSClient;UpdateSecurityLevel;REG_DWORD;0
Software\Policies\Microsoft\Windows NT\DNSClient;UpdateTopLevelDomainZones;REG_DWORD;0
.

start "info"
$XLATOR info >/dev/null </dev/null
result

start "badarg"
$XLATOR badarg >/dev/null </dev/null 2>&1
invert result

start "keys"
check $XLATOR keys </dev/null 3<<'.'
Software\Policies\Microsoft\Windows NT\DNSClient
.
result

CONF=/tmp/dnsupdate.conf

start "init from empty"
rm -f $CONF &&
check $XLATOR init </dev/null 3</dev/null && 
test ! -f $CONF
result

start "apply"
check $XLATOR <$WRKTMP/input 3</dev/null &&
check cat $CONF 3<<'.'
#--VGP BEGIN--#
RegisterReverseLookup = 2
RegistrationEnabled = 1
RegistrationOverwritesInConflict = 0
RegistrationTtl = 600
UpdateSecurityLevel = 0
UpdateTopLevelDomainZones = 0
#--VGP END--#
.
result

start "init to empty"
check $XLATOR init </dev/null 3</dev/null && 
test ! -f $CONF
result

cat <<. >$CONF
# Some random existing conf file
Foo = 1 2 3
UpdateSecurityLevel = 99999

.

start "apply existing"
cp $CONF $WRKTMP/orig.conf
cp $WRKTMP/orig.conf $WRKTMP/expect.conf
cat >>$WRKTMP/expect.conf <<-.
#--VGP BEGIN--#
RegisterReverseLookup = 2
RegistrationEnabled = 1
RegistrationOverwritesInConflict = 0
RegistrationTtl = 600
UpdateSecurityLevel = 0
UpdateTopLevelDomainZones = 0
#--VGP END--#
.
check $XLATOR <$WRKTMP/input 3</dev/null &&
check cat $CONF 3<$WRKTMP/expect.conf
result

start "init existing"
check $XLATOR init </dev/null 3</dev/null && 
check cat $CONF 3<$WRKTMP/orig.conf
result

$PASSED_ALL # must be last line
