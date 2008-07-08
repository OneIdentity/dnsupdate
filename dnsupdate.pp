# Polypackage description document
#%pp 1.0

%set
  name="quest-dnsupdate"
  pp_solaris_name=QSFTdnsup
  summary="Updates Dynamic DNS"

%files
  $sbindir/dnsupdate
  $man8dir/dnsupdate.8
  $libexecdir/dnsupdate-install-hooks

%files [macos]
  $sbindir/ipwatchd
  $man8dir/ipwatchd.8
  $datadir/ipwatchd/
  $datadir/ipwatchd/com.quest.rc.ipwatchd.plist

%post
 %{libexecdir}/dnsupdate-install-hooks -i ${pp_platform}
%preun
 %{libexecdir}/dnsupdate-install-hooks -r ${pp_platform}
