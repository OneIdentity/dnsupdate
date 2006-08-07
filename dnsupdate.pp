# Polypackage description document
#%pp 1.0

%set
  name="quest-dnsupdate"
  pp_solaris_name=quest-dnsupdat	# Argh!
  if test -x ./configure; then
    version=`./configure --version | head -n 1 | awk '{print $3}'`
  else
    version='0.0.0'
  fi

  summary="Updates DNS records for DHCP clients"

%files
  /opt/quest/sbin/dnsupdate
  /opt/quest/man/man8/dnsupdate.8
  /opt/quest/libexec/dnsupdate-install-hooks

%post [rpm]
 /opt/quest/libexec/dnsupdate-install-hooks -i linux
%preun [rpm]
 /opt/quest/libexec/dnsupdate-install-hooks -r linux

%post [solaris]
 /opt/quest/libexec/dnsupdate-install-hooks -i solaris
%preun [solaris]
 /opt/quest/libexec/dnsupdate-install-hooks -r solaris

%post [sd]
 /opt/quest/libexec/dnsupdate-install-hooks -i hpux
%preun [sd]
 /opt/quest/libexec/dnsupdate-install-hooks -r hpux

%post [aix]
 /opt/quest/libexec/dnsupdate-install-hooks -i aix
%preun [aix]
 /opt/quest/libexec/dnsupdate-install-hooks -r aix

# vim: ts=2:sw=2:et
