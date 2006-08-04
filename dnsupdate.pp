# Polypackage description document
#%pp 1.0

%set
  name="quest-dnsupdate"
  if test -x ./configure; then
    version=`./configure --version | head -n 1 | awk '{print $3}'`
  else
    version='0.0.0'
  fi

  summary="Updates DNS records for DHCP clients"

%files
  /opt/
  /opt/quest/
  /opt/quest/sbin/
  /opt/quest/sbin/dnsupdate
  /opt/quest/man/
  /opt/quest/man/man8/
  /opt/quest/man/man8/dnsupdate.8
  /opt/quest/libexec/
  /opt/quest/libexec/dnsupdate-install-hooks

%if [rpm]
%post
 /opt/quest/libexec/dnsupdate-install-hooks -i linux
%preun
 /opt/quest/libexec/dnsupdate-install-hooks -r linux
%endif

%if [solaris]
%post
 /opt/quest/libexec/dnsupdate-install-hooks -i solaris
%preun
 /opt/quest/libexec/dnsupdate-install-hooks -r solaris
%endif

%if [sd]
%post
 /opt/quest/libexec/dnsupdate-install-hooks -i hpux
%preun
 /opt/quest/libexec/dnsupdate-install-hooks -r hpux
%endif

%if [aix]
%post
 /opt/quest/libexec/dnsupdate-install-hooks -i aix
%preun
 /opt/quest/libexec/dnsupdate-install-hooks -r aix
%endif

# vim: ts=2:sw=2:et
