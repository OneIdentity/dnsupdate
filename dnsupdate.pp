# Polypackage description document
#%pp 1.0

%set
  name="quest-dnsupdate"
  pp_solaris_name=quest-dnsupdat	# Argh!
  summary="Updates DNS records for DHCP clients"

%files
  /opt/quest/sbin/dnsupdate
  /opt/quest/man/man8/dnsupdate.8
  /opt/quest/libexec/dnsupdate-install-hooks

%set
[rpm]     install_platform=linux
[solaris] install_platform=solaris
[sd]      install_platform=hpux
[aix]     install_platform=aix

%post [rpm,solaris,sd,aix]
 /opt/quest/libexec/dnsupdate-install-hooks -i %{install_platform}
%preun [rpm,solaris,sd,aix]
 /opt/quest/libexec/dnsupdate-install-hooks -r %{install_platform}

# vim: ts=2:sw=2:et
