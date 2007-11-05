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

%set
[rpm]     install_platform=linux
[solaris] install_platform=solaris
[sd]      install_platform=hpux
[aix]     install_platform=aix
[deb]     install_platform=deb

%post [rpm,solaris,sd,aix,deb]
 %{libexecdir}/dnsupdate-install-hooks -i %{install_platform}
%preun [rpm,solaris,sd,aix,deb]
 %{libexecdir}/dnsupdate-install-hooks -r %{install_platform}

# vim: ts=2:sw=2:et
