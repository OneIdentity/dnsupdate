**One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/ars-ps/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/ars-ps/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.**

# dnsupdate
When [Authentication Services](https://www.oneidentity.com/products/authentication-services/) joins a new computer to a domain, it becomes known to the LDAP and Kerberos protocols, but not to DNS. This is because the IP address of the host is not directly under the control of this part of Active Directory.

Although AD comes with a integrated DHCP and DNS servers, some sites run their own DHCP servers, meaning that the leased IP addresses must be communicated to Active Directory's DNS server through another (often manual) means.

The **dnsupdate** tool, provided below, performs just this communication. It automatically and securely informs Active Directory's DNS server of IP address changes of the host due to DHCP lease acquisition and renewal.

Because **dnsupdate** uses Kerberos to authenticate itself to the DNS server, only the computer joined with that name can update its record.

**Dnsupdate** is a small tool with a single purpose: Find the nearest working Active Directory DNS server and securely update the current host's DNS entry.

## Supported Platforms
All Authentication Services Supported Platforms

## Troubleshooting
* [Troubleshooting common problems with Dynamic DNS](https://github.com/OneIdentity/dnsupdate/wiki/Troubleshooting)
* [How dnsupdate installs itself into the operating system's DHCP client](https://github.com/OneIdentity/dnsupdate/wiki/DHCP-Installation)
