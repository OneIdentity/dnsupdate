# dnsupdate
When [Authentication Services](https://www.oneidentity.com/products/authentication-services/) joins a new computer to a domain, it becomes known to the LDAP and Kerberos protocols, but not to DNS. This is because the IP address of the host is not directly under the control of this part of Active Directory.

Although AD comes with a integrated DHCP and DNS servers, some sites run their own DHCP servers, meaning that the leased IP addresses must be communicated to Active Directory's DNS server through another (often manual) means.

The **dnsupdate** tool, provided below, performs just this communication. It automatically and securely informs Active Directory's DNS server of IP address changes of the host due to DHCP lease acquisition and renewal.

Because **dnsupdate** uses Kerberos to authenticate itself to the DNS server, only the computer joined with that name can update its record.

**Dnsupdate** is a small tool with a single purpose: Find the nearest working Active Directory DNS server and securely update the current host's DNS entry.

## Troubleshooting
* [Troubleshooting common problems with Dynamic DNS](wiki/Troubleshooting)
* [How dnsupdate installs itself into the operating system's DHCP client](wiki/DHCP-Installation)
