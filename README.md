# pam_ldapaccess
PAM module to manage login access via specified IPs/domains specified in your local LDAP directory.

The pam_ldapaccess PAM module provides login access control based on IP addresses/IP address ranges/domains/host names specified by a named attribute in your OpenLDAP directory. This attribute is then assigned to users in the LDAP database, and can be assigned as many times as desired per user. IP ranges can be specified in either CIDR or netmask format. Only StartTLS is supported as the connection protocol to the LDAP directory, and your LDAP client file should be /etc/openldap/ldap.conf.
