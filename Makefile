CC=gcc
CFLAGS=-Wall -m64 -fPIC -shared -rdynamic -o pam_ldapaccess.so pam_ldapaccess.c -lldap -lpam
STRIP=/usr/bin/strip

all: pam_ldapaccess.so

pam_ldapaccess.so: pam_ldapaccess.c
	$(CC) $(CFLAGS)
	${STRIP} pam_ldapaccess.so 

install: pam_ldapaccess.so
	cp -vp pam_ldapaccess.so /lib64/security/

uninstall:
	rm -f /lib64/security/pam_ldapaccess.so

clean:
	rm -f pam_ldapaccess.so 
