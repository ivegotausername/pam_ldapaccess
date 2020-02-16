/* 
 * pam_ldapaccess - PAM module to allow access via hosts/domains/IPs specified in local
 * LDAP directory. Currently only supports StartTLS for LDAP queries.
 * Author Ian Shore (ian.shore@kaust.edu.sa)
 * Most of this code has been recycled from other PAM modules, most notably pam_access, 
 * credit due to Alexei Nogin and Wietse Venema.
 *
 * I don't do much C coding, can you tell?
 * With thanks to Greg and Jens, for supplying me with bits of neat code when I was
 * struggling.
*/
/*
 * Version 0.11
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>   
#include <netinet/in.h> 
#include <ctype.h>

// Include PAM headers
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

//Define which PAM interfaces we provide. In this case we are
//only going to provide an account interface, i.e. one
//that decides if a login in allowed or not, *after* authentication
//Many programs will interpret a 'DENY' result here to mean that the
//account has expired, so expect to see that in your logs
#define PAM_SM_ACCOUNT

// We do not supply these
/*
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
*/

#define LDAP_FILE "/etc/openldap/ldap.conf"
#define SETTINGS_FILE "/etc/security/pam_ldapaccess.conf"
#define MAX_SIZE 512

#if !defined(MAXHOSTNAMELEN) || (MAXHOSTNAMELEN < 64)
#undef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif
#define YES             1
#define NO              0

int debug = NO;
char ldapmail[MAX_SIZE];
const char *intmessage="/etc/pam_ldapaccess.message", *extmessage="/etc/pam_ldapaccess.message";

/* Parse module config arguments */
static int parse_args(pam_handle_t *pamh, int argc, const char **argv)
{
  int i;
  for (i=0; i<argc; ++i) 
  {
    if (strcmp(argv[i], "debug") == 0) 
       debug = YES;
    else if (!strncasecmp("intmessage=", argv[i], 10))
       intmessage=argv[i]+11;
    else if (!strncasecmp("extmessage=", argv[i], 10)) 
       extmessage=argv[i]+11;
    else
      syslog( LOG_ERR, "pam_ldapaccess: Unrecognized option [%s]", argv[i]);
  }  
  if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Internal message file [%s] external message file [%s]",intmessage, extmessage);
  return YES;
}

/* Read the server URI and base from the OpenLDAP client file */
int LoadLDAPSettings(const char *ldap_file, char ***uri_ptr, char **base )
{
  FILE *iptr;
  char **uris = malloc( sizeof( char * ) );
  uris[0] = NULL;
  size_t uris_len = 0;

  if ((iptr=fopen(ldap_file,"r")) == NULL)
  {   
    syslog( LOG_ERR, "pam_ldapaccess: Unable to open file %s.",ldap_file );
    return NO;  
  }

  char line[ MAX_SIZE ];
  while ( fgets( line, sizeof( line ), iptr ) != NULL ) {
      size_t len = strlen( line );
      while (( len > 0 )&&( isspace( line[ len - 1 ] ) ) ) {
  	 len --;
  	 line[ len ] = '\0';
      }
      const char *ptr = line;
      while ( isspace( *ptr ) ) {
          ptr ++;
      }
      if (( strncmp( ptr, "URI", 3 ) == 0 )&&( isspace( ptr[ 3 ] ))) {
          /* matched */
	  ptr += 3;
          while ( *ptr ) {
		while ( isspace( *ptr ) ) {
		    ptr ++;
		}
		if ( ! *ptr ) {
		    break;
		}
    		int ctr;
		for ( ctr = 0 ; ptr[ ctr ] && ( ! isspace( ptr[ ctr ] )) ; ctr ++ ) {
		/* ctr = length of bytes */
		}
		uris_len ++;
		uris = (char**)realloc( uris, sizeof( char * ) * ( uris_len + 1 ) );
		uris[ uris_len - 1 ] = strndup( ptr, ctr );
		uris[ uris_len ] = NULL;
        	if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: URI [%s]", uris[ uris_len - 1 ] );
		/* skip past the copied text */
		ptr += ctr;
          }
    }  else if (( strncmp( ptr, "BASE", 4 ) == 0 )&&( isspace( ptr[ 4 ] ))) {
	/* matched */
	ptr += 4;
	while ( isspace( *ptr ) ) {
	    ptr ++;
	}
	*base = strdup( ptr );
        if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: BASE [%s]", *base );
      }
  } 
  fclose(iptr);

  if ( *base == NULL || uris[0] == NULL ) {
    return NO;
  } else {
    *uri_ptr = uris;
    return YES;
  }
}

/* Read the contents of a file and return the contents */
char* ReadFile(const char *filename)
{
   char *buffer = NULL;
   int string_size, read_size;
   FILE *handler = fopen(filename, "r");

   if (handler)
   {
       // Seek the last byte of the file
       fseek(handler, 0, SEEK_END);
       // Offset from the first to the last byte, or in other words, filesize
       string_size = ftell(handler);
       // go back to the start of the file
       rewind(handler);

       // Allocate a string that can hold it all
       buffer = (char*) malloc(sizeof(char) * (string_size + 1) );

       // Read it all in one operation
       read_size = fread(buffer, sizeof(char), string_size, handler);

       // fread doesn't set it so put a \0 in the last position
       // and buffer is now officially a string
       buffer[string_size] = '\0';

       if (string_size != read_size)
       {
           // Something went wrong, throw away the memory and set
           // the buffer to NULL
           free(buffer);
           buffer = NULL;
       }

       // Always remember to close the file.
       fclose(handler);
    }

    return buffer;
}

/* Compare the pam_rhost domain with domain specified in LDAP */
bool domain_grep(const char* ref, const char* sub)
{

       if (ref == 0 || sub == 0) return false;
        const char* substr = sub;
        if (sub[0]=='.') substr = sub+1;

       int ref_len = strlen(ref)-1;
       int sub_len = strlen(substr)-1;

       while (ref_len >= 0 && sub_len >= 0) 
       {
              if (ref[ref_len--] != substr[sub_len--]) return false;
       }

       if (ref_len >= 0) return ref[ref_len] == '.' || ref[ref_len] == '@';

       return (sub_len ==-1);

}

/*  Get the ip address of a given hostname  */
int hostname_to_ip(const char *hostname, char *ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        herror("gethostbyname");
        return NO;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return YES;
    }
     
    return YES;
}


/* Perform a whois query to a server and record the response */
int whois_query(char *server , char *query , char **response)
{
    char ip[32] , message[100] , buffer[1500];
    int sock , read_size , total_size = 0;
    struct sockaddr_in dest;

    sock = socket(AF_INET , SOCK_STREAM , IPPROTO_TCP);

    //Prepare connection structures :)
    memset( &dest , 0 , sizeof(dest) );
    dest.sin_family = AF_INET;

    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Resolving [%s]", server);
    if (hostname_to_ip(server, ip) != YES)
    {
        if (debug == YES) syslog( LOG_ERR, "pam_ldapaccess: Failed converting [%s] to ip [%s]", server, ip);
        return NO;
    }
    printf("%s" , ip);
    dest.sin_addr.s_addr = inet_addr( ip );
    dest.sin_port = htons( 43 );

    //Now connect to remote server
    if(connect( sock , (const struct sockaddr*) &dest , sizeof(dest) ) < 0)
    {
        syslog( LOG_ERR, "pam_ldapaccess: connect to remote whois server failed");
        return NO;
    }

    //Now send some data or message
    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Querying for [%s]", query);
    sprintf(message , "%s\r\n" , query);
    if( send(sock , message , strlen(message) , 0) < 0)
    {
        syslog( LOG_ERR, "pam_ldapaccess: whois send failed");
        return NO;
    }

    //Now receive the response
    while( (read_size = recv(sock , buffer , sizeof(buffer) , 0) ) )
    {
        *response = realloc(*response , read_size + total_size);
        if(*response == NULL)
        {
            syslog( LOG_ERR, "pam_ldapaccess: whois response failed");
            return NO;
        }
        memcpy(*response + total_size , buffer , read_size);
        total_size += read_size;
    }
    fflush(stdout);

    *response = realloc(*response , total_size + 1);
    *(*response + total_size) = '\0';

    close(sock);
    return YES;
}

/* Get the whois content of an ip by selecting the correct server */
int get_whois(char *ip , char **data)
{
    char *wch = NULL, *pch , *response = NULL;

    if (whois_query("whois.iana.org" , ip , &response) != YES )
    {
       syslog(LOG_ERR, "pam_ldapaccess: whois.iana.org query failed, ip [%s] response [%s]", ip, response);
       return NO;
    }

    pch = strtok(response , "\n");

    while(pch != NULL)
    {
        //Check if whois line
        wch = strstr(pch , "whois.");
        if(wch != NULL)
        {
            break;
        }

        //Next line please
        pch = strtok(NULL , "\n");
    }

    if(wch != NULL)
    {
        if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Whois server is [%s]", wch);
        if (whois_query(wch , ip , data) != YES)
        {
           syslog(LOG_ERR, "pam_ldapaccess: Whois query failed, wch [%s] ip [%s] response [%s]", wch, ip, response);
           return NO;
        }
    }
    else
    {
        *data = malloc(100);
        strcpy(*data , "No whois data");
    }

    return YES;
}


/* isipaddr - find out if string provided is an IP address or not */
static int isipaddr (const char *string, int *addr_type, struct sockaddr_storage *addr)
{
  struct sockaddr_storage local_addr;
  int is_ip;

 /* We use struct sockaddr_storage addr because
    struct in_addr/in6_addr is an integral part
    of struct sockaddr and we doesn't want to
    use its value.
 */

  if (addr == NULL)
    addr = &local_addr;

  memset(addr, 0, sizeof(struct sockaddr_storage));

  /* first ipv4 */
  if (inet_pton(AF_INET, string, addr) > 0)
    {
      if (addr_type != NULL)
    *addr_type = AF_INET;

      is_ip = YES;
    }
  else if (inet_pton(AF_INET6, string, addr) > 0)
    { /* then ipv6 */
      if (addr_type != NULL) {
    *addr_type = AF_INET6;
      }
      is_ip = YES;
    }
  else
    is_ip = NO;

  return is_ip;
}

/* are_addresses_equal - translate IP address strings to real IP
   addresses and compare them to find out if they are equal.
   If netmask was provided it will be used to focus comparation to
   relevant bits.
*/
static int are_addresses_equal (const char *ipaddr0, const char *ipaddr1, const char *netmask)
{
  struct sockaddr_storage addr0;
  struct sockaddr_storage addr1;
  int addr_type0 = 0;
  int addr_type1 = 0;

  if (isipaddr (ipaddr0, &addr_type0, &addr0) == NO)
    return NO;

  if (isipaddr (ipaddr1, &addr_type1, &addr1) == NO)
    return NO;

  if (addr_type0 != addr_type1)
    /* different address types */
    return NO;

  if (netmask != NULL) {
    /* Got a netmask, so normalize addresses? */
    struct sockaddr_storage nmask;
    unsigned char *byte_a, *byte_nm;

    memset(&nmask, 0, sizeof(struct sockaddr_storage));
    if (inet_pton(addr_type0, netmask, (void *)&nmask) > 0) {
      unsigned int i;
      byte_a = (unsigned char *)(&addr0);
      byte_nm = (unsigned char *)(&nmask);
      for (i=0; i<sizeof(struct sockaddr_storage); i++) {
        byte_a[i] = byte_a[i] & byte_nm[i];
      }

      byte_a = (unsigned char *)(&addr1);
      byte_nm = (unsigned char *)(&nmask);
      for (i=0; i<sizeof(struct sockaddr_storage); i++) {
        byte_a[i] = byte_a[i] & byte_nm[i];
      }
    }
  }

  /* Are the two addresses equal? */
  if (memcmp((void *)&addr0, (void *)&addr1,
              sizeof(struct sockaddr_storage)) == 0) {
    return(YES);
  }

  return(NO);
}

/* Change  number into a netmask */
static char * number_to_netmask (long netmask, int addr_type, char *ipaddr_buf, size_t ipaddr_buf_len)
{
  /* We use struct sockaddr_storage addr because
   * struct in_addr/in6_addr is an integral part
   * of struct sockaddr and we doesn't want to
   * use its value.
  */
  struct sockaddr_storage nmask;
  unsigned char *byte_nm;
  const char *ipaddr_dst = NULL;
  int i, ip_bytes;

  if (netmask == 0) {
    /* mask 0 is the same like no mask */
    return(NULL);
  }

  memset(&nmask, 0, sizeof(struct sockaddr_storage));
  if (addr_type == AF_INET6) {
    /* ipv6 address mask */
    ip_bytes = 16;
  } else {
    /* default might be an ipv4 address mask */
    addr_type = AF_INET;
    ip_bytes = 4;
  }

  byte_nm = (unsigned char *)(&nmask);
  /* translate number to mask */
  for (i=0; i<ip_bytes; i++) {
    if (netmask >= 8) {
      byte_nm[i] = 0xff;
      netmask -= 8;
    } else
    if (netmask > 0) {
      byte_nm[i] = 0xff << (8 - netmask);
      break;
    } else
    if (netmask <= 0) {
      break;
    }
  }

  /* now generate netmask address string */
  ipaddr_dst = inet_ntop(addr_type, &nmask, ipaddr_buf, ipaddr_buf_len);
  if (ipaddr_dst == ipaddr_buf) {
    return (ipaddr_buf);
  }

  return (NULL);
}


/* network_netmask_match - match a string against one token
   where string is a hostname or ip (v4,v6) address and tok
   represents either a single ip (v4,v6) address or a network/netmask
*/
static int network_netmask_match (const char *tok, const char *string)
{
    char *netmask_ptr;
    char netmask_string[MAXHOSTNAMELEN + 1];
    int addr_type;
    int gai_rv=0;               /* Cached retval of getaddrinfo */
    struct addrinfo *res;       /* Cached DNS resolution of from */

    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Starting network_netmask_match. Tok is [%s], string is [%s]", tok,string );
    /* OK, check if tok is of type addr/mask */
    if ((netmask_ptr = strchr(tok, '/')) != NULL)
    {
      /* YES */
      long netmask = 0;

      *netmask_ptr = 0;
      netmask_ptr++;

      if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Starting isipaddr 1 - checking if [%s] is an IP address", tok);
      if (isipaddr(tok, &addr_type, NULL) == NO)
      { /* no netaddr */
          return NO;
      }

      /* check netmask */
      if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Starting isipaddr 2 - checking if [%s] is an IP address", netmask_ptr );
      if (isipaddr(netmask_ptr, NULL, NULL) == NO)
      { /* netmask as integer value */
          char *endptr = NULL;
          netmask = strtol(netmask_ptr, &endptr, 0);
          if ((endptr == NULL) || (*endptr != '\0'))
          { /* invalid netmask value */
            return NO;
          }
          if ((netmask < 0) || (netmask >= 128))
          { /* netmask value out of range */
            return NO;
          }

          netmask_ptr = number_to_netmask(netmask, addr_type, netmask_string, MAXHOSTNAMELEN);
        }
    }
    /* NO, then check if it is only an addr */
    else if (isipaddr(tok, NULL, NULL) != YES)
    {
       if (debug == YES) syslog( LOG_ERR, "pam_ldapaccess: isipaddr 3 reckons [%s] is not an IP address", tok );
       return NO;
    }

    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Starting isipaddr 4 - checking if string [%s] is an IP address",string );
    if (isipaddr(string, NULL, NULL) != YES)
    {
      /* Assume network/netmask with a name of a host.  */
      struct addrinfo hint;

      memset (&hint, '\0', sizeof (hint));
      hint.ai_flags = AI_CANONNAME;
      hint.ai_family = AF_UNSPEC;

      if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Checking gai_rv - Value is [%d]", gai_rv );
      if (gai_rv != 0)
      {
          if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Not equal to zero " );
          return NO;
      }
      else if (!res && (gai_rv = getaddrinfo (string, NULL, &hint, &res)) != 0)
      {
          if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Failed when running getaddrinfo" );
          return NO;
      }
      else
      {

         char buf[INET6_ADDRSTRLEN];
         if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Converting hostname to IP address" );

         if (hostname_to_ip(string, buf) != YES)
         {
           if (debug == YES) syslog( LOG_ERR, "pam_ldapaccess: FAILED to convert hostname to IP address" );
           return NO;
         }
         if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Running are_addresses_equal 1 - buf [%s] tok [%s] netmask_ptr [%s]", buf, tok, netmask_ptr );
         if (are_addresses_equal(buf, tok, netmask_ptr))
         {
            return YES;
         }
      } 
    } 
    else
    {
      if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Running are_addresses_equal 2 - string [%s] tok [%s] netmask_ptr [%s]", string, tok, netmask_ptr  );
      return (are_addresses_equal(string, tok, netmask_ptr));
    } 

  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Ending network_netmask_match" );
  return NO;
}

/* Query the LDAP server for the user's allowed IP addresses/domains/ranges, and find their email address */
int ldapIPcheck( const char *PamUser, const char *PamRhost, const char *LdapIPattr )
{
  LDAP *ld;
  LDAPMessage *search_result, *current_entry;

  char **vals, uidstring[24], initstring[MAX_SIZE], **uristring = NULL, *basestring = NULL;
  int version, rc, i=0, ret, PamResult=PAM_PERM_DENIED;
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Starting ldapIPcheck" );

  if ((ret = LoadLDAPSettings(LDAP_FILE, &uristring, &basestring )) != YES) {
    syslog( LOG_ERR, "pam_ldapaccess: Missing URI or BASE in ldap config file." );
    return(PamResult);
  }
  strcpy(initstring, uristring[i]);
  for (i=1; uristring[i] != NULL; i++) {
        strcat(initstring, ",");
        strcat(initstring, uristring[i]);
     }
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: initstring is [%s]", initstring);

  /* Use i to determine whether or not the user exists at all in LDAP records. */
  i=-1;

  /* Initialize the LDAP library and open a connection to an LDAP server */
  if ((ret = ldap_initialize(&ld, initstring)) != LDAP_SUCCESS)
  { 
    syslog( LOG_ERR, "pam_ldapaccess: Failed to initialise with the LDAP Server.");
    PamResult=PAM_CONV_ERR;
    return(PamResult); 
  }
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Opened a connection to the LDAP server." );

  /* For TPF, set the client to an LDAPv3 client. */
  version = LDAP_VERSION3;
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Setting the client to LDAPv3 client." );
  ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ); 

  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Binding to the LDAP server" );
  /* Bind to the server. */
  //rc = ldap_simple_bind_s( ld, NULL, NULL );
  rc = ldap_start_tls_s( ld, NULL, NULL );
  if ( rc != LDAP_SUCCESS ) 
  { 
    syslog( LOG_ERR, "pam_ldapaccess: Could not bind to LDAP server [%s]", initstring );
    PamResult=PAM_CONV_ERR;
    return(PamResult); 
  }
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Successfully bound to the LDAP server" );

  strcpy(uidstring, "(uid=");
  strcat(uidstring, PamUser);
  strcat(uidstring, ")");
  
  if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Search string is %s", uidstring );

  /* Perform the LDAP search */
  rc = ldap_search_ext_s( ld, basestring, LDAP_SCOPE_SUBTREE, uidstring, NULL, 0, NULL, NULL, NULL, 0, &search_result );

  if ( rc != LDAP_SUCCESS )
  { 
    if (debug == YES) syslog( LOG_ERR, "pam_ldapaccess: Failed to connect to LDAP server.");
    PamResult=PAM_CONV_ERR;
    return(PamResult);
  }

  for (current_entry = ldap_first_entry(ld, search_result); current_entry != NULL; current_entry = ldap_next_entry(ld, current_entry)) 
  {
    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: Searching for IPrange values" );
    if (( vals = ldap_get_values( ld, current_entry, LdapIPattr )) != NULL ) 
    {
      for (i=0; vals[i] != NULL; i++) 
      {
        if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: user=[%s] rhost=[%s] IPrange[%s]", PamUser, PamRhost, vals[i] );
        if (domain_grep(PamRhost, vals[i]))
        {
           syslog( LOG_NOTICE, "pam_ldapaccess: user=[%s] rhost=[%s] IPrange[%s] STRING MATCH FOUND!!!", PamUser, PamRhost, vals[i] );
           PamResult=PAM_SUCCESS;
           break;
        }
        else if (network_netmask_match(vals[i], PamRhost))
        {
           syslog( LOG_NOTICE, "pam_ldapaccess: user=[%s] rhost=[%s] IPrange[%s] IP FOUND!!!", PamUser, PamRhost, vals[i] );
           PamResult=PAM_SUCCESS;
           break;
        }
      }
      ldap_memfree(vals);
    }
    else 
    {
      syslog( LOG_ERR, "pam_ldapaccess: Failed to return any search result for IP address.");
    }
    if (( vals = ldap_get_values( ld, current_entry, "mail" )) != NULL )
    {
      for (i=0; vals[i] != NULL; i++)
      {
        if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: user=[%s] rhost=[%s] mail=[%s]", PamUser, PamRhost, vals[i] ); 
        strncpy(ldapmail, vals[i], strlen(vals[i])+1);
      }
      ldap_memfree(vals);
    }
    else 
    {
      syslog( LOG_ERR, "pam_ldapaccess: Failed to return any search result for mail address.");
    }
  }
 
  /* If User is not in LDAP database at all, assume success. */
  if ( i == -1 ) {
    if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: User not found in LDAP database. Must be internal." );
    PamResult=PAM_SUCCESS;
  }

  ldap_msgfree(search_result);

  /* Disconnect from the server. */
  ldap_unbind( ld );

  return(PamResult);
}


// PAM entry point for 'account management'. This decides whether a user
// who has already been authenticated by pam_sm_authenticate should be
// allowed to log in (it considers other things than the users password)
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        int PamResult=PAM_IGNORE;
        //These are defined as 'const char' because they passed to us from the parent
        //library. When we called pam_get_<whatever> the pam library passes pointers
        //to strings in its own code. Thus we must not change or free them
        const char *pam_user = NULL, *pam_rhost = NULL, *pam_service = NULL;
        char pam_ip[INET6_ADDRSTRLEN];
        int i=0;
  
        if (pam_get_item(pamh, PAM_SERVICE, (const void **) &pam_service) != PAM_SUCCESS)
        {
                        openlog("pam_ldapaccess",0,LOG_AUTH);
                        syslog(LOG_ERR, "pam_ldapaccess: Failed to get pam_service");
                        closelog();
                        return(PAM_IGNORE);
        }

        //get the user. If something goes wrong we return PAM_IGNORE. This tells
        //pam that our module failed in some way, so ignore it. Perhaps we should
        //return PAM_PERM_DENIED to deny login, but this runs the risk of a broken
        //module preventing anyone from logging into the system!
        if ((pam_get_user(pamh, &pam_user, NULL) != PAM_SUCCESS) || (pam_user == NULL))
        {
                        openlog(pam_service,0,LOG_AUTH);
                        syslog(LOG_ERR, "pam_ldapaccess: Failed to get pam_user");
                        closelog();
                        return(PAM_IGNORE);
        }

        if (pam_get_item(pamh, PAM_RHOST, (const void **) &pam_rhost) != PAM_SUCCESS)
        {
                        openlog(pam_service,0,LOG_AUTH);
                        syslog(LOG_ERR, "pam_ldapaccess: Failed to get pam_rhost");
                        closelog();
                        return(PAM_IGNORE);
        }

        syslog(LOG_NOTICE, "pam_ldapaccess: user=[%s] rhost=[%s]",pam_user, pam_rhost);
        
        if (!parse_args(pamh, argc, argv)) 
        {
           syslog(LOG_ERR, "pam_ldapaccess: Failed to parse the module arguments");
           return PAM_ABORT;
        }

        if (isipaddr(pam_rhost, NULL, NULL) == YES)
        {
          strncpy(pam_ip,pam_rhost,strlen(pam_rhost)+1);
        }
        else
          if (hostname_to_ip(pam_rhost,pam_ip) != YES)
          { 
            syslog(LOG_ERR, "pam_ldapaccess: Failed to find the client IP address.");
            return PAM_ABORT;
          }
    
        if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Client IP address is [%s]", pam_ip); 

        char adminmail[MAX_SIZE] = "root", systemname[MAX_SIZE] = "system", *internalrange[4], 
             ldapipattr[MAX_SIZE] = "networkAddress", localdomain[MAX_SIZE] = "example.com", word[MAX_SIZE], 
              line[MAX_SIZE];
        FILE *iptr;

        memset(word,0,sizeof(word));
        memset(line,0,sizeof(line));
        internalrange[0] = NULL;

        if (debug ==YES) syslog( LOG_NOTICE, "pam_ldapaccess: Reading settings file %s.", SETTINGS_FILE);
        if ((iptr = fopen(SETTINGS_FILE, "r")) != NULL)
        {
          while (!feof(iptr))
          {
            fscanf(iptr, "%s", word);
            if (strncasecmp("SYSTEMNAME",word,10) == 0)
              fscanf(iptr, "%s", systemname);
            else if (strncasecmp("ADMINMAIL",word,9) == 0)
              fscanf(iptr, "%s", adminmail);
            else if (strncasecmp("LDAPIPATTR",word,10) == 0)
              fscanf(iptr, "%s", ldapipattr);
            else if (strncasecmp("LOCALDOMAIN",word,11) == 0)
              fscanf(iptr, "%s", localdomain);
            else if (strncasecmp("INTERNALRANGE",word,13) == 0)
            {
              if (fgets(line, MAX_SIZE, iptr) != NULL)
              {
                int i=0;
                char *token;
                strtok(line, "\n");
                token = strtok(line, " ,");
                while ( token != NULL)
                {
                  internalrange[i] = token;
                  i++;
                  token = strtok(NULL, " ,");
                }
                internalrange[i] = NULL;
              }
            }
          }
        }
        if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: mail [%s] system [%s] internal [%s]", adminmail, systemname, internalrange[0] );

        if (debug == YES)
          for (i=0; internalrange[i] != NULL; i++)
          {
            syslog( LOG_NOTICE, "pam_ldapaccess: internalrange[%d] is %s",i,internalrange[i]);
          }

        for (i=0; internalrange[i] != NULL; i++)
        {
          if (debug == YES) syslog( LOG_NOTICE, "pam_ldapaccess: internalrange[%d] is %s",i,internalrange[i]);
          if (network_netmask_match(internalrange[i], pam_rhost))
          {
            if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Found host [%s] in internal range [%s].", pam_rhost, internalrange[i]);
            return PAM_SUCCESS; 
          }
        } 

        PamResult=ldapIPcheck(pam_user, pam_rhost, ldapipattr);
        if ( PamResult == PAM_PERM_DENIED )
        {
          char *lines = NULL, *whoisdata = NULL, cmd[100],fname1[PATH_MAX],fname2[PATH_MAX];
          static char template[] = "/var/tmp/pam_ldapaccess.XXXXXX";

          syslog(LOG_ERR, "pam_ldapaccess: Refused connection for %s from %s", pam_user, pam_ip);
          
          strcpy(fname1, template);
          strcpy(fname2, template);
          int fd1 = mkstemp( fname1 );
          FILE *fp1, *fp2;
          if ((fp1=fdopen(fd1,"w")) == NULL)
            return PAM_ABORT;
          int fd2 = mkstemp( fname2 );
          if ((fp2=fdopen(fd2,"w")) == NULL)
            return PAM_ABORT;

          pam_info(pamh, "\nYou are logging into %s from %s (%s), which is not in the list of IP ranges authorised for %s.", systemname, pam_rhost, pam_ip, pam_user);
          if (domain_grep(ldapmail, localdomain))
            lines = ReadFile(intmessage);
          else
            lines = ReadFile(extmessage);
          if (lines)
            pam_info(pamh, lines);
          
          fprintf( fp1, "To: %s\n",ldapmail);
          fprintf( fp2, "To: %s\n",adminmail);
          fprintf( fp1, "Subject: Rejected %s from %s\n", pam_user, pam_rhost);
          fprintf( fp2, "Subject: Rejected %s from %s\n", pam_user, pam_rhost);
          fprintf( fp1, "You are logging into %s from %s (%s), which is not in the list of IP ranges authorised for %s.\n", systemname, pam_rhost, pam_ip, pam_user);
          fprintf( fp2, "User %s logged into %s from %s (%s), which is not in their list of IP ranges.\n", pam_user, systemname, pam_rhost, pam_ip);
          fprintf( fp1, "%s\n", lines );
          fprintf( fp2, "%s\n", lines );
          fclose( fp1 );
          free(lines);

          sprintf(cmd,"/usr/sbin/sendmail -t < %s",fname1); // prepare command.
          if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Sending mail, user mail=[%s]", ldapmail);
          if (system(cmd) != 0)
            syslog( LOG_ERR, "pam_ldapaccess: Failed to send mail to [%s]", ldapmail);   
          unlink(fname1);

          if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Finding whois data for: %s", pam_ip);
          if ( get_whois(pam_ip, &whoisdata) != NO )
          {
            if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Finished whois data for: %s", pam_ip);
            fprintf( fp2, "%s", whoisdata );
          }
          else
            fprintf( fp2, "Whois server could not be contacted.\n"  );
          if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Finished writing whois data");
          fclose(fp2);
          free(whoisdata);
          sprintf(cmd,"/usr/sbin/sendmail -t < %s",fname2); // prepare command.
          if (debug == YES) syslog(LOG_NOTICE, "pam_ldapaccess: Sending mail, user mail=[%s]", adminmail);
          if (system(cmd) != 0)
            syslog( LOG_ERR, "pam_ldapaccess: Failed to send mail to [%s]", adminmail);   
          unlink(fname2);
          
        }
  return(PamResult);
}

// PAM entry point for authentication. This function gets called by pam when
//a login occurs. argc and argv work just like argc and argv for the 'main'
//function of programs, except they pass in the options defined for this
//module in the pam configuration files in /etc/pam.conf or /etc/pam.d/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        return(PAM_IGNORE);
}

//We do not provide any of the below functions, we could just leave them out
//but apparently it's considered good practice to supply them and return
//'PAM_IGNORE'

//PAM entry point for starting sessions. This is called after a user has
//passed all authentication. It allows a PAM module to perform certain tasks
//on login, like recording the login occured, or printing a message of the day
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        return(PAM_IGNORE);
}


//PAM entry point for ending sessions. This is called when a user logs out
//It allows a PAM module to perform certain tasks on logout
//like recording the logout occured, or clearing up temporary files
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        return(PAM_IGNORE);
}

//PAM entry point for setting 'credentials' or properties of the user
//If our module stores or produces extra information about a user (e.g.
//a kerberous ticket or geolocation value) then it will pass this information
//to a PAM aware program in this call
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        return(PAM_IGNORE);
}

// PAM entry point for changing passwords. If our module stores passwords
// then this will be called whenever one needs changing
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
        return(PAM_IGNORE);
}


//I couldn't find any documentation on this. I think it notifies PAM of our
//module name
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ldapaccess");
#endif

