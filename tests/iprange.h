/* iprange
 * Copyright (C) 2003 Gabriel L. Somlo
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * To compile:
 *  on Linux:
 *   gcc -o iprange iprange.c -O2 -Wall
 *  on Solaris 8, Studio 8 CC:
 *   cc -xO5 -xarch=v8plusa -xdepend iprange.c -o iprange -lnsl -lresolv
 *
 * CHANGELOG:
 *  2004-10-16 Paul Townsend (alpha alpha beta at purdue dot edu)
 *   - more general input/output formatting
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*---------------------------------------------------------------------*/
/* network address type: one field for the net address, one for prefix */
/*---------------------------------------------------------------------*/
typedef struct network_addr {
  in_addr_t addr;
  int pfx;
} network_addr_t;


/*------------------------------------------------------------------*/
/* Set a bit to a given value (0 or 1); MSB is bit 1, LSB is bit 32 */
/*------------------------------------------------------------------*/
in_addr_t set_bit( in_addr_t addr, int bitno, int val ) {

  if ( val )
    return( addr | (1 << (32 - bitno)) );
  else
    return( addr & ~(1 << (32 - bitno)) );

} /* set_bit() */


/*--------------------------------------*/
/* Compute netmask address given prefix */
/*--------------------------------------*/
in_addr_t netmask( int prefix ) {

  if ( prefix == 0 )
    return( ~((in_addr_t) -1) );
  else
    return( ~((1 << (32 - prefix)) - 1) );

} /* netmask() */


/*----------------------------------------------------*/
/* Compute broadcast address given address and prefix */
/*----------------------------------------------------*/
in_addr_t broadcast( in_addr_t addr, int prefix ) {

  return( addr | ~netmask(prefix) );

} /* broadcast() */


/*--------------------------------------------------*/
/* Compute network address given address and prefix */
/*--------------------------------------------------*/
in_addr_t network( in_addr_t addr, int prefix ) {

  return( addr & netmask(prefix) );

} /* network() */


/*------------------------------------------------*/
/* Print out a 32-bit address in A.B.C.D/M format */
/*------------------------------------------------*/

void addr_to_ascii( in_addr_t addr, int prefix, char* buf, int len ) {

  struct in_addr in;

  in.s_addr = htonl( addr );
  if ( prefix < 32 )
    snprintf(buf,len, "%s/%d", inet_ntoa(in), prefix );
  else
    snprintf(buf,len, "%s", inet_ntoa(in));

}

int get_ranges( in_addr_t addr, int prefix, in_addr_t lo, in_addr_t hi, char* ranges[], uint len, uint* total ) {

  in_addr_t bc, lower_half, upper_half;
  if ((prefix < 0) || (prefix > 32)) {
    fprintf( stderr, "Invalid mask size %d!\n", prefix );
    exit(1);
  }
  bc = broadcast(addr, prefix);
  if ((lo < addr) || (hi > bc)) {
    fprintf( stderr, "Out of range limits: %x, %x for network %x/%d, broadcast: %x!\n", lo, hi, addr, prefix, bc );
    exit(1);
  }
  if ((lo == addr) && (hi == bc)) {
    char* range = malloc(40);
    addr_to_ascii(addr, prefix, range, 39);
    int x = 0;
    for (x = 0; x < len; x++) {
      if (ranges[x] == NULL) {
	(*total)++;
	ranges[x] = range;
	break;
      }
    }
    return *total;
  }
  prefix++;
  lower_half = addr;
  upper_half = set_bit( addr, prefix, 1 );
  if ( hi < upper_half ) {
    return get_ranges( lower_half, prefix, lo, hi, ranges, len, total );
  } else if ( lo >= upper_half ) {
    return get_ranges( upper_half, prefix, lo, hi, ranges, len, total );
  } else {
    get_ranges( lower_half, prefix, lo, broadcast(lower_half, prefix), ranges, len, total );
    return get_ranges( upper_half, prefix, upper_half, hi, ranges, len, total);
  }
}


/*-----------------------------------------------------------*/
/* Convert an A.B.C.D address into a 32-bit host-order value */
/*-----------------------------------------------------------*/
in_addr_t a_to_hl( char *ipstr ) {

  struct in_addr in;

  if ( !inet_aton(ipstr, &in) ) {
    fprintf( stderr, "Invalid address %s!\n", ipstr );
    exit( 1 );
  }

  return( ntohl(in.s_addr) );

} /* a_to_hl() */


/*-----------------------------------------------------------------*/
/* convert a network address char string into a host-order network */
/* address and an integer prefix value                             */
/*-----------------------------------------------------------------*/
network_addr_t str_to_netaddr( char *ipstr ) {

  long int prefix = 32;
  char *prefixstr;
  network_addr_t netaddr;

  if ( (prefixstr = strchr(ipstr, '/')) ) {
    *prefixstr = '\0';
    prefixstr++;
    prefix = strtol( prefixstr, (char **) NULL, 10 );
    if ( errno || (*prefixstr == '\0') || (prefix < 0) || (prefix > 32) ) {
      fprintf( stderr, "Invalid prefix /%s...!\n", prefixstr );
      exit( 1 );
    }
  }

  netaddr.pfx = (int) prefix;
  netaddr.addr = network( a_to_hl(ipstr), prefix );

  return( netaddr );

} /* str_to_netaddr() */


/*----------------------------------------------------------*/
/* compare two network_addr_t structures; used with qsort() */
/* sort in increasing order by address, then by prefix.     */
/*----------------------------------------------------------*/
int compar_netaddr( const void *p1, const void *p2 ) {

  network_addr_t *na1 = (network_addr_t *) p1, *na2 = (network_addr_t *) p2;

  if ( na1->addr < na2->addr )
    return( -1 );
  if ( na1->addr > na2->addr )
    return( 1 );
  if ( na1->pfx < na2->pfx )
    return( -1 );
  if ( na1->pfx > na2->pfx )
    return( 1 );
  return( 0 );

} /* compar_netaddr() */




