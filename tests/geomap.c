//=======================================================================
//
// Portions by Douglas L. Baskins, June 2002.
//   Permission to use this code is freely granted, provided that this
//   statement is retained.
//   email - doug@sourcejudy.com
//=======================================================================

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>              // errno
#include <sys/mman.h>           // mmap()
#include <sys/stat.h>           // stat()
#include <sys/time.h>           // gettimeofday()
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "Judy.h"
// #include "patricia.h"
#include "iprange.h"
#include "libcidr.h"
#include "hiredis.c"
#include "async.c"
#include "net.c"
#include "sds.c"
#include "ae.h"
#include "adapter_ae.h"
#include "ae.c"
#include "zmalloc.c"

#define FILERROR                                                        \
{                                                                       \
    printf("%s: Cannot open file \"%s\": %s "                           \
		"(errno = %d)\n", argv[0], argv[1], strerror(errno),    \
		errno);                                                 \
    fprintf(stderr, "%s: Cannot open file \"%s\": %s "                  \
		"(errno = %d)\n", argv[0], argv[1], strerror(errno),    \
		errno);                                                 \
    exit(1);                                                            \
}

// From memory map POINTER store next '\n' terminated string to BUFFER
// Delete spaces, tabs, returns and resulting blank lines.

// POINTER must be check to be within memory mapped file range
//
// NOTE: This code will core-dump if a corrupt text file because
// POINTER is not checked to exceed end of file.

#define MAX_FILELINE 200   // max length line

#define GETLINE(BUFFER,POINTER)			\
{                                               \
    char _chr;                                  \
    int  _count = 0;                            \
    for (;;)	/* forever */			\
    {                                           \
        switch (_chr = *POINTER++)		\
        {					\
        case '\r':	/* eat returns */	\
            continue;				\
	case '\n':      /* eat blank lines */	\
	    if (_count == 0) continue;		\
	case '\0':	/* Done */		\
            BUFFER[_count++] = '\0';              \
	    break;				\
	default:	/* copy char */		\
            if (_count == (MAX_FILELINE - 1))	\
	    { 	        /* cut into 2 lines */	\
                BUFFER[_count++] = '\0';	\
	        POINTER--;			\
	        break;				\
	    }					\
            BUFFER[_count++] = _chr;	        \
	    continue;				\
	}					\
	break;					\
    }						\
}

struct GeoInfo{
  struct in_addr lo;
  struct in_addr hi;
  void* covered_prefix;
  char country[8];		/* This is based on analysis of GeoIP CSV from MaxMind May 2014 */
  char region[7];		/* Of course this is dangerous to assume it will remain this way */
  char city[38];
  unsigned int prefix_cnt;
  char prefixes[62*19];
};

#define MAX(a,b) (((a)>(b))?(a):(b))

Pvoid_t GEOIP_SL = NULL;
Pvoid_t ASNIP_SL = NULL;
Pvoid_t CHECKIP_CNT_SL = NULL;

unsigned int load_geoip(char* file, Pvoid_t *arraySL) {
  int       fd;               // to read file.
  struct stat statbuf;        // to get size of file
  char     *Pfile;            // ram address of file
  size_t    fsize;            // file size in bytes
  char     *FSmap;            // start address of mapped file
  char     *FEmap;            // end address+1 of mapped file
  char      String[MAX_FILELINE];  // input buffer
  Word_t    StrCnt;           // line counter

  Word_t total = 0;
  Word_t covered_cnt = 0;
  Word_t c = 0;
  Word_t PV_IP;

  Pvoid_t uniqueSL = *arraySL;

  printf("load_geoip %s\n", file);

  // GET FILE SIZE
  if (stat(file, &statbuf) == -1) {
    printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
    exit(1);
  } else {
    fsize = statbuf.st_size;
    // OPEN INPUT FILE:
    if ((fd = open(file, O_RDONLY)) == -1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }
    // MEMORY MAP FILE
    Pfile = (char *)mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (Pfile == (char *)-1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }

    FEmap = Pfile + fsize;      // set end+1 address

    uint8_t  Index[40];  
    Word_t * PValue;  
    Word_t DupCnt = 0;
    Word_t node_total = 0;
    int max_country = 0;
    int max_region = 0;
    int max_city = 0;
    for (StrCnt = 0, FSmap = Pfile; FSmap < FEmap; )
      {
	GETLINE(String, FSmap); // 'read' next string
	if (StrCnt == 0) {
	  StrCnt++;
	  continue;
	}
	char* iplo = strtok(String,",");
	char* iphi = strtok(NULL, ",");
	char* country = strtok(NULL, ",");
	char* region = strtok(NULL, ",");
	char* city = strtok(NULL, ",");
	// printf("%lu ", StrCnt);
	struct in_addr addrlo, addrhi;
	
	max_country = MAX(strlen(country), max_country);
	max_city = MAX(strlen(city), max_city);
	max_region = MAX(strlen(region), max_region);

	inet_aton(iplo, (struct in_addr*)&addrlo.s_addr);
	inet_aton(iphi, (struct in_addr*)&addrhi.s_addr);

	struct GeoInfo* info = malloc(sizeof(struct GeoInfo));
	info->lo.s_addr = addrlo.s_addr;
	info->hi.s_addr = addrhi.s_addr;
	strcpy(info->country, country);
	strcpy(info->region, region);
	strcpy(info->city, city);
	strcpy((char*)Index, iplo);
	info->covered_prefix = NULL;
	info->prefix_cnt = 0;
	info->prefixes[0] = 0;

	/*
	if (StrCnt < 50) {
	  printf("%08lu lo=%08x - %08x %15s - %15s\t[", StrCnt, addrlo.s_addr, addrhi.s_addr, iplo, iphi);
	}
	*/

	network_addr_t netaddr = str_to_netaddr(iplo);
	in_addr_t lo = network( netaddr.addr, netaddr.pfx );
	netaddr = str_to_netaddr(iphi);
	in_addr_t hi = broadcast( netaddr.addr, netaddr.pfx );
	char* fixed_ranges[70];
	int x = 0;
	for (x = 0; x<70;x++) fixed_ranges[x] = NULL;
	info->prefix_cnt = get_ranges( 0, 0, lo, hi, fixed_ranges, 70, &info->prefix_cnt );
	for (x = 0; x<info->prefix_cnt;x++) {
	  if (fixed_ranges[x] != NULL) {
	    strcat(info->prefixes, fixed_ranges[x]);
	    strcat(info->prefixes, " ");
	    free(fixed_ranges[x]);
	  }
	}
	/*
	if (StrCnt < 50) {
	  printf("%s]\n", info->prefixes);
	}
	*/

	JSLG(PValue, uniqueSL, Index);
	if (PValue == NULL) {
	  JSLI(PValue, uniqueSL, Index);
	  if (PValue != NULL) {
	    *PValue = (Word_t)info;
	  }
	  ++total;
	} else {
	  struct GeoInfo *covering_info = (struct GeoInfo*)*PValue;
	  
	  covered_cnt++;
	  char addrlo[40], addrhi[40];
	  inet_ntop(AF_INET, &covering_info->lo, addrlo, sizeof addrlo);
	  inet_ntop(AF_INET, &covering_info->hi, addrhi, sizeof addrhi);
	  printf("  Covered by range %15s - %15s prefix ", addrlo, addrhi);
	  char* ranges[70];
	  int x = 0;
	  for (x = 0; x<70;x++) ranges[x] = NULL;
	  network_addr_t netaddr = str_to_netaddr(addrlo);
	  in_addr_t lo = network( netaddr.addr, netaddr.pfx );
	  netaddr = str_to_netaddr(addrhi);
	  in_addr_t hi = broadcast( netaddr.addr, netaddr.pfx );
	  unsigned int cnt = 0;
	  cnt = get_ranges( 0, 0, lo, hi, ranges, 70, &cnt );
	  for (x = 0; x<cnt;x++) {
	    if (ranges[x] != NULL) {
	      printf("%s", ranges[x]);
	      free(ranges[x]);
	    }
	  }
	  printf("\n");

	  if (covering_info->covered_prefix == NULL) {
	    covering_info->covered_prefix = info;
	  }
	}
	StrCnt++;
      }
    close(fd);

    total += node_total;

    printf("------------------------\n");
    printf("Total IP\t%lu\n", StrCnt);
    printf("Max Country\t%d\n", max_country);
    printf("Max Region\t%d\n", max_region);
    printf("Max City\t%d\n", max_city);

  }

  *arraySL = uniqueSL;
  printf("Loaded %lu geoip ranges (%lu covered)\n", total, covered_cnt);
  return total;
}

struct AsnInfo{
  uint32_t asn; 
  char prefix[32];
  struct in_addr lo;
  struct in_addr hi;
};


unsigned int load_asnip(char* file, Pvoid_t *arraySL) {
  int       fd;               // to read file.
  struct stat statbuf;        // to get size of file
  char     *Pfile;            // ram address of file
  size_t    fsize;            // file size in bytes
  char     *FSmap;            // start address of mapped file
  char     *FEmap;            // end address+1 of mapped file
  char      String[MAX_FILELINE];  // input buffer
  Word_t    StrCnt;           // line counter

  Word_t total = 0;
  Word_t covered_cnt = 0;
  Word_t c = 0;
  Word_t PV_IP;

  Pvoid_t uniqueSL = *arraySL;

  printf("------------------------\nload_asnip %s\n", file);

  // GET FILE SIZE
  if (stat(file, &statbuf) == -1) {
    printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
    exit(1);
  } else {
    fsize = statbuf.st_size;
    // OPEN INPUT FILE:
    if ((fd = open(file, O_RDONLY)) == -1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }
    // MEMORY MAP FILE
    Pfile = (char *)mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (Pfile == (char *)-1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }

    FEmap = Pfile + fsize;      // set end+1 address

    uint8_t  Index[40];  
    Word_t * PValue;  
    Word_t DupCnt = 0;

    for (StrCnt = 0, FSmap = Pfile; FSmap < FEmap; ) {
      GETLINE(String, FSmap); // 'read' next string

      char* prefix = strtok(String,"\t");
      char* asn = strtok(NULL, "\t");
      int asnid = atoi(asn);
	
      CIDR* cidr = cidr_from_str(prefix);
      CIDR* cidr_lo = cidr_addr_network(cidr);
      CIDR* cidr_hi = cidr_addr_broadcast(cidr);
      char* rangelo = cidr_to_str(cidr_lo, CIDR_ONLYADDR);
      char* rangehi = cidr_to_str(cidr_hi, CIDR_ONLYADDR);

      /*
      if (StrCnt < 40) {
	printf("%08lu %s\t%d\n", StrCnt, prefix, asnid);
	printf(" cidr range %s - %s\n", rangelo, rangehi);
      }
      */

      struct in_addr addrlo, addrhi;
      inet_aton(rangelo, (struct in_addr*)&addrlo.s_addr);
      inet_aton(rangehi, (struct in_addr*)&addrhi.s_addr);
      
      struct AsnInfo* info = NULL;
	  
      // Store as prefix
      strcpy((char*)Index, prefix);
      JSLG(PValue, uniqueSL, Index);
      if (PValue == NULL) {
	JSLI(PValue, uniqueSL, Index);
	if (PValue != NULL) {
	  info = malloc(sizeof(struct AsnInfo));
	  info->asn = asnid;
	  info->lo.s_addr = addrlo.s_addr;
	  info->hi.s_addr = addrhi.s_addr;
	  strcpy(info->prefix, prefix);
	  *PValue = (Word_t)info;
	}
	++total;
      } else {
	info = (struct AsnInfo*)*PValue;
	printf("Duplicate prefix! %8lu %s ASN=%d\n", StrCnt, prefix, info->asn);
      }

      // Store as rangelo
      strcpy((char*)Index, rangelo);
      JSLG(PValue, uniqueSL, Index);
      if (PValue == NULL) {
	JSLI(PValue, uniqueSL, Index);
	if (PValue != NULL) {
	  *PValue = (Word_t)info;
	}
      } else {
	info = (struct AsnInfo*)*PValue;
	/*
	if (strstr(prefix,"195.160.") != NULL)
	  printf("Covered prefix! %15s (%d) by %15s (%d)\n", prefix, asnid, info->prefix, info->asn);
	*/
	covered_cnt++;
      }

      StrCnt++;
      // if (StrCnt > 10000) break;
    }
    close(fd);
  }
  *arraySL = uniqueSL;
  printf("Loaded %lu prefixes (%lu covered)\n", total, covered_cnt);
  return total;
}

#define AMS_1 1
#define AMS_2 2
#define WAW_1 3
#define WAW_2 4
#define IAD_1 5
#define IAD_2 6
#define LAX_1 7
#define LAX_2 8
#define BOM_1 9
#define BOM_2 10

struct CheckipInfo{
  uint32_t asn; 
  uint32_t cnt;
  uint32_t ip;
  uint32_t node;
};

int compare_asninfo( const void* _a, const void* _b)
{
  Word_t a = * ( (Word_t*) _a );
  Word_t b = * ( (Word_t*) _b );

  uint32_t asn_a  = ((a & 0xFFFFFFFF00000000) >> 32);
  uint32_t cnt_a = (a & 0xFFFFFFFF);
  uint32_t asn_b  = ((b & 0xFFFFFFFF00000000) >> 32);
  uint32_t cnt_b = (b & 0xFFFFFFFF);
  
  // printf("Compare %d cnt=%d with %d cnt=%d\n", asn_a, cnt_a, asn_b, cnt_b);
  
  if ( cnt_a == cnt_b ) return 0;
  else if ( cnt_a < cnt_b ) return -1;
  else return 1;
}

unsigned int load_checkip_counts(char* file, Pvoid_t *arrayL) {
  int       fd;               // to read file.
  struct stat statbuf;        // to get size of file
  char     *Pfile;            // ram address of file
  size_t    fsize;            // file size in bytes
  char     *FSmap;            // start address of mapped file
  char     *FEmap;            // end address+1 of mapped file
  char      String[MAX_FILELINE];  // input buffer
  Word_t    StrCnt;           // line counter

  Word_t total = 0;
  Word_t asn_cnt = 0;
  Word_t c = 0;
  Word_t PV_IP;

  Pvoid_t uniqueL = *arrayL;

  char fname[512];
  strcpy(fname, file);
  char* node_loc = strtok(fname, "-");
  char* node_num = strtok(NULL, "-");
  Word_t nodeid = 0;

  printf("------------------------\nload_checkip %s\n", file);

  // GET FILE SIZE
  if (stat(file, &statbuf) == -1) {
    printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
    exit(1);
  } else {
    fsize = statbuf.st_size;
    // OPEN INPUT FILE:
    if ((fd = open(file, O_RDONLY)) == -1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }
    // MEMORY MAP FILE
    Pfile = (char *)mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (Pfile == (char *)-1) {
      printf("Cannot open file \"%s\": %s (errno = %d)\n", file, strerror(errno), errno);
      exit(1);
    }

    FEmap = Pfile + fsize;      // set end+1 address

    // Counts file format name structure is 'node-id-counts-timestamp.csv'
    if (strstr(node_loc, "ams") != NULL) {
      int id = atoi(node_num);
      switch(id) {
      case 1:
	nodeid = AMS_1; break;
      case 2:
	nodeid = AMS_2; break;
      }
    }
    else if (strstr(node_loc, "waw") != NULL) {
      int id = atoi(node_num);
      switch(id) {
      case 1:
	nodeid = WAW_1; break;
      case 2:
	nodeid = WAW_2; break;
      }
    }
    else if (strstr(node_loc, "iad") != NULL) {
      int id = atoi(node_num);
      switch(id) {
      case 1:
	nodeid = IAD_1; break;
      case 2:
	nodeid = IAD_2; break;
      }
    }
    else if (strstr(node_loc, "lax") != NULL) {
      int id = atoi(node_num);
      switch(id) {
      case 1:
	nodeid = LAX_1; break;
      case 2:
	nodeid = LAX_2; break;
      }
    }
    else if (strstr(node_loc, "bom") != NULL) {
      int id = atoi(node_num);
      switch(id) {
      case 1:
	nodeid = BOM_1; break;
      case 2:
	nodeid = BOM_2; break;
      }
    }
    
    uint8_t  Index[40];  
    Word_t * PValue;  
    Word_t DupCnt = 0;

    for (StrCnt = 0, FSmap = Pfile; FSmap < FEmap; ) {
      GETLINE(String, FSmap); // 'read' next string

      char* count = strtok(String,"\t");
      char* ip = strtok(NULL, "\t");
      int cnt = atoi(count);

      network_addr_t netaddr = str_to_netaddr(ip);
      in_addr_t lo = network( netaddr.addr, netaddr.pfx );
      strcpy((char*)Index, ip);
      JSLL(PValue, GEOIP_SL, Index);
      if (PValue != NULL) {
	struct GeoInfo *info = (struct GeoInfo*)*PValue;
	char addrlo[40], addrhi[40];
	inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
	inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrhi);
	int is_covered = 0;
	char coverlo[40], coverhi[40];
	struct GeoInfo *covered_prefix;
	int asnid = 0;
	uint8_t  AsnIndex[40];  

	if (info->covered_prefix != NULL) {
	  covered_prefix = (struct GeoInfo*)info->covered_prefix;
	  inet_ntop(AF_INET, &covered_prefix->lo, coverlo, sizeof addrlo);
	  inet_ntop(AF_INET, &covered_prefix->hi, coverhi, sizeof addrhi);
	  network_addr_t netaddrlo = str_to_netaddr(coverlo);
	  network_addr_t netaddrhi = str_to_netaddr(coverhi);
	  int greater_than_lo = compar_netaddr(&netaddr, &netaddrlo);
	  int less_than_hi = compar_netaddr(&netaddr, &netaddrhi);
	  is_covered = (greater_than_lo == 1) && (less_than_hi == -1);
	}

	strcpy((char*)AsnIndex, ip);
	JSLL(PValue, ASNIP_SL, AsnIndex);
	if (PValue != NULL) {
	  struct AsnInfo *info = (struct AsnInfo*)*PValue;
	  asnid = info->asn;

	  // NOW ADD TO OUR ASN USAGE TRACKER
	  Word_t asnidx = (nodeid << 32) | asnid;
	  Word_t *PASNCNT;
	  JLG(PASNCNT, uniqueL, asnidx);
	  if (PASNCNT != NULL) {
	    struct CheckipInfo *info = (struct CheckipInfo *)*PASNCNT;
	    info->cnt += cnt;
	    info->ip++;
	  } else {
	    JLI(PASNCNT, uniqueL, asnidx);
	    struct CheckipInfo *info = (struct CheckipInfo *)malloc(sizeof(struct CheckipInfo));
	    info->asn = asnid;
	    info->node = nodeid;
	    info->cnt = cnt;
	    info->ip = 1;
	    *PASNCNT = (Word_t)info;
	    asn_cnt++;
	  }
	} else {
	  printf("Unabled to find ASN for %s\n", ip);
	}
      }
      total++;
      StrCnt++;
    }
    close(fd);
  }
  *arrayL = uniqueL;
  Word_t asn_index_cnt, asn_index_mem;
  JLC(asn_index_cnt, uniqueL, 0, -1);
  JLMU(asn_index_mem, uniqueL);

  printf("Loaded %lu checkip nodeid=%lu (asn_cnt=%lu) %lu mem=%lu\n", total, nodeid, asn_cnt, asn_index_cnt, asn_index_mem);

  // Sort and find top 100
  Word_t* asn_array = malloc(asn_index_cnt * sizeof(Word_t));
  Word_t Index = 0, *PValue;
  int cnt = 0;
  JLF(PValue, uniqueL, Index);
  while (PValue != NULL) {
    struct CheckipInfo *info = (struct CheckipInfo*)*PValue;
    asn_array[cnt++] = ((Word_t)info->asn << 32) | info->cnt;
    if (cnt < 1000) {
      // printf("asn_array[%d]=%08lx\n", cnt-1, asn_array[cnt-1]);
    }
    JLN(PValue, uniqueL, Index);
  }

  qsort(asn_array, asn_index_cnt, sizeof(Word_t), compare_asninfo);
  for (cnt = asn_index_cnt-1; cnt > asn_index_cnt-51; cnt--) {
    Word_t val = asn_array[cnt];
    printf("ASN %8lu - %lu\n", ((val & 0xFFFFFFFF00000000) >> 32), (val & 0xFFFFFFFF));
  }

  free(asn_array);

  return total;
}

// -------------------------
// Redis Utils
// -------------------------

// redisContext *REDIS = NULL;
#define REDIS_NODE_CNT 7
redisAsyncContext *REDIS[REDIS_NODE_CNT];

char* REDIS_NODE_ADDR[REDIS_NODE_CNT] = {
  "75.101.236.56",
  "54.215.51.125",
  "54.73.94.240",
  "54.95.26.184",
  "54.255.119.106",
  "54.206.221.156",
  "54.207.244.93"};

static double current_time()
{
  struct timeval tv;
  if (gettimeofday(&tv, 0) < 0 )
    return 0;
  double now = tv.tv_sec + tv.tv_usec / 1e6;
  return now;
}

int SHUTDOWN = 0;

/* Put event loop in the global scope, so it can be explicitly stopped */
static aeEventLoop *loop;

const char* OID_MAP[] = {
  "DYNC",
  "AKAM",
  "LLNW",
  "LVLT",
  "EDGE",
  "FAST",
  "CNCC",
  "MAXC",
  "CLDF",
  "HWND",
  "CFLY",
};

const char* OID_TO_NAME(int oid) {
  return OID_MAP[oid];
}

#define MTYPE_DNS 1
#define MTYPE_INJECT 2
#define MTYPE_BEACON 3
#define MTYPE_COLLECT 4
#define MTYPE_TIMING 5

struct RecursiveInfo {
  struct in_addr addr;
  uint32_t cnt;
  uint32_t fast;
  uint32_t slow;
  char nodeid[5];
  char flap_from[5];
  uint32_t flap;
};

struct BeaconInfo {
  double ts;
  struct in_addr addr;
  char clientip[40];
  char recursiveip[40];
  uint32_t resource_cnt;
  uint32_t telemetry_cnt;
  char* telemetry;
  uint32_t mtype;
  char nodeid[4];
  uint32_t nodeflap;
  uint32_t inject;
  uint32_t beacon;
  uint32_t collect;
  double* durations;
  uint32_t* oids;
  uint32_t* sizes;
};

Pvoid_t BEACON_INFO = NULL;
Word_t  BEACON_CNT = 0;
Word_t  BEACON_COMPLETE = 0;
Word_t  BEACON_COMPLETE_TOTAL = 0;

Pvoid_t RECURSIVE_INFO = NULL;
Word_t  RECURSIVE_CNT = 0;

Pvoid_t RECURSIVE_UNIQUE = NULL;
Word_t  RECURSIVE_TOTAL = 0;

Pvoid_t FLAP_INFO = NULL;

pthread_mutex_t timer_lock=PTHREAD_MUTEX_INITIALIZER;

void dump_geo_asn_info(char* testip) {
  uint8_t GeoIndex[40];
  strcpy((char*)GeoIndex, testip);
  network_addr_t netaddr = str_to_netaddr(testip);
  in_addr_t lo = network( netaddr.addr, netaddr.pfx );
  Word_t *PValue;
  JSLL(PValue, GEOIP_SL, GeoIndex);
  if (PValue != NULL) {
    struct GeoInfo *geoinfo = (struct GeoInfo*)*PValue;
    char addrlo[40], addrhi[40];
    inet_ntop(AF_INET, &geoinfo->lo, addrlo, sizeof addrlo);
    inet_ntop(AF_INET, &geoinfo->hi, addrhi, sizeof addrhi);
    int is_covered = 0;
    char coverlo[40], coverhi[40];
    struct GeoInfo *covered_prefix;
    int asnid = 0;
    uint8_t  AsnIndex[40];  
    if (geoinfo->covered_prefix != NULL) {
      covered_prefix = (struct GeoInfo*)geoinfo->covered_prefix;
      inet_ntop(AF_INET, &covered_prefix->lo, coverlo, sizeof addrlo);
      inet_ntop(AF_INET, &covered_prefix->hi, coverhi, sizeof addrhi);
      network_addr_t netaddrlo = str_to_netaddr(coverlo);
      network_addr_t netaddrhi = str_to_netaddr(coverhi);
      int greater_than_lo = compar_netaddr(&netaddr, &netaddrlo);
      int less_than_hi = compar_netaddr(&netaddr, &netaddrhi);
      is_covered = (greater_than_lo == 1) && (less_than_hi == -1);
    }
    strcpy((char*)AsnIndex, testip);
    JSLL(PValue, ASNIP_SL, AsnIndex);
    if (PValue != NULL) {
      struct AsnInfo *asninfo = (struct AsnInfo*)*PValue;
      asnid = asninfo->asn;
    }
    printf(" => %18s\tASN=%d,%s,%s\t%08x - %08x\t%15s - %15s\n", AsnIndex, asnid, geoinfo->country, geoinfo->region, *(uint32_t*)&geoinfo->lo, *(uint32_t*)&geoinfo->hi, addrlo, addrhi);
    if (is_covered) {
      printf("  Covered by range %s ... %s %s %s ASN=%d\n", 
	     coverlo, coverhi, 
	     covered_prefix->country, covered_prefix->region, asnid);
    }
  } else {
    printf("Can't obtain GEO/ASN info\n");
  }
}

void msgCallback(redisAsyncContext *c, void *reply, void *privdata) {
  pthread_mutex_lock(&timer_lock);
  if (reply == NULL) return;
  redisReply *r = reply;
  if (r->type == REDIS_REPLY_ARRAY) {
    if (r->elements >= 3) {
      // 3rd element is the message body
      char tmp[64*1024];
      if (r->element[2]->str != NULL) {
	// int mlen = strlen(r->element[2]->str); printf("%d ", mlen);
	strncpy(tmp, r->element[2]->str, sizeof(tmp));
	char* linesave;
	char* line = strtok_r(tmp, "|", &linesave);
	while (line != NULL) {
	  char* save;
	  // printf("%s\n", line);
	  char* ts = strtok_r(line, ",", &save);
	  char* msgtype = strtok_r(NULL, ",", &save);
	  char* nodeid = strtok_r(NULL, ",", &save);
	  char* clientip = strtok_r(NULL, ",", &save);
	  char* beacon = strtok_r(NULL, ",", &save);
	  char* custid = strtok_r(NULL, ",", &save);
	  char* custdata = strtok_r(NULL, ",", &save);
	  
	  if (msgtype[0] == 'A') {
	    if (strstr(beacon,"DNS_PULSE") != NULL)
	      printf("%s,%s,%s,%s,%s\n", ts,msgtype,nodeid,clientip,beacon);
	  }
	  else if (msgtype[0] == 'H') {
	    // ignore
	  } else {
	    int is_dns = msgtype[0] == 'D';
	    char beacon_node[5];
	    memcpy(beacon_node, beacon, 4);
	    beacon_node[4] = 0;
	    struct in_addr addr;
	    inet_aton(clientip, (struct in_addr*)&addr.s_addr);

	    if (is_dns) {
	      Word_t *PV;
	      int RC_int;
	      J1S(RC_int, RECURSIVE_UNIQUE, addr.s_addr);
	      if (RC_int == 1) RECURSIVE_TOTAL++;

	      JLG(PV, RECURSIVE_INFO, addr.s_addr);
	      if (PV != NULL) {
		struct RecursiveInfo *info = (struct RecursiveInfo*)*PV;
		info->cnt++;
	      } else {
		// printf("%s,%s,%s,%s,%s\n", ts,msgtype,nodeid,clientip,beacon);
		struct RecursiveInfo *info = (struct RecursiveInfo*)malloc(sizeof(struct RecursiveInfo));
		info->addr.s_addr = addr.s_addr;
		info->cnt = 1;
		info->fast = 0;
		info->slow = 0;
		info->flap = 0;
		RECURSIVE_CNT++;
		strcpy(info->nodeid, nodeid);
		if (strstr(nodeid, beacon_node) == NULL) {
		  printf("DNS NODE flap detected recursive=%s node=%s beacon_node=%s beacon=%s\n", clientip, nodeid, beacon_node, beacon+5);
		  strcpy(info->flap_from, beacon_node);
		  dump_geo_asn_info(clientip);
		  info->flap++;
		}
		JLI(PV, RECURSIVE_INFO, addr.s_addr);
		*PV = (Word_t)info;
	      }
	    }

	    uint8_t Index[50];
	    strcpy((char*)Index, beacon+5);
	    Word_t *PV;
	    struct BeaconInfo *info = NULL;
	    JSLG(PV, BEACON_INFO, Index);
	    if (PV != NULL) {
	      info = (struct BeaconInfo*)*PV;
	      if (is_dns) {
		strcpy(info->recursiveip, clientip);
	      }
	      else {
		strcpy(info->clientip, clientip);
	      }
	    } else {
	      info = (struct BeaconInfo*)malloc(sizeof(struct BeaconInfo));
	      info->addr.s_addr = addr.s_addr;
	      info->nodeflap = 0;
	      info->telemetry_cnt = 0;
	      info->inject = info->beacon = info->collect = 0;
	      strcpy(info->nodeid, nodeid);
	      char rescnt[2];
	      rescnt[0] = beacon[4];
	      rescnt[1] = 0;
	      info->resource_cnt = strtol(rescnt,NULL,16);
	      // printf("%s resource cnt=%d\n", beacon, info->resource_cnt);
	      info->durations = (double*)malloc(info->resource_cnt*sizeof(double));
	      info->oids = (uint32_t*)malloc(info->resource_cnt*sizeof(uint32_t));
	      info->sizes = (uint32_t*)malloc(info->resource_cnt*sizeof(uint32_t));
	      int x;
	      for (x = 0; x < info->resource_cnt; x++) {
		info->durations[x] = 0;
		info->oids[x] = 0;
		info->sizes[x] = 0;
	      }
	      info->clientip[0] = 0;
	      info->recursiveip[0] = 0;
	      if (is_dns) {
		strcpy(info->recursiveip, clientip);
	      }
	      else {
		strcpy(info->clientip, clientip);
	      }
	      JSLI(PV, BEACON_INFO, Index);
	      *PV = (Word_t)info;
	      BEACON_CNT++;
	    }

	    switch (msgtype[0]) 
	      {
	      case 'I':
		info->inject++;
		break;
	      case 'B':
		info->beacon++;
		break;
	      case 'C':
		info->collect++;
		break;
	      case 'R': 
		{
		  info->telemetry_cnt++;
		  if (info->telemetry_cnt == info->resource_cnt)
		    BEACON_COMPLETE++;
		  char* size = strtok_r(NULL, ",", &save);
		  char* oid = strtok_r(NULL, ",", &save);
		  char* rid = strtok_r(NULL, ",", &save);
		  char* t2dns = strtok_r(NULL, ",", &save);
		  char* t2conn = strtok_r(NULL, ",", &save);
		  char* t2fb = strtok_r(NULL, ",", &save);
		  char* t2lb = strtok_r(NULL, ",", &save);
		  char* duration = strtok_r(NULL, ",", &save);
		  if (t2lb == NULL || duration == NULL) {
		    printf("WARN: %s\n", line);
		    fflush(stdout);
		  }
		  else {
		    // printf("t2lb=%s dur=%s ", t2lb, duration);
		    double dur = strtod(duration,NULL);
		    // printf("%s,%s,%s,%s,%s,%s\n", ts,msgtype,nodeid,clientip,beacon,save);
		    uint32_t u32_rid = atoi(rid);
		    uint32_t u32_oid = atoi(oid);
		    info->durations[u32_rid-1] = dur;
		    info->oids[u32_rid-1] = u32_oid;
		    info->sizes[u32_rid-1] = atoi(size);
		  }
		  break;
		}
	      }

	  }
	  line = strtok_r(NULL, "|", &linesave);
	}
      }
    }
  }
  pthread_mutex_unlock(&timer_lock);
}


void flush_stats(int onexit) {
  pthread_mutex_lock(&timer_lock);

  // Dump the recursive info
  printf("- RECURSIVES cnt=%lu total=%lu\n", RECURSIVE_CNT, RECURSIVE_TOTAL);
  Word_t Index = 0;
  Word_t *PV;
  if (onexit) {
    JLF(PV, RECURSIVE_INFO, Index);
    printf("  MOST RECENT ----\n");
    while (PV != NULL) {
      struct RecursiveInfo *info = (struct RecursiveInfo*)*PV;
      char addr[40];
      inet_ntop(AF_INET, &info->addr, addr, sizeof addr);
      printf("%08lx %15s cnt=%d\n", Index, addr, info->cnt);
      JLN(PV, RECURSIVE_INFO, Index);
      free(info);
    }
    printf("  ALL ------------\n");
    Word_t rc_int;
    Index = 0;
    J1F(rc_int, RECURSIVE_UNIQUE, Index);
    while (rc_int > 0) {
      struct in_addr addr;
      addr.s_addr = Index;
      char addr_recursive[40];
      inet_ntop(AF_INET, &addr.s_addr, addr_recursive, sizeof addr_recursive);
      printf("%08lx %15s\n", Index, addr_recursive);
      J1N(rc_int, RECURSIVE_UNIQUE, Index);
    }
  }

  JLFA(Index, RECURSIVE_INFO);
  RECURSIVE_CNT=0;

  printf("- BEACONS cnt=%lu complete=%lu total_complete=%lu\n", BEACON_CNT, BEACON_COMPLETE, BEACON_COMPLETE + BEACON_COMPLETE_TOTAL);
  uint8_t BeaconIndex[40];
  BeaconIndex[0] = 0;
  JSLF(PV, BEACON_INFO, BeaconIndex);
  while (PV != NULL) {
    struct BeaconInfo *info = (struct BeaconInfo*)*PV;
    if (info->resource_cnt == info->telemetry_cnt) {
      // printf("----------\n%s\t%15s\t%15s\tibc=%d%d%d\t%d\t%d\n", BeaconIndex, info->recursiveip, info->clientip, info->inject, info->beacon, info->collect, info->resource_cnt, info->telemetry_cnt);
      unsigned int x, i;
      double min_durs[2];
      int min_oids[2];
      int rid_sizes[2];
      for (i = 0; i < 2; i++) {
	min_durs[i] = 0;
	min_oids[i] = 0;
	rid_sizes[i] = 0;
	double min_dur = 1000000.0;
	int min_oid = -1;
	int rid_size = -1;
	for (x = 0; x < info->resource_cnt/2; x++) {
	  unsigned int idx = i * (info->resource_cnt/2) + x;
	  if (info->durations[idx] < min_dur) {
	    min_dur = info->durations[idx];
	    min_oid = info->oids[idx];
	    rid_size = info->sizes[idx];
	  }
	}
	// printf("min=%f oid=%d size=%d\n", min_dur, min_oid, rid_size);
	min_durs[i] = min_dur;
	min_oids[i] = min_oid;
	rid_sizes[i] = rid_size;
      }
      char* result = "WINNER";
      if (min_oids[0] == min_oids[1]) {

	/*
	JLG(PV, WINNER_INFO, addr.s_addr);
	if (PV != NULL) {
	  struct RecursiveInfo *info = (struct RecursiveInfo*)*PV;
	  info->cnt++;
	} else {
	  // printf("%s,%s,%s,%s,%s\n", ts,msgtype,nodeid,clientip,beacon);
	  struct RecursiveInfo *info = (struct RecursiveInfo*)malloc(sizeof(struct RecursiveInfo));
	}
	*/

	if (info->recursiveip[0] != 0) {
	  dump_geo_asn_info(info->recursiveip);
	  dump_geo_asn_info(info->clientip);
	} else {
	  dump_geo_asn_info(info->clientip);
	}
      } else {
	result = "NO winner";
      }
      printf("%s\t recursive=%s clientip=%s\n", "WINNER", info->recursiveip, info->clientip);
      printf("  r1 %s min=%f oid=%d size=%d\n", OID_TO_NAME(min_oids[0]), min_durs[0], min_oids[0], rid_sizes[0]);
      printf("  r2 %s min=%f oid=%d size=%d\n", OID_TO_NAME(min_oids[0]), min_durs[1], min_oids[1], rid_sizes[1]);
    }
    JSLN(PV, BEACON_INFO, BeaconIndex);
  }

  BeaconIndex[0] = 0;
  JSLF(PV, BEACON_INFO, BeaconIndex);
  while (PV != NULL) {
    struct BeaconInfo *info = (struct BeaconInfo*)*PV;
    free(info);
    JSLN(PV, BEACON_INFO, BeaconIndex);
  }
  JSLFA(Index, BEACON_INFO);
  BEACON_CNT=0;
  BEACON_COMPLETE_TOTAL += BEACON_COMPLETE;
  BEACON_COMPLETE=0;

  pthread_mutex_unlock(&timer_lock);
}

void* beacon_timer (void * args) {
  while(1) {
    sleep (1);
    int now = (int)current_time();
    printf("%d,%lu,%lu,%lu\n", now, RECURSIVE_CNT, BEACON_CNT, BEACON_COMPLETE);
    if (now % 60 == 0) {
      printf("- Flushing Stats ------------\n");
      flush_stats(0);
    }
  }
}


void connectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("Error: %s\n", c->errstr);
        aeStop(loop);
        return;
    }
    printf("- Connected %s -----------------------\n", (char*)c->data);
}

void disconnectCallback(const redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("Error: %s\n", c->errstr);
        aeStop(loop);
        return;
    }
    printf("- Disconnected %s -------------------\n", (char*)c->data);
    aeStop(loop);
}

void endprocess(int signo) {
  SHUTDOWN = 1;
  int x;
  printf("\n");
  for(x = 0; x < REDIS_NODE_CNT; x++){
    if (REDIS[x] != NULL) {
      redisAsyncDisconnect(REDIS[x]);
    }
  }
  flush_stats(1);
}

int main(int argc, char* argv[]) {

  if (argc < 2) {
    printf("Usage: %s <geoip file> <asnip file>\n", argv[0]);
    exit(1);
  }

  load_geoip(argv[1], &GEOIP_SL);
  load_asnip(argv[2], &ASNIP_SL);

  signal(SIGINT, endprocess);

  /*
  if (argc > 3)
    load_checkip_counts(argv[3], &CHECKIP_CNT_SL);
  */

  // Create timer thread                                                                                                                               
  pthread_t thread;
  pthread_create (&thread, NULL, &beacon_timer, NULL);

  int x;
  for (x = 0; x < REDIS_NODE_CNT; x++) {
    REDIS[x] = redisAsyncConnect(REDIS_NODE_ADDR[x], 6379);
    if (REDIS[x]->err) {
      /* Let *c leak for now... */
      printf("Error: %s\n", REDIS[x]->errstr);
      return 1;
    }
    REDIS[x]->data = REDIS_NODE_ADDR[x];
  }

  loop = aeCreateEventLoop(64);

  for (x = 0; x < REDIS_NODE_CNT; x++) {
    redisAeAttach(loop, REDIS[x]);
    redisAsyncSetConnectCallback(REDIS[x],connectCallback);
    redisAsyncSetDisconnectCallback(REDIS[x],disconnectCallback);
    redisAsyncCommand(REDIS[x], msgCallback, NULL, "SUBSCRIBE beacon");
  }

  aeMain(loop);

  
////
////  Word_t * PValue;  
////  /*
////  printf("- JL Dump %p ----------------------\n", UNIQUE_L);
////  Word_t IndexL = 0;
////  JLF(PValue, UNIQUE_L, IndexL);
////  while (PValue != NULL) {
////    struct GeoInfo *info = (struct GeoInfo*)*PValue;
////    char addrlo[40], addrhi[40];
////    inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
////    inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrlo);
////    printf("%x => %x (%s)..%x (%s) %s %s\n", (uint)IndexL, info->lo.s_addr, addrlo, info->hi.s_addr, addrhi, info->country, info->region);
////    JLN(PValue, UNIQUE_L, IndexL);
////  }
////  */
////
////  uint8_t  Index[40];  
/////*
////  printf("- GEOIP DUMP --------------------\n");
////  Index[0] = 0;
////  JSLF(PValue, GEOIP_SL, Index);
////  while (PValue != NULL) {
////    struct GeoInfo *info = (struct GeoInfo*)*PValue;
////    char addrlo[40], addrhi[40];
////    inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
////    inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrlo);
////    printf("%s => %x (%s)..%x (%s) %s %s\n", Index, info->lo.s_addr, addrlo, info->hi.s_addr, addrhi, info->country, info->region);
////    JSLN(PValue, GEOIP_SL, Index);
////  }
////*/
//// 
////  printf("- GEOIP SEARCH ------------------\n");
////  char jsl_tests[1000] = "1.0.155.0,1.0.155.1,1.0.155.10,1.1.63.200,195.160.236.9,195.160.237.24,195.160.238.3";
////  char* testip = strtok(jsl_tests, ",");
////  while (testip != NULL) {
////    strcpy((char*)Index, testip);
////
////    network_addr_t netaddr = str_to_netaddr(testip);
////    in_addr_t lo = network( netaddr.addr, netaddr.pfx );
////    printf("testing %15s ", testip);
////    JSLL(PValue, GEOIP_SL, Index);
////    if (PValue != NULL) {
////      struct GeoInfo *info = (struct GeoInfo*)*PValue;
////      char addrlo[40], addrhi[40];
////      inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
////      inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrhi);
////      int is_covered = 0;
////      char coverlo[40], coverhi[40];
////      struct GeoInfo *covered_prefix;
////      int asnid = 0;
////      uint8_t  AsnIndex[40];  
////
////      if (info->covered_prefix != NULL) {
////	covered_prefix = (struct GeoInfo*)info->covered_prefix;
////	inet_ntop(AF_INET, &covered_prefix->lo, coverlo, sizeof addrlo);
////	inet_ntop(AF_INET, &covered_prefix->hi, coverhi, sizeof addrhi);
////	network_addr_t netaddrlo = str_to_netaddr(coverlo);
////	network_addr_t netaddrhi = str_to_netaddr(coverhi);
////	int greater_than_lo = compar_netaddr(&netaddr, &netaddrlo);
////	int less_than_hi = compar_netaddr(&netaddr, &netaddrhi);
////	is_covered = (greater_than_lo == 1) && (less_than_hi == -1);
////      }
////
////      strcpy((char*)AsnIndex, testip);
////      JSLL(PValue, ASNIP_SL, AsnIndex);
////      if (PValue != NULL) {
////	struct AsnInfo *info = (struct AsnInfo*)*PValue;
////	asnid = info->asn;
////      }
////
////      printf(" => %15s\t%08x - %08x\t%15s - %15s\t%s %s ASN=%d\n", Index, *(uint32_t*)&info->lo, *(uint32_t*)&info->hi, addrlo, addrhi, info->country, info->region, asnid);
////      // printf(" => %15s [%s] ASN=%d\n", Index, info->prefixes, info->country, info->region, asnid);
////      if (is_covered) {
////	printf("  Covered by range %s ... %s %s %s ASN=%d\n", 
////	       coverlo, coverhi, 
////	       covered_prefix->country, covered_prefix->region, asnid);
////      }
////    }
////    testip = strtok(NULL, ",");
////  }
////
////  /*
////  printf("- ASNIP DUMP --------------------\n");
////  Index[0] = 0;
////  JSLF(PValue, ASNIP_SL, Index);
////  while (PValue != NULL) {
////    struct AsnInfo *info = (struct AsnInfo*)*PValue;
////    char addrlo[40], addrhi[40];
////    inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
////    inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrlo);
////    printf("%15s\t=>\t%08x (%s)\t%08x (%s)\t %d\n", Index, info->lo.s_addr, addrlo, info->hi.s_addr, addrhi, info->asn );
////    JSLN(PValue, ASNIP_SL, Index);
////  }
////  */
////
////  printf("- ASNIP SEARCH ------------------\n");
////  char asn_tests[1000] = "1.0.155.0,1.0.155.1,1.0.155.10,1.1.63.200,195.160.236.9,195.160.237.24,195.160.238.3";
////  testip = strtok(asn_tests, ",");
////  uint8_t  IndexNext[40];  
////  uint8_t  IndexPrev[40];  
////  while (testip != NULL) {
////    printf("testing %15s ", testip);
////
////    int is_covered = 0;
////    network_addr_t netaddr = str_to_netaddr(testip);
////    strcpy((char*)Index, testip);
////    JSLL(PValue, ASNIP_SL, Index);
////    int direction = 1;
////    while (1) {
////      if (PValue != NULL) {
////	struct AsnInfo *info = (struct AsnInfo*)*PValue;
////	char addrlo[40], addrhi[40];
////	inet_ntop(AF_INET, &info->lo, addrlo, sizeof addrlo);
////	inet_ntop(AF_INET, &info->hi, addrhi, sizeof addrhi);
////	
////	network_addr_t netaddrlo = str_to_netaddr(addrlo);
////	network_addr_t netaddrhi = str_to_netaddr(addrhi);
////	int greater_than_lo = compar_netaddr(&netaddr, &netaddrlo);
////	int less_than_hi = compar_netaddr(&netaddr, &netaddrhi);
////	int range_hit = greater_than_lo == 1 && less_than_hi == -1;
////	// printf("=> %15s\t%08x - %08x\t%15s - %15s\t%15s\tASN=%d %s RangeCompare=(%d %d)\n", Index, *(uint32_t*)&info->lo, *(uint32_t*)&info->hi, addrlo, addrhi, info->prefix, info->asn, range_hit?"HIT":"MISS", greater_than_lo, less_than_hi);
////	if (range_hit) {
////	  printf("=> %18s\tASN=%d\n", info->prefix, info->asn);
////	  break;
////	}
////	if (greater_than_lo == -1) {
////	  if (direction == 1) {
////	    direction = -1;
////	    strcpy((char*)IndexPrev, (char*)Index);
////	  } else if (direction == -1) {
////	    printf("=> UNKNOWN ASN!\n");
////	    break;
////	  }
////	}
////
////	if (direction == 1) {
////	  // printf("  trying next range ");
////	  strcpy((char*)IndexNext, (char*)Index);
////	  JSLN(PValue, ASNIP_SL, IndexNext);
////	} else if (direction == -1) {
////	  // printf("  trying prev range ");
////	  JSLP(PValue, ASNIP_SL, IndexPrev);
////	}
////      }
////    }
////    testip = strtok(NULL, ",");
////  }
////
////  printf("- CIDR Fun ----------------------\n");
////  char test_ranges[] = "1.0.1.0-1.0.3.255,0.0.0.0-255.255.255.254";
////  char* save_range;
////  char* test_range = strtok_r(test_ranges, ",", &save_range);
////  while(test_range != NULL) {
////    printf("Testing %s\n", test_range);
////    char* save;
////    char* rangelo = strtok_r(test_range,"-",&save);
////    char* rangehi = strtok_r(NULL, "-", &save);
////    printf("  lo=%s hi=%s\n", rangelo, rangehi);
////    network_addr_t netaddr = str_to_netaddr(rangelo);
////    in_addr_t lo = network( netaddr.addr, netaddr.pfx );
////    netaddr = str_to_netaddr(rangehi);
////    in_addr_t hi = broadcast( netaddr.addr, netaddr.pfx );
////    uint cnt = 0;
////    printf("get_range %s - %s => ", rangelo, rangehi);
////    char* ranges[70];
////    int x = 0;
////    for (x = 0; x<70;x++) ranges[x] = NULL;
////    cnt = get_ranges( 0, 0, lo, hi, ranges, 70,&cnt );
////    for (x = 0; x<cnt;x++) {
////      if (ranges[x] != NULL) {
////	printf(" %s ", ranges[x]);
////	free(ranges[x]);
////      }
////    }
////    printf("\n");
////    test_range = strtok_r(NULL, ",", &save_range);
////  }
////
////  char tests_cidr[1000] = "1.0.155.10,1.1.63.200";
////  testip = strtok(tests_cidr, ",");
////  while (testip != NULL) {
////    network_addr_t netaddr = str_to_netaddr(testip);
////    char addr[40];
////    addr_to_ascii(netaddr.addr, netaddr.pfx, addr, 40);
////    printf("addr_to_ascii %s => %s\n", testip, addr);
////    testip = strtok(NULL,",");
////  }

}


