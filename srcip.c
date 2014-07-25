#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "hiredis.c"
#include "net.c"
#include "sds.c"
#include <Judy.h>
#include <pthread.h>

pcap_t* pd;
int linkhdrlen;

pthread_mutex_t timer_lock=PTHREAD_MUTEX_INITIALIZER;

Pvoid_t AGENT_CACHE = (PWord_t) NULL;
Word_t  REQS = 0;
Word_t  AGENT_COUNT = 0;
Word_t  AGENT_TOTAL = 0;
int     AGENT_PREAMBLE_LEN = 0;
char    AGENT_PREAMBLE[64];
int     DEBUG = 0;
int     AGENT_TRACK = 0;
char    AGENT_CHANNEL[64] = "";

struct AgentInfo {
  uint first_issued;
  uint cnt;
  uint total;
};

int     COUNT_TRACK = 0;
char    COUNT_CHANNEL[64] = "";
Pvoid_t COUNT_CACHE = (PWord_t) NULL;
Word_t  COUNT_CNT = 0;
Word_t  COUNT_TOTAL = 0;

struct IP_Info {
  uint first_issued;
  uint cnt;
  uint total;
};

Pvoid_t SRCIP_CACHE = (Pvoid_t) NULL;
Word_t  SRCIP_TOTAL = 0;
Word_t  SRCIP_COUNT = 0;
char    SRCIP_CHANNEL[64] = "srcip";

redisContext *REDIS = NULL;

static double current_time()
{
  struct timeval tv;
  if (gettimeofday(&tv, 0) < 0 )
    return 0;
  double now = tv.tv_sec + tv.tv_usec / 1e6;
  return now;
}

char REDIS_SERVER[64] = "127.0.0.1";

static void redis_flush();

void* redis_timer (void * args) {
  while(1) {
    sleep (1);
    redis_flush();
  }
}

static void redis_init() {
  REDIS = redisConnect(REDIS_SERVER, 6379);
  if (REDIS == NULL || REDIS->err) {
    if (REDIS) {
      printf("REDIS Connection error: %s\n", REDIS->errstr);
      redisFree(REDIS);
    } else {
      printf("REDIS Connection error: can't allocate redis context\n");
    }
    REDIS = NULL;
    // exit(1);
  } else {
    redisEnableKeepAlive(REDIS);
    // Init the preamble we'll use for each telemetry publish                                                                                          
    sprintf(AGENT_PREAMBLE, "*3\r\n$7\r\nPUBLISH\r\n$%d\r\n%s\r\n", (int)strlen(AGENT_CHANNEL), AGENT_CHANNEL);
    AGENT_PREAMBLE_LEN = strlen(AGENT_PREAMBLE);
  }
  // Create timer thread                                                                                                                               
  pthread_t thread;
  pthread_create (&thread, NULL, &redis_timer, NULL);
}

static void redis_term() {
  if (REDIS != NULL) {
    redisFree(REDIS);
    REDIS = NULL;
  }
}

static void publish_agent_telemetry(char* buffer, int bufi) {

  if (DEBUG)
    printf("PUBLISH %s %s\n", AGENT_CHANNEL, buffer);

  char command[64];
  sprintf(command, "$%d\r\n", bufi);
  int msg_len = (int)strlen(command);
  int payload_len = AGENT_PREAMBLE_LEN+msg_len+bufi+2;
  // Shift the buffer (message)                                                                                                                        
  memmove(buffer+AGENT_PREAMBLE_LEN+msg_len, buffer, bufi);
  // Fill in the preamble                                                                                                                              
  memcpy(buffer,AGENT_PREAMBLE, AGENT_PREAMBLE_LEN);
  // Fill in the msg len                                                                                                                               
  memcpy(buffer+AGENT_PREAMBLE_LEN, command, msg_len);
  // Append the closing CRLF                                                                                                                           
  memcpy(buffer+AGENT_PREAMBLE_LEN+msg_len+bufi, "\r\n", 2);
  buffer[payload_len] = 0;

  if (REDIS != NULL) {
    redisAppendFormattedCommand(REDIS,buffer, payload_len);
    redisReply *reply;
    redisGetReply(REDIS, (void*)&reply);
    freeReplyObject(reply);
  }

}

static void add_srcip_count(double network_time, const char* srcip) {
  // Add to event cache. Flushed when we dump per second stats
  int now = (int)network_time;
  uint8_t Index[256];
  strcpy((char*)Index, srcip);
  struct IP_Info* info = NULL;
  PWord_t PV = NULL;
  pthread_mutex_lock(&timer_lock);
  COUNT_CNT++;
  JSLG(PV, COUNT_CACHE, Index);
  if (PV != NULL) {
    info = (struct IP_Info*)*PV;
    info->cnt++;
    COUNT_TOTAL++;
  } else {
    info = (struct IP_Info*)malloc(sizeof(struct IP_Info));
    info->first_issued = now;
    info->cnt = 1;
    JSLI(PV, COUNT_CACHE, Index);
    *PV = (long)info;
  }
  pthread_mutex_unlock(&timer_lock);
}

static void add_srcip(double network_time, const char* proto, const char* srcip, uint port) {
  // Add to event cache. Flushed when we dump per second stats
  char* val = (char*)malloc(256);
  sprintf(val, "%f,%s,%s,%d", network_time, proto, srcip, port);
  PWord_t PV = NULL;
  pthread_mutex_lock(&timer_lock);
  ++SRCIP_COUNT;
  JError_t J_Error;
  if (((PV) = (PWord_t)JudyLIns(&SRCIP_CACHE, SRCIP_COUNT, &J_Error)) == PJERR) {
    J_E("JudyLIns", &J_Error);
  }
  *PV = (Word_t)val;
  pthread_mutex_unlock(&timer_lock);
}

static void add_user_agent(double start, const char* srcip, unsigned int id, unsigned char tos, unsigned char ttl, uint port, const char* agent) {
  // printf("%s %d %s\n", srcip, port, agent);

  uint8_t Index[256];
  strcpy((char*)Index, agent);
  struct AgentInfo *info = NULL;
  PWord_t PV;
  pthread_mutex_lock(&timer_lock);
  JSLG(PV, AGENT_CACHE, Index);
  if (PV != NULL) {
    info = (struct AgentInfo*)*PV;
    info->cnt++;
  } else {
    info = (struct AgentInfo*)malloc(sizeof(struct AgentInfo));
    info->cnt = 1;
    info->total = 0;
    JSLI(PV, AGENT_CACHE, Index);
    *PV = (long)info;
  }
  ++REQS;
  pthread_mutex_unlock(&timer_lock);
}

static void flush_srcip_cache(double network_time) {
  char buffer[32*1024];
  Word_t delta = SRCIP_COUNT - SRCIP_TOTAL;
  SRCIP_TOTAL = SRCIP_COUNT;

  if (delta > 0) {
    uint bufi = 0;

    // Dump cached events and publish them
    Word_t cache_count = 0;
    PWord_t PV = NULL;
	
    sprintf(buffer, "PUBLISH %s ", SRCIP_CHANNEL);
    bufi = strlen(buffer);
    buffer[bufi] = 0;

    Word_t Index;
    JError_t J_Error;
    if (((PV) = (PWord_t)JudyLFirst(SRCIP_CACHE, &Index, &J_Error)) == PJERR) J_E("JudyLFirst", &J_Error);
	
    while (PV != NULL) {
      ++cache_count;
      const char* val = (const char*)*PV;
      // fprintf(stderr, "%s\n", val);
      uint len = strlen(val);
      if (bufi + len > sizeof(buffer)) {
	// fprintf(stderr, "%s\n", buffer);
	if (REDIS != NULL) {
	  redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
	  freeReplyObject(reply);
	}
	sprintf(buffer, "PUBLISH %s ", SRCIP_CHANNEL);
	bufi = strlen(buffer);
	buffer[bufi] = 0;
      } 

      // Cache the value
      if (bufi > 30) {
	buffer[bufi++] = '|';
      }
      memcpy(buffer+bufi, val, len);
      bufi += len;
      buffer[bufi] = 0;
	  
      free((void*)val);
      JError_t J_Error;
      if (((PV) = (PWord_t)JudyLNext(SRCIP_CACHE, &Index, &J_Error)) == PJERR) J_E("JudyLNext", &J_Error);
    }
	
    // Cleanup array
    Word_t index_size;  
    JLFA(index_size, SRCIP_CACHE);
	
    if (DEBUG) fprintf(stderr, "%s\n", buffer);
    // fprintf(stderr, "%f srcip index used %lu bytes of memory, total cache cost: %lu expected=%lu found=%lu total=%lu\n", network_time, index_size, (cache_count*48)+index_size, delta, cache_count, SRCIP_TOTAL);
    if (REDIS != NULL) {
      redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
      freeReplyObject(reply);
    }
  }

}

static Word_t flush_agent_cache(double network_time) {

  // Emit 32K of msg telemetry at a time
  uint8_t key[256];
  char buffer[32*1024];
  uint bufi = 0;
  // Dump cached events and publish them                                                                                                               
  Word_t cache_count = 0;
  PWord_t PV = NULL;
  Word_t reqs = 0;

  if (REQS > 0) {

    // Init for publishing.                                                                                                                            
    buffer[bufi] = 0;

    pthread_mutex_lock(&timer_lock);
    reqs = REQS;
    AGENT_TOTAL += REQS;
    REQS = 0;
    pthread_mutex_unlock(&timer_lock);

    key[0] = 0;
    JSLF(PV, AGENT_CACHE, key);
    while (PV != NULL) {
      cache_count++;
      struct AgentInfo *info = (struct AgentInfo*)*PV;
      // fprintf(stderr, "  '%s',%d\n", key, info->cnt);                                                                                               
      if (info->cnt > 0) {
        char agent_info[512];
        sprintf(agent_info, "%f,UA,'%s',%d,%d", network_time, key, info->cnt, info->total);
        size_t len = strlen(agent_info);

        if ((bufi + len + AGENT_PREAMBLE_LEN) > sizeof(buffer)) {
          // Flush and reset buffer                                                                                                                    
          publish_agent_telemetry(buffer, bufi);
          bufi = 0;
        }

        // Get ready for the next item, if we've already got an item, add delimeter                                                                    
        if (bufi > 20) {
          buffer[bufi++] = '|';
        }

        pthread_mutex_lock(&timer_lock);

        char telemetry[512];
        info->total += info->cnt;
        sprintf(telemetry, "%f,UA,'%s',%d,%d", network_time,key, info->cnt, info->total);
        size_t linelen = strlen(telemetry);
        memcpy(buffer+bufi, telemetry, linelen);
        bufi += linelen;
        buffer[bufi] = 0;
        info->cnt = 0;
        pthread_mutex_unlock(&timer_lock);
      }
      JSLN(PV, AGENT_CACHE, key);
    }

    publish_agent_telemetry(buffer, bufi);
    bufi = 0;

    pthread_mutex_lock(&timer_lock);
    AGENT_COUNT = cache_count;
    pthread_mutex_unlock(&timer_lock);

  }

  return reqs;
}

static Word_t flush_count_cache(double network_time) {

  // NOT IMPL YET. 
  return 0;
}


static void redis_flush() {

  // ------------------------------------------------------------                                                                                      
  // Flush telemetry events                                                                                                                            
  // ------------------------------------------------------------                                                                                      

  double start = current_time();
  flush_srcip_cache(start);
  Word_t reqs = flush_agent_cache(start);
  if (COUNT_TRACK)
    flush_count_cache(start);

  // Emit health heartbeat                                                                                                                             
  if (REDIS != NULL) {
    char buffer[256];
    sprintf(buffer, "PUBLISH %s %f,R,%lu,%lu,%lu", AGENT_CHANNEL, start, reqs, AGENT_COUNT, AGENT_TOTAL);
    redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
    freeReplyObject(reply);
  }

}

static pcap_t* open_pcap(char* device, const char* filter) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pd;
  uint32_t  srcip, netmask;
  struct bpf_program  bpf;

  // Start live capture
  if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
      printf("pcap_open_live(): %s\n", errbuf);
      return NULL;
    }

  // Get network device source IP address and netmask.
  if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
      printf("pcap_lookupnet: %s\n", errbuf);
      return NULL;
    }

  // Convert the packet filter epxression into a packet filter binary.
  if (pcap_compile(pd, &bpf, filter, 0, netmask))
    {
      printf("pcap_compile(): %s\n", pcap_geterr(pd));
      return NULL;
    }

  // Assign the packet filter to the given libpcap socket.
  if (pcap_setfilter(pd, &bpf) < 0)
    {
      printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
      return NULL;
    }
  return pd;
}

static void parse_packet(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr) {
  struct ip* iphdr;
  double start = current_time();
  char srcip[256];
  packetptr += linkhdrlen;
  iphdr = (struct ip*)packetptr;
  strcpy(srcip, inet_ntoa(iphdr->ip_src));
  packetptr += 4*iphdr->ip_hl;
  if (iphdr->ip_p == IPPROTO_TCP) {
    struct tcphdr* tcphdr = (struct tcphdr*)packetptr;
    int port = ntohs(tcphdr->source);
    // if (DEBUG) printf("TCP  %s:%d\n", srcip, ntohs(tcphdr->source));
    add_srcip(start, "TCP", srcip, port);
    if (COUNT_TRACK)
      add_srcip_count(start, srcip);

    if (AGENT_TRACK && ntohs(tcphdr->dest) == 80) {
      // Until we can crack the agent header ... substitute one for now
      add_user_agent(start, srcip, ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, port, "unknown");
    }
  }
  else if (iphdr->ip_p == IPPROTO_UDP) {
    struct udphdr* udphdr = (struct udphdr*)packetptr;
    // if (DEBUG) printf("UDP  %s:%d\n", srcip, ntohs(udphdr->source));
    add_srcip(start, "UDP", srcip, ntohs(udphdr->source));
  }
}

static void usage(const char* program, const char* default_filter) {
  printf("usage: %s [-h] [-a CHANNEL] [-c CHANNEL] [-d] -i INTERFACE [filter...]\n", program);
  printf("  [-a CHANNEL] - enable user agent tracking (partially working) and channel, ONLY applies to 'tcp port 80'\n");
  printf("  [-c CHANNEL] - pubsub channel, defaults to 'srcip'\n");
  printf("  [-d]         - debug output\n");
  printf("  [-h]         - show this help message\n");
  printf("  [-k CHANNEL] - enable client kount tracking and channel\n");
  printf("  [-s SERVER]  - change the server (defaults to 127.0.0.1)\n");
  printf("  [filter...] %s\n", default_filter);
}

static void endprocess(int signo) {
  pcap_close(pd);
  redis_term();
  exit(0);
}


int main(int argc, char **argv) {
  char interface[256] = "", filter[256] = "tcp port 80 and tcp[13] == 2";
  int packets = 0, c;
  // Get the command line options, if any
  while ((c = getopt (argc, argv, "a:c:dhi:k:s:")) != -1) {
    switch (c)
      {
      case 'a':
	AGENT_TRACK = 1;
	strcpy(AGENT_CHANNEL, optarg);
	break;
      case 'c':
	strcpy(SRCIP_CHANNEL, optarg);
	break;
      case 'd':
	DEBUG = 1;
	break;
      case 'h':
	usage(argv[0], filter);
	exit(0);
	break;
      case 'i':
	strcpy(interface, optarg);
	break;
      case 'k':
	COUNT_TRACK = 1;
	strcpy(COUNT_CHANNEL, optarg);
	break;
      case 's':
	strcpy(REDIS_SERVER, optarg);
	break;
      }
  }

  if (interface[0] == 0) {
    // Bail
    usage(argv[0], filter);
    exit(0);
  }

  // Maybe override our default filter
  int i;
  char custom_filter[256] = "";
  for (i = optind; i < argc; i++) {
    strcat(custom_filter, argv[i]);
    strcat(custom_filter, " ");
  }
  if (custom_filter[0] != 0) strcpy(filter, custom_filter);

  printf("REDIS=%s SRCIP_CHANNEL='%s' COUNT_CHANNEL='%s' AGENT_CHANNEL='%s' DEBUG=%d FILTER='%s'\n", REDIS_SERVER, SRCIP_CHANNEL, COUNT_CHANNEL, AGENT_CHANNEL, DEBUG, filter); 
  if (AGENT_TRACK) 
    printf("AGENT enabled, CHANNEL=%s\n", AGENT_CHANNEL);

  // Open libpcap, set the program termination signals then start
  // processing packets.
  if ((pd = open_pcap(interface, filter))) {

    // Init redis connection
    redis_init();

    signal(SIGINT, endprocess);
    signal(SIGTERM, endprocess);
    signal(SIGQUIT, endprocess);

    // capture_loop(pd, packets, (pcap_handler)parse_packet);

    int linktype;
    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
      {
	printf("pcap_datalink(): %s\n", pcap_geterr(pd));
	exit(0);
      }
 
    // Setup datalink header size.
    switch (linktype)
      {
      case DLT_NULL:
	linkhdrlen = 4;
	break;
      case DLT_EN10MB:
	linkhdrlen = 14;
	break;
      case DLT_SLIP:
      case DLT_PPP:
	linkhdrlen = 24;
	break;
      default:
	printf("Unsupported datalink (%d)\n", linktype);
	exit(0);
      }
 
    // Start capturing packets.
    if (pcap_loop(pd, packets, (pcap_handler)parse_packet, 0) < 0)
      printf("pcap_loop failed: %s\n", pcap_geterr(pd));

    endprocess(0);
  }
  exit(0);
}
