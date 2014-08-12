//
// Examples -- nearly identical to TCPDUMP since BPF filters are part of this implementation
//
// 
// sudo ./srcip -i eth0 'tcp dst port 8080 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
//
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
#include <pthread.h>

#define MAXLINELEN 1024
#include "Judy.h"
#include "hash.h"
#include "redblack.h"

pcap_t* pd;
int linkhdrlen;

pthread_mutex_t timer_lock=PTHREAD_MUTEX_INITIALIZER;

int     PACKET_DUMP = 0;

Pvoid_t AGENT_CACHE = (PWord_t) NULL;
Word_t  AGENT_CNT = 0;
Word_t  AGENT_PRV = 0;
Word_t  AGENT_TOTAL = 0;
Word_t  AGENT_UNIQUE = 0;
Word_t  AGENT_NEW = 0;
int     AGENT_PREAMBLE_LEN = 0;
char    AGENT_PREAMBLE[64];
int     DEBUG = 0;
int     AGENT_TRACK = 0;
char    AGENT_CHANNEL[64] = "";
char    AGENT_FILTER[512] = "";

#define FREQ_WINDOW 1
#define FREQ_HISTORY 10

struct AgentInfo {
  uint cnt;
  uint total;
  long int sec;
  uint freq_cnt;
  uint freq_idx;
  Pvoid_t unique;
  uint freq[FREQ_HISTORY];
};

int     COUNT_TRACK = 0;
char    COUNT_CHANNEL[64] = "";
Pvoid_t COUNT_CACHE = (PWord_t) NULL;
Word_t  COUNT_CNT = 0;
Word_t  COUNT_PRV = 0;
Word_t  COUNT_NEW = 0;
Word_t  COUNT_UNIQUE = 0;
Word_t  COUNT_TOTAL = 0;

struct IP_Info {
  uint cnt;
  uint total;
  long int sec;
  uint freq_cnt;
  uint freq_idx;
  uint freq[FREQ_HISTORY];
};

int     SRCIP_TRACK = 0;
Pvoid_t SRCIP_CACHE = (Pvoid_t) NULL;
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

int SHUTDOWN = 0;

static void flush_stats();

void* redis_timer (void * args) {
  while(1) {
    sleep (1);
    if (!SHUTDOWN) {
      flush_stats();
    }
  }
  return NULL;
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

  // if (DEBUG) printf("PUBLISH %s %s\n", AGENT_CHANNEL, buffer);

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

char BUFF_TELEMETRY[512*MAXLINELEN];
Word_t BUFF_PTR = 0;
Word_t BUFF_CNT = 0;

static void add_srcip(long int sec, long int usec, const char* proto, const char* srcip, uint port, uint id) {
  // Add to event cache. Flushed when we dump per second stats. We always use an increasing Word_t as the index into the array
  // for this to avoid collisions.
  char temp[MAXLINELEN];
  PWord_t PV = NULL;
  pthread_mutex_lock(&timer_lock);
  ++SRCIP_COUNT;
  ++BUFF_CNT;
  sprintf(temp, "%lu.%lu,%s,%s,%u,%u", sec, usec, proto, srcip, port, id);
  int len = strlen(temp);
  memcpy(BUFF_TELEMETRY+BUFF_PTR, temp, len);
  BUFF_TELEMETRY[BUFF_PTR+len] = 0;
  // if (DEBUG) fprintf(stderr, "%s\n", BUFF_TELEMETRY+BUFF_PTR);
  JLI(PV, SRCIP_CACHE, SRCIP_COUNT);
  if (PV != NULL)
    *PV = (long)BUFF_TELEMETRY+BUFF_PTR;
  else
    fprintf(stderr, "Failed to insert @ %lu\n", SRCIP_COUNT);
  BUFF_PTR += (len+1);
  pthread_mutex_unlock(&timer_lock);
}

static void flush_srcip_cache(double network_time, int debug, int dump, FILE* f) {
  char buffer[32*MAXLINELEN];

  pthread_mutex_lock(&timer_lock);

  Word_t cache_cnt = 0;
  Word_t Key = 0;
  Word_t index_cnt;
  JLC(index_cnt, SRCIP_CACHE, 0, -1);

  if (SRCIP_COUNT > 0 || dump) {
    uint bufi = 0;

    // Dump cached events and publish them
    PWord_t PV = NULL;
	
    sprintf(buffer, "PUBLISH %s ", SRCIP_CHANNEL);
    bufi = strlen(buffer);
    buffer[bufi] = 0;

    JLF(PV,SRCIP_CACHE, Key);

    while (PV != NULL) {
      cache_cnt += 1;
      const char* val = (const char*)*PV;

      if (dump)
	fprintf(f != NULL ? f : stderr, "%s\n", val);
      else {
	uint len = strlen(val);
	if (bufi + len > sizeof(buffer)) {
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
      }

      // Get next key
      JLN(PV, SRCIP_CACHE, Key);
    }

    // Free array
    Word_t index_size;  
    JLFA(index_size, SRCIP_CACHE);

    if (BUFF_CNT != cache_cnt)
      fprintf(stderr, "  ERROR index_delta != cache_count\n");

    if (REDIS != NULL) {
      redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
      freeReplyObject(reply);
    }

    if (debug) {
      double now = current_time();
      double lag = now - network_time;
      printf("%f,IP,%f,%lu,%lu\n", network_time, lag, SRCIP_COUNT, BUFF_PTR);
    }

    BUFF_PTR = 0;
    BUFF_CNT = 0;
    SRCIP_COUNT = 0;

  }

  pthread_mutex_unlock(&timer_lock);
}

char UA_TELEMETRY[10*1024*MAXLINELEN];
Word_t UA_PTR = 0;
uint8_t UA_INDEX[MAXLINELEN];


#define AGENT_GET(KEY, VAL)   JSLG(VAL, AGENT_CACHE, (uint8_t *) KEY);
#define AGENT_SET(KEY, VAL)				\
{                                                       \
        PWord_t _PValue;                                \
        JSLI(_PValue, AGENT_CACHE, (uint8_t *) KEY);    \
	*_PValue = (long)VAL;                           \
}
#define AGENT_FIRST(KEY, VAL) JSLF(VAL, AGENT_CACHE, (uint8_t *) KEY); 
#define AGENT_NEXT(KEY, VAL)  JSLN(VAL, AGENT_CACHE, (uint8_t *) KEY);    

// SRCIP COUNT MACROS
#define COUNT_GET(KEY, VAL) JLG(VAL, COUNT_CACHE, KEY);
#define COUNT_SET(KEY, VAL)				\
{                                                       \
        PWord_t _PValue;                                \
        JLI(_PValue, COUNT_CACHE, KEY);    \
	*_PValue = (long)VAL;                           \
}

#define COUNT_FIRST(KEY, VAL) JLF(VAL, COUNT_CACHE, KEY); 
#define COUNT_NEXT(KEY, VAL)  JLN(VAL, COUNT_CACHE, KEY);    

HASHREC** AGENT_TABLE = NULL;
HASHREC** COUNT_TABLE = NULL;

void init_hash_tables() {
  AGENT_TABLE = inithashtable();
  COUNT_TABLE = inithashtable();
}

#define HASH_AGENT_SET(KEY,VALUE)   hashinsert(AGENT_TABLE, (char*)KEY, (long)VALUE)
#define HASH_AGENT_GET(KEY, VALUE)              		\
{                                                               \
        VALUE = NULL;                                           \
        HASHREC *temp = hashsearch(AGENT_TABLE, (char*)KEY);	\
	if (temp != NULL) VALUE = (PWord_t)&temp->val;		\
}
#define HASH_AGENT_FIRST(KEY, VALUE)  \
    HASHREC *temp = hashfirst(AGENT_TABLE);\
    if (temp) {\
      VALUE = (PWord_t)&temp->val;\
      strcpy((char*)KEY, temp->key);\
    } else {\
      VALUE = NULL;\
    }

#define HASH_AGENT_NEXT(KEY, VALUE)\
        temp = hashnext(AGENT_TABLE, temp);\
        if (temp) {\
	  VALUE = (PWord_t)&temp->val;\
	  strcpy((char*)KEY,temp->key);\
        } else {\
	  VALUE = NULL;\
        }

#define HASH_COUNT_SET(KEY,VALUE)   hashinsert(COUNT_TABLE, (char*)KEY, (long)VALUE)
#define HASH_COUNT_GET(KEY, VALUE)              		\
{                                                               \
        VALUE = NULL;                                           \
        HASHREC *temp = hashsearch(COUNT_TABLE, (char*)KEY);	\
	if (temp != NULL) VALUE = (PWord_t)&temp->val;		\
}
#define HASH_COUNT_FIRST(KEY, VALUE, ITER)		\
    ITER = hashfirst(COUNT_TABLE);\
    if (ITER) {\
      VALUE = (PWord_t)&ITER->val;\
      strcpy((char*)KEY, ITER->key);\
    } else {\
      VALUE = NULL;\
    }

#define HASH_COUNT_NEXT(KEY, VALUE, ITER)		\
        ITER = hashnext(COUNT_TABLE, ITER);\
        if (ITER != NULL) {\
	  VALUE = (PWord_t)&ITER->val;\
	  strcpy((char*)KEY,ITER->key);\
        } else {\
	  VALUE = NULL;\
        }

// ------------------------------------------------------------

ANSREC AGENT_TREE = {0};
#define RB_AGENT_GET(KEY, VALUE)  redblacksearch(&AGENT_TREE, (char*)KEY);  if (AGENT_TREE.ans != NULL)  VALUE = (PWord_t)&AGENT_TREE.ans->val; else VALUE = NULL;
#define RB_AGENT_SET(KEY, VALUE)  redblackinsert(&AGENT_TREE, (char*)KEY, (long)VALUE);
#define RB_AGENT_FIRST(KEY, VALUE) \
    redblack_iterator iter = rbt_begin(&AGENT_TREE);\
    TREEREC* temp = (TREEREC*)iter;\
    if (temp != NULL) {\
      strcpy((char*)key, temp->key);\
      PV = (PWord_t)&temp->val;\
    }\
    else\
      PV = NULL;

#define RB_AGENT_NEXT(KEY, VALUE) \
      PV = NULL;\
      iter = rbt_next(&AGENT_TREE, iter);\
      TREEREC* temp = (TREEREC*)iter;\
      if (iter != NULL) {\
	strcpy((char*)key, temp->key);\
	PV = (PWord_t)&temp->val;\
      }\


ANSREC COUNT_TREE = {0};
#define RB_COUNT_GET(KEY, VALUE)  redblacksearch(&COUNT_TREE, (char*)KEY);  if (COUNT_TREE.ans != NULL)  VALUE = (PWord_t)&COUNT_TREE.ans->val; else VALUE = NULL;
#define RB_COUNT_SET(KEY, VALUE)  redblackinsert(&COUNT_TREE, (char*)KEY, (long)VALUE);
#define RB_COUNT_FIRST(KEY, VALUE, ITER)		\
    ITER = rbt_begin(&COUNT_TREE);\
    TREEREC* temp = (TREEREC*)ITER;\
    if (temp != NULL) {\
      strcpy((char*)key, temp->key);\
      PV = (PWord_t)&temp->val;\
    }\
    else\
      PV = NULL;

#define RB_COUNT_NEXT(KEY, VALUE, ITER) \
      PV = NULL;\
      ITER = rbt_next(&COUNT_TREE, ITER);\
      TREEREC* temp = (TREEREC*)iter;\
      if (temp != NULL) {\
	strcpy((char*)key, temp->key);\
	PV = (PWord_t)&temp->val;\
      }\


void print_agent_tree(TREEREC* node) {
  if (node == NULL) {
    return;
  }
  if (node->right != NULL) {
    print_agent_tree(node->right);
  }

  struct AgentInfo *info = (struct AgentInfo*)node->val;
  fprintf(stderr, "%d\t'%s' color=%d\n", info->total, node->key, node->color);

  if (node->left != NULL) {
    print_agent_tree(node->left);
  }
}

static int add_user_agent(long int sec, long int usec, const char* srcip, struct in_addr addr, unsigned int id, uint port, const char* agent, const uint ua_len) {

  int result = 0;
  PWord_t PV;
  struct AgentInfo *info = NULL;
  if (ua_len > sizeof(UA_INDEX)) {
    printf("ERROR: UA len=%u\n", ua_len);
  } else {
    memcpy(UA_INDEX, agent, ua_len);
  }

  pthread_mutex_lock(&timer_lock);
  AGENT_CNT += 1;

  // AGENT_GET(UA_INDEX, PV);
  // HASH_AGENT_GET(UA_INDEX, PV);
  RB_AGENT_GET(UA_INDEX, PV);

  Word_t PV_IP;

  if (PV != NULL) {
    AGENT_PRV += 1;
    info = (struct AgentInfo*)*PV;
    info->cnt += 1;
    info->total += 1 ;
    // Update unique count bitmap
    J1S(PV_IP, info->unique, addr.s_addr);
    if (sec >= (info->sec+FREQ_WINDOW)) {
      // Note current cnt, next frequency will be calculated based on it
      memmove(&info->freq[1], &info->freq[0], (FREQ_HISTORY-1)*sizeof(uint));
      info->freq[0] = info->cnt - info->freq_cnt;
      info->freq_cnt = info->cnt;
      info->sec = sec;
    }
    result = 1;
  } else {
    if (UA_PTR < sizeof(UA_TELEMETRY)) {
      info = (struct AgentInfo*)(UA_TELEMETRY + UA_PTR);
      info->cnt = 1;
      info->total = 1;
      info->freq_idx = 0;
      info->unique = NULL;
      memset(&info->freq, 0, sizeof(uint)*FREQ_HISTORY);
      // Add count for this new IP
      J1S(PV_IP, info->unique, addr.s_addr);
      UA_PTR += sizeof(struct AgentInfo);
      AGENT_NEW += 1;
      
      // AGENT_SET(UA_INDEX, info);
      // HASH_AGENT_SET(UA_INDEX, info);
      RB_AGENT_SET(UA_INDEX, info);
    } else {
      printf("WARN: OOM, ignoring new agent: %s\n", agent);
    }
  }
  pthread_mutex_unlock(&timer_lock);
  return result;
}

static Word_t flush_agent_cache(double network_time, int debug, int dump, FILE* f) {
  
  // Emit 32K of msg telemetry at a time
  uint8_t key[MAXLINELEN];
  char buffer[32*MAXLINELEN];
  
  if (!SHUTDOWN)
    pthread_mutex_lock(&timer_lock);

  // Dump cached events and publish them                                                                                                               
  PWord_t PV = NULL;
  Word_t reqs = 0;

  if (AGENT_CNT > 0 || dump) {

    uint bufi = 0;
    // Init for publishing.                                                                                                                            
    buffer[bufi] = 0;
    if (!dump)
      reqs = AGENT_CNT;

    key[0] = '\0';

    // AGENT_FIRST(key, PV);
    // HASH_AGENT_FIRST(key, PV);
    RB_AGENT_FIRST(key, PV);

    while (PV != NULL) {
      struct AgentInfo *info = (struct AgentInfo*)*PV;

      if (dump) {
	Word_t unique_count;
	reqs++;
	J1C(unique_count, info->unique, 0, -1);
	fprintf(f != NULL ? f : stderr, "%d\t%lu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t'%s'\n", info->total, unique_count, info->freq[0], info->freq[1], info->freq[2], info->freq[3], info->freq[4], info->freq[5], info->freq[6], info->freq[7], info->freq[8], info->freq[9], key);
      } 

      if (info->cnt > 0) {
        char agent_info[1024];
        snprintf(agent_info, sizeof(agent_info), "%f,UA,%u,%u,%u,%u,%u,%u,%u,%s", network_time, info->total, info->cnt, info->freq[0], info->freq[1], info->freq[2], info->freq[3], info->freq[4], key);
        size_t len = strlen(agent_info);
	
	// if (debug) printf("%s\n", agent_info);

        if ((bufi + len + AGENT_PREAMBLE_LEN) > sizeof(buffer)) {
          // Flush and reset buffer                                                                                                                    
          publish_agent_telemetry(buffer, bufi);
          bufi = 0;
        }

	if (bufi > 20) {
          buffer[bufi++] = '|';
        }

        memcpy(buffer+bufi, agent_info, len);
        bufi += len;
      }

      // AGENT_NEXT(key, PV);
      // HASH_AGENT_NEXT(key, PV);
      RB_AGENT_NEXT(key, PV);
    }

    int bufsize = bufi;
    bufi = 0;
    
    if (!dump) {      
      if (bufsize > 0)
	publish_agent_telemetry(buffer, bufsize);
    }

  }

  if (!dump) {
    AGENT_UNIQUE += AGENT_NEW;
    AGENT_TOTAL += AGENT_CNT;
  }

  if (debug) {
    double now = current_time();
    double lag = now - network_time;
    printf("%f,UA,%f,%lu,%lu,%lu,%lu,%lu\n", network_time, lag, AGENT_CNT, AGENT_PRV, AGENT_NEW, AGENT_UNIQUE, AGENT_TOTAL);
  }

  AGENT_NEW = 0;
  AGENT_PRV = 0;
  AGENT_CNT = 0;

  if (f != NULL) {
    fflush(f);
  }

  if (!SHUTDOWN)
    pthread_mutex_unlock(&timer_lock);

  return reqs;
}

int COUNT_ALGO = 0;		/* 0 - Judy, 1 - redblack, 2 - hash */
char COUNT_ALGO_STR[32];

char COUNT_TELEMETRY[48*1024*1024];
Word_t COUNT_PTR = 0;

static void add_srcip_count(long int sec, long int usec, const char* srcip, struct in_addr addr) {
  // Add to event cache.
  pthread_mutex_lock(&timer_lock);
  struct IP_Info* info = NULL;
  PWord_t PV = NULL;
  COUNT_CNT += 1;
  switch (COUNT_ALGO) {
  case 0:
    // Use JUDY Array
    COUNT_GET(addr.s_addr, PV); break;
  case 1:
    // Use REDBLACK tree
    RB_COUNT_GET(srcip, PV);
    break;
  case 2:
    // Use Simple HASH
    HASH_COUNT_GET(srcip, PV);
    break;
  }

  if (PV != NULL) {
    info = (struct IP_Info*)*PV;
    info->cnt++;
    if (sec > info->sec+FREQ_WINDOW) {
      // Note current cnt, next frequency will be calculated based on it
      info->freq[info->freq_idx++] = info->cnt - info->freq_cnt;
      info->freq_cnt = info->cnt;
      if (info->freq_idx == FREQ_HISTORY) info->freq_idx = 0;
    }
    COUNT_PRV += 1;
  } else {
    if (COUNT_PTR < sizeof(COUNT_TELEMETRY)) {
      info = (struct IP_Info*)(COUNT_TELEMETRY + COUNT_PTR);
      COUNT_PTR += sizeof(struct IP_Info);
    } else {
      // printf("WARN: OOM for pre-allocated memory\");
      info = (struct IP_Info*)malloc(sizeof(struct IP_Info));
    }
    COUNT_NEW += 1;
    info->cnt = 0;
    info->total = 1;
    info->sec = sec;
    info->freq_idx = 0;
    info->freq_cnt = 0;
    memset(&info->freq, 0, sizeof(uint)*FREQ_HISTORY);
    switch (COUNT_ALGO) {
    case 0:
      COUNT_SET(addr.s_addr, info); break;
    case 1:
      RB_COUNT_SET(srcip, info);
      break;
    case 2:
      HASH_COUNT_SET(srcip, info);
      break;
    }
  }
  pthread_mutex_unlock(&timer_lock);
}

Word_t flush_count_cache(double network_time, int debug, int dump, FILE* f) {

  // Emit 32K of msg telemetry at a time
  uint8_t key[256];
  char buffer[32*MAXLINELEN];

  if (!SHUTDOWN)
    pthread_mutex_lock(&timer_lock);

  uint bufi = 0;
  // Dump cached events and publish them                                                                                                               
  PWord_t PV = NULL;
  Word_t result = 0; // COUNT_CNT;

  if (COUNT_CNT > 0 || dump) {

    // Init for publishing.                                                                                                                            
    sprintf(buffer, "PUBLISH %s ", COUNT_CHANNEL);
    bufi = strlen(buffer);
    buffer[bufi] = 0;

    key[0] = 0;
    Word_t key32 = 0;
    redblack_iterator iter = NULL;
    HASHREC* hashiter = NULL;
    switch(COUNT_ALGO) {
    case 0: {
      COUNT_FIRST(key32, PV);break;
    }
    case 1:
      RB_COUNT_FIRST(key, PV, iter);break;
    case 2: 
      {
	HASH_COUNT_FIRST(key, PV, hashiter);break;
      }
    }

    while (PV != NULL) {
      struct IP_Info *info = (struct IP_Info*)*PV;
      char telemetry[512];

      if (dump) {
	struct in_addr addr;
	addr.s_addr = key32;
	fprintf(f != NULL ? f : stderr ,"%d\t%s\n", info->total, inet_ntoa(addr));
	++result;
      }
      else if (info->cnt > 0) {

        info->total += info->cnt;
        sprintf(telemetry, "%f,IP,'%s',%d,%d", network_time, key, info->cnt, info->total);
        size_t linelen = strlen(telemetry);

        if ((bufi + linelen) > sizeof(buffer)) {
	  if (REDIS != NULL) {
	    redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
	    freeReplyObject(reply);
	  }
	  sprintf(buffer, "PUBLISH %s ", COUNT_CHANNEL);
	  bufi = strlen(buffer);
	  buffer[bufi] = 0;
        }

        // Get ready for the next item, if we've already got an item, add delimeter                                                                    
        if (bufi > 20) {
          buffer[bufi++] = '|';
        }

        memcpy(buffer+bufi, telemetry, linelen);
        bufi += linelen;
        buffer[bufi] = 0;
	// Not freeing up memory ... could exhaust if we get exhausted by spoofed set of SRCIPs.
	// Reset count to 0 for next cycle
        info->cnt = 0;
      }
      switch(COUNT_ALGO) {
      case 0:
	COUNT_NEXT(key32, PV);break;
      case 1:
	RB_COUNT_NEXT(key, PV, iter);break;
      case 2:
	HASH_COUNT_NEXT(key, PV, hashiter);break;
      }
    }

    // if (DEBUG) printf("%s\n", buffer);
    if (!dump) {
      if (REDIS != NULL) {
	redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
	freeReplyObject(reply);
      }
    }

  }

  if (debug) {
    double now = current_time();
    double lag = now - network_time;
    printf("%f,COUNT,%f,%lu,%lu,%lu,%lu,%lu\n", network_time, lag, COUNT_CNT, COUNT_PRV, COUNT_NEW, COUNT_UNIQUE+COUNT_NEW, COUNT_TOTAL+COUNT_CNT);
  }
  
  if (!dump) {
    COUNT_TOTAL += COUNT_CNT;
    COUNT_UNIQUE += COUNT_NEW;
    COUNT_NEW = 0;
    COUNT_PRV = 0;
    COUNT_CNT = 0;
  } 

  if (f != NULL) {
    fflush(f);
  }

  if (!SHUTDOWN)
    pthread_mutex_unlock(&timer_lock);

  return result;
}


static void flush_stats() {

  // ------------------------------------------------------------
  // Flush telemetry events                                                                                                                             // ------------------------------------------------------------                                                                                      
  double start = current_time();

  if (SRCIP_TRACK)
    flush_srcip_cache(start, DEBUG, 0, 0);
  
  if (AGENT_TRACK)
    flush_agent_cache(start, DEBUG, 0, 0);

  if (COUNT_TRACK)
    flush_count_cache(start, DEBUG, 0, 0);

  /*
  // Emit health heartbeat                                                                                                                             
  if (REDIS != NULL) {
    char buffer[256];
    sprintf(buffer, "PUBLISH %s %f,R,%lu,%lu", AGENT_CHANNEL, start, AGENT_CNT, AGENT_TOTAL);
    redisReply *reply = (redisReply*)redisCommand(REDIS, buffer);
    freeReplyObject(reply);
  }
  */

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

#define ASCII_LINELENGTH 300
#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE  (HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)

void
hex_and_ascii_print_with_offset(register const char *ident, register const u_char *cp, register u_int length, register u_int oset)
{
  register u_int i;
  register int s1, s2;
  register int nshorts;
  char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
  char asciistuff[ASCII_LINELENGTH+1], *asp;

  nshorts = length / sizeof(u_short);
  i = 0;
  hsp = hexstuff; asp = asciistuff;
  while (--nshorts >= 0) {
    s1 = *cp++;
    s2 = *cp++;
    (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
		   " %02x%02x", s1, s2);
    hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
    *(asp++) = (isgraph(s1) ? s1 : '.');
    *(asp++) = (isgraph(s2) ? s2 : '.');
    i++;
    if (i >= HEXDUMP_SHORTS_PER_LINE) {
      *hsp = *asp = '\0';
      (void)printf("%s0x%04x: %-*s  %s",
		   ident, oset, HEXDUMP_HEXSTUFF_PER_LINE,
		   hexstuff, asciistuff);
      i = 0; hsp = hexstuff; asp = asciistuff;
      oset += HEXDUMP_BYTES_PER_LINE;
    }
  }
  if (length & 1) {
    s1 = *cp++;
    (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
		   " %02x", s1);
    hsp += 3;
    *(asp++) = (isgraph(s1) ? s1 : '.');
    ++i;
  }
  if (i > 0) {
    *hsp = *asp = '\0';
    (void)printf("%s0x%04x: %-*s  %s",
		 ident, oset, HEXDUMP_HEXSTUFF_PER_LINE,
		 hexstuff, asciistuff);
  }
}

void hex_and_ascii_print(register const char *ident, register const u_char *cp, register u_int length)
{
  hex_and_ascii_print_with_offset(ident, cp, length, 0);
}

static int request_is_complete(const u_char *req, uint len) {
  // Request is complete if we've got a CRLFCRLF
  char CRLFCRLF[] = "\r\n\r\n";
  int n = 0;
  for(n=0; n < len-4; n++) {
    if (memcmp(req+n,CRLFCRLF,4) == 0)
      return 1;
  }
  /*
  if (strstr((char*)req, "\r\n\r\n") != NULL) {
    return 1;
  }
  */
  return 0;
}

int find_ip(char **str)
{ char *token;
  char *search = ",";
  struct addrinfo hint, *res = NULL;

  memset(&hint, 0, sizeof(struct addrinfo));
  hint.ai_family = PF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;

  token = strtok(*str, search);

  while(token != NULL)
  {
    /* trim off leading whitespace from the string */
    while(isspace(*token)) token++;

    if(!(getaddrinfo(token, NULL, &hint, &res)))
    {
      /* found a valid IPv4 or IPv6 address */
      char buf[NI_MAXHOST];

      getnameinfo(res->ai_addr, res->ai_addrlen, buf, sizeof(buf), NULL, 0,
                  NI_NUMERICHOST);

      *str = buf;
      freeaddrinfo(res);
      return 1;
    }

    /* not found in that token, try another */
    token = strtok(NULL, search);
  }

  /* never found one. return in shame. */
  return 0;
}

static uint request_clientip(const u_char *req, const uint pktlen, char* clientip, uint clientip_len) {
  const char* cip = "Client-IP:";
  const char* header = strstr((char*)req, cip);
  uint hlen = strlen(cip);
  if (header == NULL) {
    const char* xff = "X-Forwarded-For:";
    header = strstr((char*)req, xff);
    hlen = strlen(xff);
  }
  if (header != NULL) {
    // Extract up to the terminating CRLF.
    char* header_end = strstr(header+hlen, "\r\n");
    if (header_end != NULL) {
      uint len = header_end - header;
      len -= hlen;

      if (header[hlen] == 32)
        memcpy(clientip, header+hlen+1, --len);
      else
	memcpy(clientip, header+hlen, len);

      clientip[len] = 0;

      find_ip(&clientip);

      /*
      // Trim trailing whitespace
      char* end = clientip+len-1;
      while(end > clientip && isspace(*end)) {
	len--;
	end--;
      }
      // Write new null terminator
      *(end+1) = 0;

      return len;
      */

      return strlen(clientip);
      
    }
  } 
  clientip[0] = 0;
  return 0;
}

static uint request_user_agent(const u_char *req, const uint pktlen, char* ua, uint ua_len) {
  // Quick and dirty. We only attempt to find User-Agent
  char user_agent[] = "User-Agent:";
  int n;
  // const char* agent = strstr((char*)req, "User-Agent:");
  char* agent = NULL;
  for (n = 0; n < pktlen - 11; n++) {
    if (memcmp(req+n, user_agent, 11) == 0) {
      agent = (char*)req+n;
      break;
    }
  }

  if (agent != NULL) {
    // Extract up to the terminating CRLF.
    char* agent_end = strstr(agent+11, "\r\n");
    if (agent_end != NULL) {
      uint len = agent_end - agent;
      len -= 11;
      // Strip leading space if present                                                                                                                
      if (agent[11] == 32)
        memcpy(ua, agent+12, len-1);
      else
        memcpy(ua, agent+11, len);
      ua[len-1] = 0;

      // Replace \n and all non-printable characters and > 127 chars with a ' '
      uint i;
      for (i =0; i < len-1; i++) {
	if ((u_char)ua[i] >= 127 || ua[i] < 32) 
	  ua[i] = ' ';
      }
      return len;
    }
  } 
  ua[0] = '-';
  ua[1] = 0;
  return 2;
}

static void parse_packet(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

  if (SHUTDOWN) return;

  struct ip* iphdr;
  const struct timeval *tvp = &packethdr->ts;
  // double start = (tvp->tv_sec) + (tvp->tv_usec / 1000000.0);
  long int sec = tvp->tv_sec;
  long int usec = tvp->tv_usec;

  char srcip[256];
  packetptr += linkhdrlen;
  iphdr = (struct ip*)packetptr;
  strcpy(srcip, inet_ntoa(iphdr->ip_src));
  /*
  char iphdrInfo[256], dstip[256];
  strcpy(dstip, inet_ntoa(iphdr->ip_dst));
  sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
	  ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
	  4*iphdr->ip_hl, ntohs(iphdr->ip_len));
  printf("%s\n", iphdrInfo);
  */
  uint ip_hdrlen = 4*iphdr->ip_hl;
  packetptr += ip_hdrlen;
  
  if (iphdr->ip_p == IPPROTO_TCP) {
    struct tcphdr* tcphdr = (struct tcphdr*)packetptr;
#ifdef FREEBSD
    uint tcphdrlen = 4*tcphdr->th_off;
#else
    uint tcphdrlen = 4*tcphdr->doff;
#endif
    /*
    printf("TCP  %s:%d -> %s:%d Seq: 0x%x Win: 0x%x PktLen: %u TcpHdrLen: %u\n", srcip, ntohs(tcphdr->source), dstip, ntohs(tcphdr->dest), 
	   ntohl(tcphdr->seq), 
	   ntohl(tcphdr->window), 
	   packethdr->caplen, tcphdrlen);
    */
    if (PACKET_DUMP) {
      hex_and_ascii_print("\n\t", packetptr+tcphdrlen, packethdr->caplen-tcphdrlen);
      printf("\n");
    }

#ifdef FREEBSD
    int port = ntohs(tcphdr->th_sport);
#else
    int port = ntohs(tcphdr->source);
#endif

    if (SRCIP_TRACK)
      add_srcip(sec, usec, "TCP", srcip, port, ntohs(iphdr->ip_id));

    if (COUNT_TRACK)
      add_srcip_count(sec, usec, srcip, iphdr->ip_src);

    /*
#ifdef FREEBSD
    int dport = ntohs(tcphdr->th_dport);
#else
    int dport = ntohs(tcphdr->dest);
#endif
    */

    if (AGENT_TRACK /* && dport == 80*/) {
      uint remaining_len = packethdr->caplen - tcphdrlen;
      if (remaining_len > 0) {
	if (request_is_complete(packetptr+tcphdrlen, remaining_len)) {

	  /*
	  char clientip[128];
	  const uint clientip_len = request_clientip(packetptr+tcphdrlen, remaining_len, clientip, sizeof(clientip));
	  if (clientip_len != 0) {
	    printf("\nsrcip: '%s' client_ip: '%s' len=%u\n", srcip, clientip, clientip_len);
	  }
	  */

	  char UA[MAXLINELEN];
	  const uint ua_len = request_user_agent(packetptr+tcphdrlen, remaining_len, UA, sizeof(UA));

	  if (ua_len != 0 && (u_char)UA[0] > 127) {
	    // Dump UAs that are not ascii so we can see them
	    hex_and_ascii_print("\n\t", packetptr, packethdr->caplen);
	    printf("\n");
	  }
	  if (AGENT_FILTER[0] != 0){
	    if (strstr(UA, AGENT_FILTER) != NULL)
	      add_user_agent(sec, usec, srcip, iphdr->ip_src, ntohs(iphdr->ip_id), port, UA, ua_len);
	  } else {
	    add_user_agent(sec, usec, srcip, iphdr->ip_src, ntohs(iphdr->ip_id), port, UA, ua_len);
	  }
	}
      } else {
	printf("%lu.%lu ignoring caplen=%u tcphdrlen=%u remaining=%u\n", sec, usec, packethdr->caplen, tcphdrlen, remaining_len);
      }
    }
  }
  else if (iphdr->ip_p == IPPROTO_UDP) {
    struct udphdr* udphdr = (struct udphdr*)packetptr;
#ifdef FREEBSD
    int port = ntohs(udphdr->uh_sport);
#else
    int port = ntohs(udphdr->source);
#endif
    // if (DEBUG) printf("UDP  %s:%d\n", srcip, port);
    add_srcip(sec, usec, "UDP", srcip, port, ntohs(iphdr->ip_id));
  }
}

char NODE[10] = "node";

static void usage(const char* program, const char* default_filter) {
  printf("usage: %s [-h] [-a CHANNEL] [-c CHANNEL] [-d] -i INTERFACE [filter...]\n", program);
  printf("  [-a CHANNEL] - enable user agent tracking (partially working) and channel, ONLY applies to 'tcp port 80'\n");
  printf("  [-c CHANNEL] - enable client count tracking and channel\n");
  printf("  [-d CHANNEL] - details channel, defaults to 'srcip', flushed every second\n");
  printf("  [-f FILTER]  - agent filter, defaults to ''\n");
  printf("  [-D]         - debug output\n");
  printf("  [-h]         - show this help message\n");
  printf("  [-n]         - node name, used for constructing export file names\n");
  printf("  [-s SERVER]  - change the server (defaults to 127.0.0.1)\n");
  printf("  [-t ALGO]    - change the count algorithm (judy | redblack | hash)\n");
  printf("  [filter...] %s\n", default_filter);
}

static void dumpdata(int signo) {
  // Dump the caches
  printf("\n");
  if (SRCIP_TRACK) {
    printf("--- SrcIP Dump Total=%lu----\n", SRCIP_COUNT);
    flush_srcip_cache(0, 0, 1, 0);
  }
  if (AGENT_TRACK) {
    printf("--- Agent Dump %lu----\n", AGENT_UNIQUE);
    flush_agent_cache(0, 0, 1, 0);
  }
  if (COUNT_TRACK) {
    printf("--- SrcIP Count Dump Unique=%lu Total=%lu----\n", COUNT_NEW, COUNT_TOTAL);
    flush_count_cache(0, 0, 1, 0);
  }
}

int DUMP_TO_FILE = 1;

static void endprocess(int signo) {

  if (!SHUTDOWN) {
    printf("ENDPROCESS %d\n", signo);fflush(stdout);
    // Global that stops packet processing (see parse_packet above)
    SHUTDOWN = 1;
	
    // Dump the agent and srcip caches
    printf("\n");

    if (AGENT_TRACK) {
      printf("--- Agent Dump Unique=%lu Total=%lu----\n", AGENT_UNIQUE+AGENT_NEW, AGENT_TOTAL+AGENT_CNT);
      if (DUMP_TO_FILE) {
	char timestr[256];
	time_t t = time(NULL);
	strftime(timestr, sizeof(timestr), "%Y%m%d%H%M", gmtime(&t));
	char fname[256];
	sprintf(fname, "%s-agents-%s.csv", NODE, timestr);
	printf("Writing to file %s\n", fname);
        fflush(stdout);
	FILE* f = fopen(fname, "w");
	Word_t result = flush_agent_cache(0, 0, 1, f);
	fflush(f);
	fclose(f);
	printf("Wrote %lu unique Agents\n", result);
        fflush(stdout);
      } else {
	flush_agent_cache(0, 0, 1, 0);
      }
    }

    if (COUNT_TRACK) {
      if (DUMP_TO_FILE) {
	printf("--- Count Dump %lu----\n", COUNT_UNIQUE+COUNT_NEW);
	char timestr[256];
	time_t t = time(NULL);
	strftime(timestr, sizeof(timestr), "%Y%m%d%H%M", gmtime(&t));
	char fname[256];
	sprintf(fname, "%s-counts-%s.csv", NODE,timestr);
	printf("Writing to file %s\n", fname);
	fflush(stdout);
	// pthread_mutex_lock(&timer_lock);
	FILE* f = fopen(fname, "w");
	Word_t result = flush_count_cache(0, 0, 1, f);
	fflush(f);
	fclose(f);
	printf("Wrote %lu unique IPs\n", result);
        fflush(stdout);
	// pthread_mutex_unlock(&timer_lock);
      } else {
	printf("--- Count Dump %lu----\n", COUNT_TOTAL);
	flush_count_cache(0, 0, 1, 0);
      }
    }
    
    if (SRCIP_TRACK) {
      if (DUMP_TO_FILE) {
	printf("--- SrcIP Dump %lu----\n", SRCIP_COUNT);
	char timestr[256];
	time_t t = time(NULL);
	strftime(timestr, sizeof(timestr), "%Y%m%d%H%M", gmtime(&t));
	char fname[256];
	sprintf(fname, "%s-srcip-%s.csv", NODE,timestr);
	printf("Writing to file %s\n", fname);
	FILE* f = fopen(fname, "w");
	flush_srcip_cache(0, 0, 1, f);
	fflush(f);
	fclose(f);
      } else {
	flush_srcip_cache(0, 0, 1, 0);
      }
    }

    printf("Closing REDIS connection (if one is available)\n");
    fflush(stdout);
    redis_term();

    printf("Closing pcap\n");
    fflush(stdout);
    pcap_close(pd);

    exit(0);
  } else {
    printf("Ignoring SIGINT, still shutting down\n");
  }

}

TREEREC* rbfirst(ANSREC *ans) {
  return ans->root;
}

TREEREC* rbnext_right(ANSREC* ans, TREEREC* last) {
  if (last->right != NULL)
    return last->right;
  return NULL;
}

TREEREC* rbnext_left(ANSREC* ans, TREEREC* last) {
  if (last->left != NULL)
    return last->left;
  return NULL;
}

int main(int argc, char **argv) {
  char interface[256] = "", filter[256] = "tcp port 80 and tcp[13] == 2";
  int packets = 0, c;

  // Get the command line options, if any
  while ((c = getopt (argc, argv, "Aa:c:d:Df:hi:n:s:t:")) != -1) {
    switch (c)
      {
      case 'A':
	PACKET_DUMP = 1;
	break;
      case 'a':
	AGENT_TRACK = 1;
	strcpy(AGENT_CHANNEL, optarg);
	break;
      case 'c':
	COUNT_TRACK = 1;
	strcpy(COUNT_CHANNEL, optarg);
	break;
      case 'd':
	SRCIP_TRACK = 1;
	strcpy(SRCIP_CHANNEL, optarg);
	break;
      case 'f':
	printf("AGENT_FILTER[0]=%d\n", AGENT_FILTER[0]);
	strcpy(AGENT_FILTER, optarg);
	printf("AGENT_FILTER = '%s'\n", AGENT_FILTER);
	break;
      case 'D':
	DEBUG = 1;
	break;
      case 'h':
	usage(argv[0], filter);
	exit(0);
	break;
      case 'i':
	strcpy(interface, optarg);
	break;
      case 'n':
	strcpy(NODE, optarg);
	break;
      case 's':
	strcpy(REDIS_SERVER, optarg);
	break;
      case 't':
	strcpy(COUNT_ALGO_STR, optarg);
	if (strcmp(COUNT_ALGO_STR, "judy") == 0) {
	  // Default
	  COUNT_ALGO = 0;
	}
	else if (strcmp(COUNT_ALGO_STR, "redblack") == 0) {
	  COUNT_ALGO = 1;
	}
	else if (strcmp(COUNT_ALGO_STR, "hash") == 0) {
	  COUNT_ALGO = 2;
	  init_hash_tables();
	}
	fprintf(stderr, "COUNT_ALGO=%d %s\n", COUNT_ALGO, COUNT_ALGO_STR);
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

  printf("REDIS=%s ALGO=%s SRCIP_CHANNEL='%s' COUNT_CHANNEL='%s' AGENT_CHANNEL='%s' DEBUG=%d FILTER='%s'\n", REDIS_SERVER, COUNT_ALGO==1?"redblack":"judy",SRCIP_CHANNEL, COUNT_CHANNEL, AGENT_CHANNEL, DEBUG, filter); 
  if (SRCIP_TRACK) 
    printf("SRCIP enabled, CHANNEL=%s\n", SRCIP_CHANNEL);
  if (AGENT_TRACK) 
    printf("AGENT enabled, CHANNEL=%s\n", AGENT_CHANNEL);
  if (COUNT_TRACK) 
    printf("COUNT enabled, CHANNEL=%s\n", COUNT_CHANNEL);

  // Get the pcap flowing
  if ((pd = open_pcap(interface, filter))) {

    // Init redis connection
    redis_init();

    signal(SIGINT, endprocess);
//    signal(SIGTERM, endprocess);
//    signal(SIGQUIT, endprocess);
#ifdef FREEBSD
    //    signal(SIGTERM, endprocess);
    //    signal(SIGQUIT, endprocess);
    signal(SIGINFO, dumpdata);
#else
    signal(SIGUSR1, dumpdata);
#endif

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

    printf("Capture complete, done\n");
    fflush(stdout);
    endprocess(0);
  }
  exit(0);
}
