//=======================================================================
//
// Portions by Douglas L. Baskins, June 2002.
//   Permission to use this code is freely granted, provided that this
//   statement is retained.
//   email - doug@sourcejudy.com
//=======================================================================

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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

double    DeltaUSec;            // Global for remembering delta times

// Note: I have found some Linux systems (2.4.18-6mdk) to have bugs in the 
// gettimeofday() routine.  Sometimes it returns a negative ~2840 microseconds
// instead of 0 or 1.  If you use the above #include "timeit.h" and compile with
// timeit.c and use -DJU_LINUX_IA32, that problem will be eliminated.  This is
// because for delta times less than .1 sec, the hardware free running timer
// is used instead of gettimeofday().  I have found the negative time problem
// appears about 40-50 times per second with consecutive gettimeofday() calls.

#define TIMER_vars(T) struct timeval __TVBeg_##T, __TVEnd_##T

#define STARTTm(T) gettimeofday(&__TVBeg_##T, NULL)

#define ENDTm(D,T)                                                      \
{                                                                       \
    gettimeofday(&__TVEnd_##T, NULL);                                   \
    (D) = (double)(__TVEnd_##T.tv_sec  - __TVBeg_##T.tv_sec) * 1E6 +    \
         ((double)(__TVEnd_##T.tv_usec - __TVBeg_##T.tv_usec));         \
}

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

#define MAXLINE 100   // max length line

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
            if (_count == (MAXLINE - 1))	\
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

int main(int argc, char* argv[]) {

  TIMER_vars(tm);             // declare timer variables
  int       fd;               // to read file.
  struct stat statbuf;        // to get size of file
  char     *Pfile;            // ram address of file
  size_t    fsize;            // file size in bytes
  char     *FSmap;            // start address of mapped file
  char     *FEmap;            // end address+1 of mapped file
  char      String[MAXLINE];  // input buffer
  Word_t    StrCnt;           // line counter

  if (argc < 2) {
    printf("Usage: %s <text file> [<text file>]*\n", argv[0]);
    exit(1);
  }
  
  Word_t total = 0;
  Word_t c = 0;
  Pvoid_t unique;
  Word_t PV_IP;

  int x;
  for (x = 1; x < argc; x++) {
    char* file = argv[x];

    // GET FILE SIZE
    if (stat(file, &statbuf) == -1)
      FILERROR;
    fsize = statbuf.st_size;
  
    // OPEN INPUT FILE:
    if ((fd = open(file, O_RDONLY)) == -1)
      FILERROR;

    // MEMORY MAP FILE
    Pfile = (char *)mmap(NULL, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (Pfile == (char *)-1)
      FILERROR;

    FEmap = Pfile + fsize;      // set end+1 address
    
    Word_t DupCnt = 0;
    Word_t node_total = 0;
    STARTTm(tm);                // start timer
    for (StrCnt = 0, FSmap = Pfile; FSmap < FEmap; )
      {
	GETLINE(String, FSmap); // 'read' next string
	char* cnt = strtok(String,"\t");
	int count = atoi(cnt);
	node_total += count;
	c++;
	char* srcip = strtok(NULL, "\t");
	struct in_addr addr;
	inet_aton(srcip, (struct in_addr*)&addr.s_addr);
	Word_t is_set;
	J1S(is_set, unique, addr.s_addr);
	if (!is_set) DupCnt++;
	StrCnt++;
      }
    ENDTm(DeltaUSec, tm);       // end timer
    
    Word_t Rcount;
    J1C(Rcount, unique, 0, -1);  // count all bits set in array

    printf("#lines,newip,dupip,req,linelen,getline,file\n");
    printf("%lu,%lu,%lu,%lu,%.1f,%5.3f,%s\n", StrCnt, StrCnt-DupCnt,DupCnt,node_total,(double)fsize / (double)StrCnt,  DeltaUSec / (double)StrCnt, file);
    
    total += node_total;

    close(fd);

  }

  Word_t Rcount;
  J1C(Rcount, unique, 0, -1);  // count all bits set in array
  printf("------------------------\n");
  printf("Total IP\t%lu\n", Rcount);
  printf("Total REQ\t%lu\n", total);
  printf("%% Unique\t%0.2f%%\n", (double)Rcount/total*100);

}
