// ---------------------------------------------------------------

/* Author J. Zobel, April 2001.
   Permission to use this code is freely granted, provided that this
   statement is retained. */

#define TSIZE (1LU << 20)  /* many processors need this to be a pwr of 2 */
#define SEED	1159241
#define HASHFN  bitwisehash

#define INITHASH        static HASHREC *ht[TSIZE]
#define SIZEOFINIT      sizeof(ht[TSIZE])

typedef struct hashrec
{
  struct hashrec *next;
  char     *key;
  long     val;
}
HASHREC;

/* Bitwise hash function.  Note that tsize does not have to be prime. */
unsigned int
bitwisehash(char *word, int tsize, unsigned int seed)
{
    char      c;
    unsigned int h;

    h = seed;
    for (; (c = *word) != '\0'; word++)
    {
        h ^= ((h << 5) + c + (h >> 2));
    }
    return ((unsigned int)((h & 0x7fffffff) % tsize));
}

/* Create hash table, initialise ptrs to NULL */
HASHREC ** inithashtable()
{
  printf("inithashtable TSIZE=%ld\n", TSIZE);
  int       i;
  HASHREC **ht;
  ht = (HASHREC **) malloc(sizeof(HASHREC *) * TSIZE);
  for (i = 0; i < TSIZE; i++)
    ht[i] = (HASHREC *) NULL;
  return (ht);
}

/* Search hash table for given string, insert if not found */
void
hashinsert(HASHREC ** ht, char *w, long val)
{
    HASHREC  *htmp, *hprv;
    unsigned int hval = HASHFN(w, TSIZE, SEED);

    for (hprv = NULL, htmp = ht[hval];
         htmp != NULL && strcmp(htmp->key, w) != 0;
         hprv = htmp, htmp = htmp->next)
    {
        ;
    }

    if (htmp == NULL)
    {
        htmp = (HASHREC *) malloc(sizeof(HASHREC));
        htmp->key = (char *)malloc(strlen(w) + 1);
	htmp->val = val;
        strcpy(htmp->key, w);
        htmp->next = NULL;
        if (hprv == NULL)
            ht[hval] = htmp;
        else
            hprv->next = htmp;
        /* new records are not moved to front */
    }
    else
    {
        if (hprv != NULL)       /* move to front on access */
        {
	  hprv->val = val;
	  hprv->next = htmp->next;
	  htmp->next = ht[hval];
	  ht[hval] = htmp;
        }
    }

    return;
}

HASHREC  *
hashsearch(HASHREC ** ht, char *w)
{
    HASHREC  *htmp, *hprv;
    unsigned int hval = HASHFN(w, TSIZE, SEED);
    for (hprv = NULL, htmp = ht[hval];
         htmp != NULL && strcmp(htmp->key, w) != 0;
         hprv = htmp, htmp = htmp->next)
    {
      ;
    }

    if (hprv != NULL && htmp != NULL) /* move to front on access */
    {
        hprv->next = htmp->next;
        htmp->next = ht[hval];
        ht[hval] = htmp;
    }
    return (htmp);
}

HASHREC * hashfirst(HASHREC ** ht)
{
  uint i = 0;
  for (i = 0; i < TSIZE; i++) {
    HASHREC* temp = ht[i];
    if (temp != NULL) {
      return temp;
    } 
  }
  return NULL;
}

HASHREC * hashnext(HASHREC ** ht, HASHREC *last)
{
  if (last->next != NULL) {
    return last->next;
  }
  unsigned int i = HASHFN(last->key, TSIZE, SEED) + 1;
  for (; i < TSIZE; i++) {
    HASHREC* temp = ht[i];
    if (temp != NULL) {
      return temp;
    } 
  }
  return NULL;
}

