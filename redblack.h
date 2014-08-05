typedef struct wordrec
{
    char     *key;
    long     val;
    struct wordrec *left, *right;
    struct wordrec *par;
    char      color;
}
TREEREC;

typedef struct ansrec
{
    struct wordrec *root;
    struct wordrec *ans;
}
ANSREC;

#define RED		0
#define BLACK		1

/* Create a node to hold a key / val */
TREEREC  *
wcreate(char *key, long val, TREEREC * par)
{
    TREEREC  *tmp;
    tmp = (TREEREC *) malloc(sizeof(TREEREC));
    tmp->key = (char *)malloc(strlen(key) + 1);
    strcpy(tmp->key, key);
    tmp->val = val;
    tmp->left = tmp->right = NULL;
    tmp->par = par;
    return (tmp);
}

/* Find key in a redblack tree */
void redblacksearch(ANSREC * ans, char *key)
{
  ans->ans = NULL;
  TREEREC  *curr = ans->root;
  int       val;
  if (ans->root != NULL)
    {
      while (curr != NULL && (val = strcmp(key, curr->key)) != 0)
        {
            if (val > 0)
	      curr = curr->right;
            else
	      curr = curr->left;
        }
    }
  ans->ans = curr;
}

TREEREC* redblackfirst(ANSREC *ans) {
  // descend to the deepest left and climb up to root and then down the right
  TREEREC *curr = ans->root;
  if (curr == NULL) return NULL;
  TREEREC *first = curr;
  while(curr->left != NULL) {
    first = curr->left;
    curr = first;
  }
  return first;
}

/* Rotate the right child of par upwards */

void
leftrotate(ANSREC * ans, TREEREC * par)
{
    TREEREC  *curr, *gpar;
    if ((curr = par->right) != NULL)
    {
        par->right = curr->left;
        if (curr->left != NULL)
            curr->left->par = par;
        curr->par = par->par;
        if ((gpar = par->par) == NULL)
            ans->root = curr;
        else
        {
            if (par == gpar->left)
                gpar->left = curr;
            else
                gpar->right = curr;
        }
        curr->left = par;
        par->par = curr;
    }
}

/* Rotate the left child of par upwards */
void
rightrotate(ANSREC * ans, TREEREC * par)
{
    TREEREC  *curr, *gpar;

    if ((curr = par->left) != NULL)
    {
        par->left = curr->right;
        if (curr->right != NULL)
            curr->right->par = par;
        curr->par = par->par;
        if ((gpar = par->par) == NULL)
            ans->root = curr;
        else
        {
            if (par == gpar->left)
                gpar->left = curr;
            else
                gpar->right = curr;
        }
        curr->right = par;
        par->par = curr;
    }
}

/* Insert key into a redblack tree */
void
redblackinsert(ANSREC * ans, char *key, long value)
{
  TREEREC  *curr = ans->root, *par, *gpar, *prev = NULL, *wcreate();
  int       val;

  if (ans->root == NULL) {
    ans->ans = ans->root = wcreate(key, value, NULL);
    return;
  }
  while (curr != NULL && (val = strcmp(key, curr->key)) != 0) {
    prev = curr;
    if (val > 0)
      curr = curr->right;
    else
      curr = curr->left;
  }

  ans->ans = curr;

  if (curr == NULL) {
    /* Insert a new node, rotate up if necessary */
    if (val > 0) {
      curr = prev->right = wcreate(key, value, prev);
    }
    else {
      curr = prev->left = wcreate(key, value, prev);
    }
    ans->ans = curr;

    curr->color = RED;
    while ((par = curr->par) != NULL
	   && (gpar = par->par) != NULL && curr->par->color == RED)
      {
	if (par == gpar->left) {
	  if (gpar->right != NULL && gpar->right->color == RED) {
	    par->color = BLACK;
	    gpar->right->color = BLACK;
	    gpar->color = RED;
	    curr = gpar;
	  }
	  else {
	    if (curr == par->right)
	      {
		curr = par;
		leftrotate(ans, curr);
		par = curr->par;
	      }
	    par->color = BLACK;
	    if ((gpar = par->par) != NULL)
	      {
		gpar->color = RED;
		rightrotate(ans, gpar);
	      }
	  }
	}
	else
	  {
	    if (gpar->left != NULL && gpar->left->color == RED)
	      {
		par->color = BLACK;
		gpar->left->color = BLACK;
		gpar->color = RED;
		curr = gpar;
	      }
	    else
	      {
		if (curr == par->left)
		  {
		    curr = par;
		    rightrotate(ans, curr);
		    par = curr->par;
		  }
		par->color = BLACK;
		if ((gpar = par->par) != NULL)
		  {
		    gpar->color = RED;
		    leftrotate(ans, gpar);
		  }
	      }
	  }
      }
    if (curr->par == NULL) {
      ans->root = curr;
    }
    ans->root->color = BLACK;
  } else {
    // gDupCnt++;              /* count duplicate strings */
  }
  return;
}

typedef void *redblack_iterator;

redblack_iterator rbt_begin(ANSREC* ans) {
  // return pointer to first value
  TREEREC *i;
  if (ans->root == NULL) return NULL;
  for (i = ans->root; i->left != NULL; i = i->left);
  return i;
}

redblack_iterator rbt_next(ANSREC* ans, redblack_iterator it) {

  TREEREC* i = it;
  if (i->right != NULL) {
    // go right 1, then left to the end
    for (i = i->right; i->left != NULL; i = i->left);
  } else {
    // while you're the right child, chain up parent link
    TREEREC* p = i->par;
    while (p && i == p->right) {
      i = p;
      p = p->par;
    }
    // return the "inorder" node
    i = p;
  }
  return i;
}

void redblack_delete_tree(TREEREC* node) {
  if (node == NULL) {
    return;
  }
  if (node->right != NULL) {
    redblack_delete_tree(node->right);
  }
  if (node->left != NULL) {
    redblack_delete_tree(node->left);
  }
  free(node);
}

void redblack_delete(ANSREC* ans) {
  if (ans->root == NULL) return;
  redblack_delete_tree(ans->root);
  free(ans->root);
  ans->root = NULL;
}

