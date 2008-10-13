
/* Manage lists. A list is a null terminated array of string pointers.
 * This code is meant to be convenient, not efficient. Won't scale */

#include "common.h"
#include "list.h"

static char **
list_alloc(int len)
{
    char **list;

    if (!(list = (char **)malloc((len + 1) * sizeof (char *))))
	return NULL;
    list[len] = NULL;
    return list;
}

/* Creates a list out of a whitespace separated string. 
 * Returns NULL on error */
char **
list_from_string(const char *string)
{
    char **list, *word;
    const char *s, *start;
    int wordlen;

    while (*string == ' ')
	string++;

    if (!(list = list_alloc(0)))
	return NULL;

    s = string;
    for (;;) {
	while (*s == ' ')
	    s++;
	if (!*s)
	    break;
	start = s;
	while (*s && *s != ' ')
	    s++;
	wordlen = s - start;
	/* Duplicate s[start..start+wordlen] */
	word = (char *)malloc(wordlen + 1);
	if (!word) {
	    list_free(list);
	    return NULL;
	}
	memcpy(word, start, wordlen);
	word[wordlen] = 0;
	list_append(&list, word);
	free(word);
    }
    return list;
}

/* Returns the length of a list. Lists must not be NULL. */
int
list_length(char **list)
{
    int len;

    for (len = 0; *list; list++)
	len++;
    return len;
}

/* Returns true if the list is empty or null */
int
list_is_empty_or_null(char **list)
{
    return !list || !*list;
}

char **
list_new()
{
    return list_alloc(0);
}

/* Create a list from a single item */
char **
list_from_single(const char *item)
{
    char **list;
    char *item_copy;

    if (!(item_copy = strdup(item)))
	return NULL;
    if (!(list = list_alloc(1))) {
	free(item_copy);
	return NULL;
    }
    list[0] = item_copy;
    return list;
}

/* Append an item to the list. The item is copied with strdup.
 * List must already have been allocated.
 * Returns new length on list success, or -1 on error */
int
list_append(char ***listp, const char *item)
{
    int nwords;
    char **new_list;
    char *item_copy;

    /* Count the number of existing words in the list */
    nwords = list_length(*listp);

    /* Allocate new storage */
    if (!(new_list = list_alloc(nwords + 1)))
	return -1;

    if (!(item_copy = strdup(item))) {
	free(new_list);
	return -1;
    }

    if (*listp)
	memcpy(new_list, *listp, sizeof (char *) * nwords);
    new_list[nwords] = item_copy;

    if (*listp)
	free(*listp);
    *listp = new_list;
    return nwords + 1;
}

/* Frees a previously allocated list. OK if list is NULL */
void
list_free(char **list)
{
    char **l;

    if (list) {
	for (l = list; *l; l++)
	    free(*l);
	free(list);
    }
}

/* Returns a duplicate of a list */
char **
list_dup(char **list)
{
    char **list_copy;
    int i, nwords;

    nwords = list_length(list);
    if (!(list_copy = list_alloc(nwords)))
	return NULL;
    for (i = 0; i < nwords; i++)
	if (!(list_copy[i] = strdup(list[i]))) {
	    while (i--)
		free(list_copy[i]);
	    free(list_copy);
	    return NULL;
	}
    return list_copy;
}

/* Removes all elements from a list that are equal to item.
 * Preserves order of remaining elements. Resulting list may be empty. */
void
list_remove(char **list, const char *item)
{
    char **ok;

    for (ok = list; *list; list++)
	if (strcmp(*list, item) == 0)
	    free(*list);
	else
	    *ok++ = *list;
    *ok = NULL;
}
