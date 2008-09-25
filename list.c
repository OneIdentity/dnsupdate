
/* Manage lists. A list is a null terminated array of string pointers.
 * This code is meant to be convenient, not efficient. Won't scale */

#include "common.h"
#include "list.h"

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

    /* Copy words into the list */
    list = NULL;
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
	word = malloc(wordlen + 1);
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

/* Returns the length of a list */
int
list_length(char **list)
{
    int len;

    if (!list)
	return 0;
    for (len = 0; *list; list++)
	len++;
    return len;
}

/* Create a list from a single item */
char **
list_from_single(const char *item)
{
    char **list;
    char *item_copy;

    item_copy = strdup(item);
    list = (char **)malloc(sizeof (char *) * 2);
    if (!item_copy || !list) {
	if (item_copy) free(item_copy);
	if (list) free(list);
	return NULL;
    }
    list[0] = item_copy;
    list[1] = NULL;
    return list;
}

/* Append an item to the list. 
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
    new_list = (char **)malloc(sizeof (char *) * (nwords + 1 + 1));
    item_copy = strdup(item);
    if (!new_list || !item_copy) {
	if (new_list) free(new_list);
	if (item_copy) free(item_copy);
	return -1;
    }

    if (*listp)
	memcpy(new_list, *listp, sizeof (char *) * nwords);
    new_list[nwords] = item_copy;
    new_list[nwords + 1] = NULL;

    if (*listp)
	free(*listp);
    *listp = new_list;
    return nwords + 1;
}

/* Frees a previously allocated list */
void
list_free(char **list)
{
    char **l;

    if (!list)
	return;
    for (l = list; *l; l++)
	free(*l);
    free(list);
}

/* Returns a duplicate of a list */
char **
list_dup(char **list)
{
    char **list_copy;
    int i, nwords;

    nwords = list_length(list);
    list_copy = (char **)malloc(sizeof (char *) * (nwords + 1));
    for (i = 0; i < nwords; i++)
	list_copy[i] = strdup(list[i]);
    list_copy[nwords] = NULL;
    return list_copy;
}

/* Removes all elements from a list that are equal to item.
 * Preserves order of remaining elements. Resulting list may be empty. */
void
list_remove(char **list, const char *item)
{
    char **ok;

    if (!list)
	return;
    for (ok = list; *list; list++)
	if (strcmp(*list, item) == 0)
	    free(*list);
	else
	    *ok++ = *list;
    *ok = NULL;
}
