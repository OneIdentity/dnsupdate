
/* Unit tests for conf */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#define streq(a,b) ((a)!=NULL && (b)!=NULL && strcmp(a,b)==0)

int main()
{
    char **list, **list2;
    int ret;
    char foo[] = "foo";
    char bar[] = "bar";

    list = NULL;
    assert(list_length(list) == 0);
    list2 = list_dup(list);
    assert(list2 != NULL);
    assert(list2[0] == NULL);
    assert(list_length(list2) == 0);
    list_free(list);
    list_free(list2);

    list = NULL;
    ret = list_append(&list, bar);
    assert(ret == 1);
    assert(list != NULL);
    assert(streq(list[0], "bar"));
    assert(list[0] != bar);
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    ret = list_append(&list, foo);
    assert(ret == 2);
    assert(list != NULL);
    assert(streq(list[0], "bar"));
    assert(list[0] != bar);
    assert(streq(list[1], "foo"));
    assert(list[1] != foo);
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_single(foo);
    assert(list != NULL);
    assert(list[0] != foo);
    assert(streq(list[0], "foo"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list2 = list_dup(list);
    assert(list2 != NULL);
    assert(list2[0] != list[0]);
    assert(streq(list2[0], "foo"));
    assert(list2[1] == NULL);
    assert(list_length(list2) == 1);

    ret = list_append(&list, "bar");
    assert(ret == 2);
    assert(streq(list[0], "foo"));
    assert(streq(list[1], "bar"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);
    list_free(list2);

    list = list_from_string("");
    assert(list == NULL);

    list = list_from_string(" ");
    assert(list == NULL);

    list = list_from_string("        ");
    assert(list == NULL);

    list = list_from_string("word");
    assert(list != NULL);
    assert(streq(list[0], "word"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list_free(list);

    list = list_from_string(" word");
    assert(list != NULL);
    assert(streq(list[0], "word"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list_free(list);

    list = list_from_string("word ");
    assert(list != NULL);
    assert(streq(list[0], "word"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list_free(list);

    list = list_from_string(" word ");
    assert(list != NULL);
    assert(streq(list[0], "word"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list_free(list);

    list = list_from_string("      word          ");
    assert(list != NULL);
    assert(streq(list[0], "word"));
    assert(list[1] == NULL);
    assert(list_length(list) == 1);
    list_free(list);

    list = list_from_string("abc def");
    assert(list != NULL);
    assert(streq(list[0], "abc"));
    assert(streq(list[1], "def"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_string(" abc def");
    assert(list != NULL);
    assert(streq(list[0], "abc"));
    assert(streq(list[1], "def"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_string("abc def ");
    assert(list != NULL);
    assert(streq(list[0], "abc"));
    assert(streq(list[1], "def"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_string(" abc def ");
    assert(list != NULL);
    assert(streq(list[0], "abc"));
    assert(streq(list[1], "def"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_string("    abc      def    ");
    assert(list != NULL);
    assert(streq(list[0], "abc"));
    assert(streq(list[1], "def"));
    assert(list[2] == NULL);
    assert(list_length(list) == 2);
    list_free(list);

    list = list_from_string("a b c d e f");
    assert(list != NULL);
    assert(streq(list[0], "a"));
    assert(streq(list[1], "b"));
    assert(streq(list[2], "c"));
    assert(streq(list[3], "d"));
    assert(streq(list[4], "e"));
    assert(streq(list[5], "f"));
    assert(list[6] == NULL);
    assert(list_length(list) == 6);

    ret = list_append(&list, "g");
    assert(ret == 7);
    assert(list != NULL);
    assert(streq(list[0], "a"));
    assert(streq(list[1], "b"));
    assert(streq(list[2], "c"));
    assert(streq(list[3], "d"));
    assert(streq(list[4], "e"));
    assert(streq(list[5], "f"));
    assert(streq(list[6], "g"));
    assert(list[7] == NULL);
    assert(list_length(list) == 7);
    list_free(list);

    exit(0);
}
