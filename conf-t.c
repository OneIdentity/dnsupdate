
/* Unit tests for conf */

#include "common.h"
#include "conf.h"

#define TESTFILEPATH "/tmp/_conf_test.txt"

int verbose;

int main()
{
    FILE *f;

    config_add("test", "1");
    assert(config_get_int("test", 2) == 1);
    assert(strcmp(config_get_string("test", "2"), "1") == 0);
    assert(config_get_int("unset", 2) == 2);
    assert(config_get_int("unset", -1) == -1);
    assert(strcmp(config_get_string("unset", "2"), "2") == 0);
    assert(config_get_string("unset", NULL) == NULL);

    config_add("test4", "4");
    assert(config_get_int("test4", 2) == 4);
    assert(strcmp(config_get_string("test4", "2"), "4") == 0);
    assert(config_get_int("test", 2) == 1);
    assert(strcmp(config_get_string("test", "2"), "1") == 0);
    assert(config_get_int("unset", 2) == 2);
    assert(strcmp(config_get_string("unset", "2"), "2") == 0);

    config_add("test", "3");
    assert(config_get_int("test", 2) == 3);
    assert(strcmp(config_get_string("test", "2"), "3") == 0);
    assert(config_get_int("unset", 2) == 2);
    assert(strcmp(config_get_string("unset", "2"), "2") == 0);

    config_add("test", "0x10");
    assert(config_get_int("test", 99) == 0x10);
    config_add("test", "077");
    assert(config_get_int("test", 99) == 077);

    config_add("test", NULL);
    assert(config_get_string("test", "") == NULL);

    f = fopen(TESTFILEPATH, "w");
    assert(f != NULL);
    fprintf(f, "a=a\n"
	       "b=\n"
	       " \t c =  \t c c \t c \t \r\n\r\n"
	       " badline #=\n"		    /* generate error but ignore */
	       "   \t #comment\n"
	       "\n"
	       " d = d # comment\n"
	       " e =# comment # #\n"
	       " # f = something\n"
	       " g = eol \t");
    fclose(f);

    fprintf(stderr, "(Ignore following error about expected '=')\n");
    config_load(TESTFILEPATH);
    (void)unlink(TESTFILEPATH);
    assert(strcmp(config_get_string("a", "x"),"a") == 0);
    assert(strcmp(config_get_string("b", "x"),"") == 0);
    assert(strcmp(config_get_string("c", "x"),"c c \t c") == 0);
    assert(strcmp(config_get_string("badline", "x"),"x") == 0);
    assert(strcmp(config_get_string("d", "x"),"d") == 0);
    assert(strcmp(config_get_string("e", "x"),"") == 0);
    assert(strcmp(config_get_string("f", "x"),"x") == 0);
    assert(strcmp(config_get_string("g", "x"),"eol") == 0);

    exit(0);
}
