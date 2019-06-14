#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"list.h"

extern void exit(int);        

#define MAX_STR_LEN 128

struct server_node {
    struct list_elem elem;
    char name[MAX_STR_LEN];
    int pfd[2];
};

struct list server_list;

void print_server_list(struct list *l)
{
    struct list_elem *e;

    printf("Servers: ");
    for (e = list_begin(l); e != list_end(l); e = list_next(e)) {
        struct server_node *s = list_entry(e, struct server_node, elem);
        printf("%s ", s->name);
    }
    printf("\n");
}

struct server_node *find_server(struct list *l, char *name)
{
    struct list_elem *e;
    struct server_node *rv = NULL;
    
    for (e = list_begin(l); e != list_end(l); e = list_next(e)) {
        struct server_node *s = list_entry(e, struct server_node, elem);
        if (strcmp(s->name, name) == 0) {
            rv = s;
            break;
        }
    }
    
    return rv;
}

int main(int argc, char **argv)
{
    struct server_node *s;
    struct server_node s1, s2, s3, s4;
    list_init(&server_list);

    s = &s1;
    strlcpy(s->name, "Foo", MAX_STR_LEN);
    list_push_back(&server_list, &s->elem);

    s = &s2;
    strlcpy(s->name, "Goo", MAX_STR_LEN);
    list_push_back(&server_list, &s->elem);

    s = &s3;
    strlcpy(s->name, "Boo", MAX_STR_LEN);
    list_push_back(&server_list, &s->elem);

    s = &s4;
    strlcpy(s->name, "Zoo", MAX_STR_LEN);
    list_push_back(&server_list, &s->elem);
        
    print_server_list(&server_list);

    if ((s = find_server(&server_list, "Boo")) != NULL) {
        printf("Found Boo\n");
        list_remove(&s->elem);
    }

    print_server_list(&server_list);
    
    return 0;
}


void debug_panic (const char *file, int line, const char *function,
                  const char *message, ...)
{
  va_list args;
  printf ("Kernel PANIC at %s:%d in %s(): ", file, line, function);

  va_start (args, message);
  vprintf (message, args);
  printf ("\n");
  va_end (args);
  exit(-1);
}
