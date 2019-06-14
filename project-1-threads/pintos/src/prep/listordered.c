#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"list.h"

extern void exit(int);        

#define MAX_STR_LEN 128

struct version_node {
    struct list_elem elem;
    char name[32];
    int major;
    int minor;
};

struct list version_list;

bool version_less_func(const struct list_elem *a, 
                       const struct list_elem *b, void *aux)
{
    struct version_node *sa, *sb;
    
    sa = list_entry(a, struct version_node, elem);
    sb = list_entry(b, struct version_node, elem);

    /* compare X1.Y1 < X2.Y2 */
    if (sa->major == sb->major) {
        return sa->minor < sb->minor;
    } else {
        return sa->major < sb->major;
    }
}

void print_version_list(struct list *l)
{
    struct list_elem *e;

    printf("Versions:\n");
    for (e = list_begin(l); e != list_end(l); e = list_next(e)) {
        struct version_node *v = list_entry(e, struct version_node, elem);
        printf("%20s: %d.%d\n", v->name, v->major, v->minor);
    }
}


int main(int argc, char **argv)
{
    struct version_node *v;
    struct version_node v1, v2, v3, v4;

    list_init(&version_list);
    
    v = &v1;
    strlcpy(v->name, "Liddy Piddy", MAX_STR_LEN);
    v->major = 3;
    v->minor = 1;
    list_insert_ordered(&version_list, &v->elem, version_less_func, NULL);

    v = &v2;
    strlcpy(v->name, "Maddy Paddy", MAX_STR_LEN);
    v->major = 3;
    v->minor = 2;
    list_insert_ordered(&version_list, &v->elem, version_less_func, NULL);

    v = &v3;
    strlcpy(v->name, "Jetty Ketty", MAX_STR_LEN);
    v->major = 2;
    v->minor = 4;
    list_insert_ordered(&version_list, &v->elem, version_less_func, NULL);

    v = &v4;
    strlcpy(v->name, "Zeldi Meldi", MAX_STR_LEN);
    v->major = 1;
    v->minor = 1;
    list_insert_ordered(&version_list, &v->elem, version_less_func, NULL);
        
    print_version_list(&version_list);
    
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
