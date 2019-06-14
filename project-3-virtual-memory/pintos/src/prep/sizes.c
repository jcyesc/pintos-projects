#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"list.h"

extern void exit(int);        

int main(int argc, char **argv)
{
        printf("sizeof(char)      = %d\n", sizeof(char));
        printf("sizeof(int)       = %d\n", sizeof(int));
        printf("sizeof(long)      = %d\n", sizeof(long));
        printf("sizeof(long long) = %d\n", sizeof(long long));
        printf("sizeof(float)     = %d\n", sizeof(float));
        printf("sizeof(double)    = %d\n", sizeof(double));
        printf("sizeof(int *)     = %d\n", sizeof(int *));
        printf("sizeof(uint8_t)   = %d\n", sizeof(uint8_t));
        printf("sizeof(size_t)    = %d\n", sizeof(size_t));


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
