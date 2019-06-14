#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"list.h"

extern void exit(int);        

struct block_array_zero
  {
    size_t              length;         /* length of block, including header */
    uint8_t             data[0];        /* memory_block.data points at the
                                           memory behind the length . */
  };

struct block
  {
    size_t              length;         /* length of block, including header */
  };


int main(int argc, char **argv)
{
        printf("sizeof(char)      = %d\n", sizeof(char));
        printf("sizeof(int)       = %d\n", sizeof(int));
        printf("sizeof(long)      = %d\n", sizeof(long));
        printf("sizeof(long long) = %d\n", sizeof(long long));
        printf("sizeof(float)     = %d\n", sizeof(float));
        printf("sizeof(double)    = %d\n", sizeof(double));
        printf("sizeof(int *)     = %d\n", sizeof(int *));
        printf("sizeof(size_t)    = %d\n", sizeof(size_t));
        printf("sizeof(block_array_zero)    = %d\n", sizeof(struct block_array_zero));
        printf("sizeof(block)    = %d\n", sizeof(struct block));

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
