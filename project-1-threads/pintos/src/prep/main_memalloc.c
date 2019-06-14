/*
 * main_memalloc.c
 *
 *  Created on: Sep 10, 2013
 *      Author: jcyescas
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "memalloc.h"

extern void exit(int);

void
test_complex_mem_free()
{
	printf("\ntest_complex_mem_free(): starting");
	int memsize = 2000;
	uint8_t memory[memsize];
	// printf("\ntest_simple_mem_allocation(): Memsize address %d", (int) memory);

	mem_init(memory, memsize);

	mem_dump_free_list();

	uint8_t *dm1 = (uint8_t *) mem_alloc(140);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm1);

	mem_dump_free_list();

	uint8_t *dm2 = (uint8_t *) mem_alloc(400);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm2);

	mem_dump_free_list();

	uint8_t *dm3 = (uint8_t *) mem_alloc(560);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm3);

	mem_dump_free_list();

	mem_free(dm2);

	mem_dump_free_list();

	mem_free(dm3);

	mem_dump_free_list();

	mem_free(dm1);

	mem_dump_free_list();
}

void
test_simple_mem_free()
{
	printf("\ntest_simple_mem_free(): starting");
	int memsize = 2000;
	uint8_t memory[memsize];
	// printf("\ntest_simple_mem_allocation(): Memsize address %d", (int) memory);

	mem_init(memory, memsize);

	mem_dump_free_list();

	uint8_t *dm1 = (uint8_t *) mem_alloc(140);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm1);
	mem_free(dm1);

	mem_dump_free_list();

	uint8_t *dm2 = (uint8_t *) mem_alloc(400);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm2);
	mem_free(dm2);

	mem_dump_free_list();

	uint8_t *dm3 = (uint8_t *) mem_alloc(560);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm3);
	mem_free(dm3);

	mem_dump_free_list();

	uint8_t *dm4 = (uint8_t *) mem_alloc(1000);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm4);

	mem_dump_free_list();

	uint8_t *dm5 = (uint8_t *) mem_alloc(865);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm5);
	mem_free(dm5);

	mem_dump_free_list();

	mem_free(dm4);

	mem_dump_free_list();
}

void
test_simple_mem_allocation()
{
	printf("\ntest_simple_mem_allocation(): starting");
	int memsize = 2000;
	uint8_t memory[memsize];
	// printf("\ntest_simple_mem_allocation(): Memsize address %d", (int) memory);

	mem_init(memory, memsize);

	mem_dump_free_list();

	uint8_t *dm1 = (uint8_t *) mem_alloc(140);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm1);

	mem_dump_free_list();

	uint8_t *dm2 = (uint8_t *) mem_alloc(400);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm2);

	mem_dump_free_list();

	uint8_t *dm3 = (uint8_t *) mem_alloc(560);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm3);

	mem_dump_free_list();

	uint8_t *dm4 = (uint8_t *) mem_alloc(1000);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm4);

	mem_dump_free_list();

	uint8_t *dm5 = (uint8_t *) mem_alloc(865);
	// printf("\nmain(): Address dynamic memory: %d", (int) dm5);

	mem_dump_free_list();
}

int
main()
{
	printf("\nmain(): Executing memory allocator testing");
	test_simple_mem_allocation();
	test_simple_mem_free();
	test_complex_mem_free();

	printf("\nmain(): End testing");
	return 1;
}

/* In Pintos, this function is part of the Pintos library.
 * It's used by the ASSERT() macro which is used in list.c.
 * Since this program is linked with the pthreads library,
 * we must duplicate it here.
 */
void debug_panic(const char *file, int line, const char *function,
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
