/*
 * list_example.c
 *
 * This program shows how to use the Pintos double linked list.
 *
 *  Created on: Sep 7, 2013
 *      Author: jcyescas
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

extern void exit(int);

#define MAX_STR_LEN 128

struct person_node {
	struct list_elem elem;
	char first_name[MAX_STR_LEN];
	char last_name[MAX_STR_LEN];
	short age;
	int priority;
};

void print_person_list(struct list *ptr_list) {
	struct list_elem *e;

	printf("\n# of Persons: %d", (int) list_size(ptr_list));
	for (e = list_begin(ptr_list); e != list_end(ptr_list); e = list_next(e)) {
		struct person_node *ptr = list_entry(e, struct person_node, elem);
		printf("\n[%s, %s, %d]", ptr->first_name, ptr->last_name, ptr->age);
	}

	printf("\n");
}

/* Compare if string a is greater than string b.  */
bool compare_by_first_name (const struct list_elem *a,
                            const struct list_elem *b,
                            void *aux) {
	struct person_node *pa = list_entry(a, struct person_node, elem);
	struct person_node *pb = list_entry(b, struct person_node, elem);
	int result = strcmp(pa->first_name, pb->first_name);

	if (result >= 0) {
		return false;
	}

	return true;
}


void testSimpleInsertions() {
	struct list person_list;
	struct person_node p1, p2, p3;
	struct person_node *ptr;

	list_init(&person_list);

	ptr = &p1;
	strlcpy(ptr->first_name, "John", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Smith", MAX_STR_LEN);
	ptr->age = 23;
	list_push_back(&person_list, &ptr->elem);

	ptr = &p2;
	strlcpy(ptr->first_name, "Michael", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Jordan", MAX_STR_LEN);
	ptr->age = 45;
	list_push_back(&person_list, &ptr->elem);

	ptr = &p3;
	strlcpy(ptr->first_name, "Joe", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Carson", MAX_STR_LEN);
	ptr->age = 34;
	list_push_back(&person_list, &ptr->elem);

	print_person_list(&person_list);
}

void testInsertOrdered() {
	struct list person_list;
	struct person_node p1, p2, p3;
	struct person_node *ptr;

	list_init(&person_list);

	ptr = &p1;
	strlcpy(ptr->first_name, "John", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Smith", MAX_STR_LEN);
	ptr->age = 23;
	list_insert_ordered(&person_list, &ptr->elem, compare_by_first_name, NULL);

	ptr = &p2;
	strlcpy(ptr->first_name, "Michael", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Jordan", MAX_STR_LEN);
	ptr->age = 45;
	list_insert_ordered(&person_list, &ptr->elem, compare_by_first_name, NULL);

	ptr = &p3;
	strlcpy(ptr->first_name, "Anne", MAX_STR_LEN);
	strlcpy(ptr->last_name, "Carson", MAX_STR_LEN);
	ptr->age = 34;
	list_insert_ordered(&person_list, &ptr->elem, compare_by_first_name, NULL);

	print_person_list(&person_list);
}

int main() {
	testSimpleInsertions();
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
