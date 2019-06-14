/*
 * memoallo.c
 *
 *  Created on: Sep 8, 2013
 *      Author: Juan Yescas
 *
 * Implements the memalloc.h interface. This interface contains the basic
 * methods to allocate and deallocate memory. The problem consists basically
 * on allocating memory given a huge chunk of memory, and deallocating it when
 * the program that requested ended.
 *
 * There are many approaches to allocate memory. The best known are:
 *		BEST FIT
 *		FIRST FIT
 *		WORST FIT
 *
 * This file implements the FIRST FIT approach.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "list.h"
#include "memalloc.h"

/* global variables shared among threads */
pthread_mutex_t memory_mutex = PTHREAD_MUTEX_INITIALIZER;

// Size of the free block
#define SIZE_FREE_BLOCK sizeof (struct free_block)

// Size of the used block
#define SIZE_USED_BLOCK sizeof (struct used_block)

struct list free_block_list;

/* Compare if string a is greater than string b.  */
bool
compare_by_address(const struct list_elem *a, const struct list_elem *b, void *aux)
{
	// printf"\ncompare_by_address(): [%d, %d]: ", (int) a, (int) b);

	// Sorting by address.
	if ((size_t)a >= (size_t)b) {
		// printf"false");
		return false;
	}

	// printf"true");
	return true;
}

struct free_block *
get_first_fit(size_t length) {
	struct list *ptr_list = &free_block_list;
	struct list_elem *e;
	for (e = list_begin(ptr_list); e != list_end(ptr_list); e = list_next(e)) {
		struct free_block *ptrBlock = list_entry(e, struct free_block, elem);
		if (ptrBlock->length >= length) {
			list_remove(e);
			// printf"\nget_first_fit(): %d", (int) ptrBlock);

			return ptrBlock;
		}
	}

	// printf"\ngetFirstFit(): NULL");
	return NULL;
}

/* Sets the header in the assigned memory. */
void
set_use_block(struct used_block **ub, uint8_t *assigned_memory, size_t length_assigned_memory)
{
	*ub = (struct used_block *) assigned_memory;
	(*ub)->length = length_assigned_memory;
	// printf"\nset_use_block(): ub->data [%d]", (int) (*ub)->data);
}

/* Initialize memory allocator to use 'length'
   bytes of memory at 'base'.

   Initially, the free list will contain one memory block that
   is the size of the global memory.*/
void
mem_init(uint8_t *base, size_t length)
{
	pthread_mutex_lock(&memory_mutex);

	// printf"\nmem_init(): SIZE_FREE_BLOCK %d", (int)SIZE_FREE_BLOCK);
	// printf"\nmem_init(): SIZE_USED_BLOCK %d", (int)SIZE_USED_BLOCK);

	// Write the node in the memory
	struct free_block *first;
	first = (struct free_block *) base;
	first->length = length;
	first->elem.next = NULL;
	first->elem.prev = NULL;
	list_init(&free_block_list);
	// Add the node to the list.
	list_insert_ordered(&free_block_list, &first->elem, compare_by_address, NULL);

	pthread_mutex_unlock(&memory_mutex);
}

/* Allocate 'length' bytes of memory. */
void *
mem_alloc(size_t length)
{
	/*
	 * Allocated blocks must be at least as large as a free block header - otherwise, if a
	 * block is freed, it would be impossible to reinsert that block into the free list.
	 * If an allocation request is small, you will have to round it up accordingly.
	 */
	size_t requested_memory;
	if (length >= SIZE_FREE_BLOCK) {
		requested_memory = SIZE_USED_BLOCK + length;
		// printf"\nmem_alloc(): Requested memory (SIZE_USED_BLOCK + %d) = [%d]", (int) length, (int) requested_memory);
	} else {
		requested_memory = SIZE_FREE_BLOCK + length;
		// printf"\nmem_alloc(): Requested memory (SIZE_FREE_BLOCK + %d) = [%d]", (int) length, (int) requested_memory);
	}

	pthread_mutex_lock(&memory_mutex);
	// Getting the first fit for the requested memory
	struct free_block *fb = get_first_fit(requested_memory);

	if (fb == NULL) {
		// printf"\nmem_alloc(): Memory couldn't be allocated");
		pthread_mutex_unlock(&memory_mutex);
		return NULL;
	}

	size_t size_remaining_memory = fb->length - requested_memory;

	// Setting used block.
	uint8_t *assigned_memory = (uint8_t *) fb;
	struct used_block *ub;

	// printf"\nmem_alloc(): Remaining memory %d", (int) size_remaining_memory);

	// Corner cases
	// Create a new node with the remaining memory if the remaining memory
	// is big enough to fit a free_block plus space memory.
	if (size_remaining_memory > SIZE_FREE_BLOCK) {
		// Save the new node in the list with the remaining memory.
		uint8_t *ptr_remaining_memory = (uint8_t *) fb;
		ptr_remaining_memory += requested_memory;
		struct free_block *newBlock;
		newBlock = (struct free_block *) ptr_remaining_memory;
		newBlock->length = size_remaining_memory;
		newBlock->elem.next = NULL;
		newBlock->elem.prev = NULL;
		// Add the node to the list.
		list_insert_ordered(&free_block_list, &newBlock->elem, compare_by_address, NULL);

		// printf"\nmem_alloc() Address new free memory: %d", (int) ptr_remaining_memory);
		// Setting used block
		set_use_block(&ub, assigned_memory, requested_memory);

	} else {
		// printf"\nmem_alloc() Remaining memory added to the used block [%d]", requested_memory + size_remaining_memory);
		// The size of the used memory will be the requested memory plus the remaining memory.
		set_use_block(&ub, assigned_memory, requested_memory + size_remaining_memory);
	}

	// block_use.data points to the memory that is immediately after length.
	void *mem = (void *) ub->data;

	pthread_mutex_unlock(&memory_mutex);

	return mem;
}

/* Free memory pointed to by 'ptr'. */
void
mem_free(void *ptr)
{
	pthread_mutex_lock(&memory_mutex);

	uint8_t *assigned_memory = (uint8_t *) ptr;
	assigned_memory -= SIZE_USED_BLOCK;
	struct used_block *ub = (struct used_block *) assigned_memory;
	size_t free_size = ub->length;
	// printf"\nmem_free(): Size memory to free %d", free_size);

	// Creating the free block in the memory that used to be occupied.
	struct free_block *fb = (struct free_block *) ub;
	fb->length = free_size;
	fb->elem.next = NULL;
	fb->elem.prev = NULL;
	// Add the free node to the list.
	list_insert_ordered(&free_block_list, &fb->elem, compare_by_address, NULL);

	/**
	 * Deallocation and Coalescing
	 * If memory is freed, you must find the beginning of the block of memory that contains
	 * the address of the pointer passed to the free routine. That block of memory must be added
	 * to the free list. In addition, you'll have to coalesce the free list: if the blocks to
	 * the left and/or right of the block being freed are also free, they must be merged into
	 * a single block.
	 */
	uint8_t *ptr_fb = (uint8_t *) fb;
	struct list_elem *element = fb->elem.next;
	if (&fb->elem != list_tail(&free_block_list)) {
		if (element != NULL) {
			struct free_block *lfb = list_entry(element, struct free_block, elem);
			if (lfb != NULL) {
				// printf"\nmem_free(): Left Element [Address, size] = [%d, %d]", (int) lfb, (int) lfb->length);

				// If the current address of the fb plus its size is equals to the address
				// of the left block, then they are consecutive.
				if ((ptr_fb + fb->length) == (uint8_t *) lfb) {
					// printf"\nmem_free(): Left Consecutive block [Address fb, Address lfb] = [%d, %d]", (int) fb, (int) lfb);
					// Expanding the free block.
					fb->length += lfb->length;
					// Removing the left free block.
					list_remove (&lfb->elem);
				}
			}
		}
	}

	element = fb->elem.prev;
	if (&fb->elem != list_head(&free_block_list)) {
		if (element != NULL) {
			struct free_block *rfb = list_entry(element, struct free_block, elem);
			if (rfb != NULL) {
				// printf"\nmem_free(): Right Element [Address, size] = [%d, %d]", (int) rfb, (int) rfb->length);

				// If the current address of the fb minus the right free block is equals to the
				// address of the right block, then they are consecutive.
				if ((ptr_fb - rfb->length) == (uint8_t *) rfb) {
					// printf"\nmem_free(): Right Consecutive blocks [Address fb, Address rfb] = [%d, %d]", (int) fb, (int) rfb);
					// Expanding the right free block.
					rfb->length += fb->length;
					// Removing the middle free block.
					list_remove(&fb->elem);
				}
			}
		}
	}

	pthread_mutex_unlock(&memory_mutex);
}

/* Return the number of elements in the free list. */
size_t
mem_sizeof_free_list()
{
	pthread_mutex_lock(&memory_mutex);
	size_t size =  list_size(&free_block_list);
	pthread_mutex_unlock(&memory_mutex);

	return size;
}

/* Dump the free list.  Implementation of this method is optional. */
void
mem_dump_free_list()
{
	// printf"\n\n---------------------------------------------------------");
	// printf"\nSize of the free list %d", (int) mem_sizeof_free_list());
	struct list *ptr_list = &free_block_list;
	struct list_elem *e;
	// printf"\nAddress \tLength");
	for (e = list_begin(ptr_list); e != list_end(ptr_list); e = list_next(e)) {
		struct free_block *ptrBlock = list_entry(e, struct free_block, elem);
		// printf"\n%d \t%d", (int) ptrBlock, (int) ptrBlock->length);
		// printf"\n%08X \t%d", ((void *)(ptrBlock)), (int) ptrBlock->length);
	}
	// printf"\n---------------------------------------------------------\n");
}

