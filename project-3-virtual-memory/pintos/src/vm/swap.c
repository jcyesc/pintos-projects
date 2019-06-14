#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include <bitmap.h>
#include <hash.h>
#include <debug.h>
#include <stdio.h>

#define SECTORS_PER_PAGE PGSIZE / BLOCK_SECTOR_SIZE

static struct block *swap;              /* Swap partition */
static struct lock swap_lock;           /* Lock for concurrency */
static size_t swap_size;                /* Size of the swap */
static struct bitmap *swap_sectors;     /* Bitmap of swap sectors. */

void
swap_init(void)
{
  swap = block_get_role(BLOCK_SWAP);
  ASSERT (swap != NULL);
  swap_size = block_size(swap);
  lock_init(&swap_lock);
  swap_sectors = bitmap_create(swap_size);
}

block_sector_t
swap_alloc (void)
{
  block_sector_t first_free;

  lock_acquire(&swap_lock);
  first_free = bitmap_scan_and_flip(swap_sectors, 0, SECTORS_PER_PAGE, false);
  lock_release(&swap_lock);

  if (first_free == BITMAP_ERROR)
    PANIC("Swap partition is full .................");

  return first_free;
}

void
swap_write (block_sector_t starting_sector, uint8_t *kpage)
{
  lock_acquire(&swap_lock);

  int i;
  for (i = 0; i < SECTORS_PER_PAGE; i++)
    block_write(swap, starting_sector + i, kpage + i * BLOCK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

/* Loads a frame from swap into memory */
void
swap_read (block_sector_t starting_sector, uint8_t *kpage)
{
  lock_acquire(&swap_lock);
  int i;
  for (i = 0; i < SECTORS_PER_PAGE; i++)
    block_read(swap, starting_sector + i, kpage + i * BLOCK_SECTOR_SIZE);

  lock_release(&swap_lock);
}

void
swap_free (block_sector_t starting_sector)
{
  ASSERT (bitmap_all (swap_sectors, starting_sector, SECTORS_PER_PAGE));
  bitmap_set_multiple (swap_sectors, starting_sector, SECTORS_PER_PAGE, false);
}


void
swap_destroy (void)
{
  bitmap_destroy (swap_sectors);
}
