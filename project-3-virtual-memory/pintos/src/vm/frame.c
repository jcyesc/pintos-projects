#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/loader.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "hash.h"
#include "list.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <bitmap.h>
#include <stdio.h>

/* Starting address of the user pool. */
static uint8_t *user_pool_base;

/* Total number of user frames. */
static size_t user_frames;

/* Frame table of references to present pages */
static struct frame *frame_table;

/* Lock for the frame functionality.*/
struct lock fpool_lock;

/* Frees a frame an save the data in the swap partition. It uses the clock
 * page replacement algorithm. */
static void *get_frame_and_swap(void);

/* It returns a frame. This function is not synchronized. */
static void *get_frame (enum palloc_flags flags, void *upage);

/* Initial starting point of the clock page replacement algorithm. */
static uint32_t clock_pointer = 0;

void frame_init(void)
{
  lock_init(&fpool_lock);

  user_pool_base = get_user_pool_base();
  user_frames = get_number_user_pages();

  /* Initializing the frame table. */
  frame_table = malloc (sizeof (struct frame) * user_frames);

  int i;
  struct frame *tmp_ptr = frame_table;
  for (i = 0; i < user_frames; i++)
    {
      struct frame *f = tmp_ptr++;
      f->owner = NULL;
      f->upage = NULL;
      f->kpage = NULL;
      f->free = true;
      lock_init(&f->frame_lock);
      cond_init(&f->evicted);
    }
}

void frame_destroy(void)
{
  free (frame_table);
}

void *
frame_get_frame(enum palloc_flags flags, void *upage)
{
  void *kpage;

  lock_acquire(&fpool_lock);
  kpage = get_frame(flags, upage);
  lock_release(&fpool_lock);

  return kpage;
}

static void *
get_frame(enum palloc_flags flags, void *upage)
{
  ASSERT(flags & PAL_USER);
  void *kpage;

  kpage = palloc_get_page(flags);

  if (kpage == NULL)
    {
      kpage = get_frame_and_swap();

      // Setting the memory to ZERO so the user doesn't receive garbage or important information.
      memset(kpage, 0, PGSIZE);
    }

  uint32_t index = (((uint32_t) kpage - (uint32_t) user_pool_base) / PGSIZE);
  frame_table[index].owner = thread_current();
  frame_table[index].upage = upage;
  frame_table[index].kpage = kpage;
  frame_table[index].free = false;

  return kpage;
}

/* It applies the Clock page replacement algorithm. */
static void *
get_frame_and_swap(void)
{
  void *kpage;

  while (true)
    {
      int index = clock_pointer % user_frames;
      clock_pointer++;

      struct frame *f = &frame_table[index];

      // Frame has to be used, otherwise we don't have access to the thread and user page.
      if (!f->free)
        {
          struct supplemental_page *sp = supplemental_page_lookup(
              &f->owner->supplemental_pages, pg_no(f->upage));

          // An entry has to be in the supplemental page table, if there is nothing,
          // It means that the frame was removed from the supplemental table and
          // we need to continue looking for it, otherwise we can update the supplemental
          // information.
          if (sp == NULL)
            continue;

          ASSERT(f->owner != NULL);
          ASSERT(f->upage != NULL);

          /* Cannot access the frame's accessed bit, so continue. */
          if (pagedir_get_page(f->owner->pagedir, f->upage) == NULL)
            continue;

          /* If the page has been accessed, continue.*/
          if (pagedir_is_accessed(f->owner->pagedir, f->upage))
            {
              pagedir_set_accessed(f->owner->pagedir, f->upage, false);
              continue;
            }

          sp->loaded = false;
          sp->kpage = NULL;

          //Removing the page from the directory.
          pagedir_clear_page(f->owner->pagedir, f->upage);

          // Saving the page in the swap partition, if the page belongs to an
          // executable and is not writable, we don't save it in the swap partition.
          if (sp->writable)
            {
              /* Allocating the swap slot. */
              sp->swap_lot = swap_alloc();
              /* Writing the frame to the swap slot.*/
              swap_write(sp->swap_lot, f->kpage);
              sp->swapped = true;
            }
        }

      // Setting the frame that will be returned.
      kpage = f->kpage;
      break;
    }

  return kpage;
}

/* Retrieve frame page from swap */
void *
frame_retrieve_from_swap(struct supplemental_page *sup_page)
{
  lock_acquire(&fpool_lock);

  // Getting a new kernel page to copy the data.
  void *kpage = get_frame(PAL_USER, sup_page->virtual_user_address);
  // Copy the data from the swap slop the kpage.
  swap_read(sup_page->swap_lot, kpage);
  swap_free(sup_page->swap_lot);

  sup_page->kpage = kpage;
  sup_page->swapped = false;
  sup_page->loaded = true;

  lock_release(&fpool_lock);

  return kpage;
}

void
frame_free_frame(void *kpage)
{
  lock_acquire(&fpool_lock);

  int index = ((uint32_t) kpage - (uint32_t) user_pool_base) / PGSIZE;
  if (frame_table[index].owner == thread_current())
    {
      palloc_free_page(kpage);
      frame_table[index].owner = NULL;
      frame_table[index].upage = NULL;
      frame_table[index].kpage = NULL;
      frame_table[index].free = true;
    }

  lock_release(&fpool_lock);
}

