#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "list.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

/* Get a frame for a new page of memory */
void *
frame_get_frame(enum palloc_flags flags, void *upage);

/* Free the frame for use elsewhere */
void
frame_free_frame(void *page);

/* Retrieve frame from swap */
void *
frame_retrieve_from_swap(struct supplemental_page *sup_page);

void
frame_update_dirty_bits(void);

void
frame_init(void);

void
frame_destroy(void);

void
update_access(void);

struct frame
{
  struct thread *owner;
  void *upage;
  void *kpage;
  bool free;
  struct lock frame_lock;
  struct condition evicted;
};

#endif /* vm/frame.h */
