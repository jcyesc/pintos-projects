
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdint.h>
#include "filesys/off_t.h"
#include "hash.h"
#include "devices/block.h"
#include "threads/thread.h"

enum page_type
{
  EXECUTABLE,
  MMAP,
  STACK,
  SWAP
};

/* Supplemental page table entry*/
struct supplemental_page
{
  uintptr_t virtual_page_number;  /* Virtual page number that will be the key. */
  uintptr_t virtual_user_address;
  uint32_t mapid;
  uint8_t *kpage;
  size_t read_bytes;              /* Number of bytes to read from the executable. */
  size_t zero_bytes;
  off_t offset;                   /* File offset */
  bool writable;
  bool loaded;
  bool swapped;
  block_sector_t swap_lot;       /* Sector where the first segment is stored */
  enum page_type type;
  struct hash_elem hash_elem;
};

unsigned supplemental_page_hash (const struct hash_elem *p, void *aux);

bool supplemental_page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

struct page *supplemental_page_lookup (struct hash *supplemental_pages, const uintptr_t virtual_page_number);

bool install_page (void *upage, void *kpage, bool writable);

void load_page(struct thread *t, struct supplemental_page *sup_page);

void load_stack_page (struct thread *t, struct supplemental_page *sup_page);

void dump_and_release_mmap(const struct mmap_info *mmap, struct thread *t);

#endif /* vm/page.h */


