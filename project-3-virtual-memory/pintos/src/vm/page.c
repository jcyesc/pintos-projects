#include "vm/page.h"
#include <debug.h>
#include "filesys/file.h"
#include "hash.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static void load_from_file(struct thread *t, struct supplemental_page *sup_page, struct file *file);

/* Returns a hash value for page p. */
unsigned
supplemental_page_hash (const struct hash_elem *p, void *aux UNUSED)
{
  const struct supplemental_page *sp = hash_entry (p, struct supplemental_page, hash_elem);
  return hash_int(sp->virtual_page_number);
}

/* Returns true if page a precedes page b. */
bool
supplemental_page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct supplemental_page *sp_a = hash_entry (a, struct supplemental_page, hash_elem);
  const struct supplemental_page *sp_b = hash_entry (b, struct supplemental_page, hash_elem);
  return sp_a->virtual_page_number < sp_b->virtual_page_number;
}

struct page *
supplemental_page_lookup (struct hash *supplemental_pages, const uintptr_t virtual_page_number)
{
  struct supplemental_page p;
  struct hash_elem *e;
  p.virtual_page_number = virtual_page_number;
  e = hash_find (supplemental_pages, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct supplemental_page, hash_elem) : NULL;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void
load_page(struct thread *t, struct supplemental_page *sup_page)
{
  if (sup_page->loaded)
    return;

  struct file *file = NULL;

  // First it's necessary to check if the page is swapped.
  if (sup_page->swapped)
    {
      void *kpage = frame_retrieve_from_swap(sup_page);

      /* Add the page to the process's address space. */
      if (!install_page(sup_page->virtual_user_address, kpage,
          sup_page->writable))
        {
          frame_free_frame(kpage);
          PANIC(t->process_name, 200, "load_page", "install_page() failed");
        }
    }
  else if (sup_page->type == EXECUTABLE)
    {
      load_from_file(t, sup_page, t->monitor->executable);
    }
  else if (sup_page->type == MMAP)
    {
      struct mmap_info * mmap = mmap_info_lookup(&t->mmap_ids, sup_page->mapid);
      if (mmap == NULL)
        {
          PANIC(t->process_name, 200,  "load_page", "mmap_info_lookup() returned null");
        }
      load_from_file(t, sup_page, mmap->mmap_file);
    }
}

void load_stack_page (struct thread *t, struct supplemental_page *sup_page)
{
  if (sup_page->loaded)
    return;

   /* Get a page of memory. */
  uint8_t *kpage = frame_get_frame(PAL_USER, sup_page->virtual_user_address);
  sup_page->kpage = kpage;
  if (kpage == NULL)
    {
      PANIC(t->process_name, 200,  "load_page", "palloc_get_page() returned null");
    }

  memset(kpage, 0, PGSIZE);

  /* Add the page to the process's address space. */
  if (!install_page(sup_page->virtual_user_address, kpage, true))
    {
      frame_free_frame(kpage);
      PANIC(t->process_name, 200,  "load_page", "install_page() failed");
    }

  sup_page->loaded = true;
}

/*
 * It dumps all the information from the memory map to the file and then releases
 * the page.
 */
void
dump_and_release_mmap(const struct mmap_info *mmap, struct thread *t)
{
  uint8_t *upage = mmap->mapid;     /* Initial virtual memory address of the mapping file. */
  struct supplemental_page *sup_page = supplemental_page_lookup(&t->supplemental_pages, pg_no (upage));

  /* Dump the information to the file. */
  while (sup_page != NULL && sup_page->mapid == mmap->mapid)
    {
      /* If the page was loaded, release the resources. */
      if (sup_page->loaded)
        {
          /* Write the changes only if the page was modified. */
          if (pagedir_is_dirty(t->pagedir, upage))
            {
              file_seek(mmap->mmap_file, sup_page->offset);
              file_write(mmap->mmap_file, sup_page->virtual_user_address, sup_page->read_bytes);
            }
          pagedir_clear_page(t->pagedir, upage);
          frame_free_frame (sup_page->kpage);
        }
      /*Remove the current supplemental entry from the supplemental table. */
      hash_delete(&t->supplemental_pages, &sup_page->hash_elem);
      free(sup_page);
      upage += PGSIZE;
      sup_page = supplemental_page_lookup(&t->supplemental_pages, pg_no (upage));
    }

  file_close(mmap->mmap_file);
}

static
void
load_from_file(struct thread *t, struct supplemental_page *sup_page, struct file *file)
{
  file_seek(file, sup_page->offset);

  /* Get a page of memory. */
  uint8_t *kpage = frame_get_frame(PAL_USER, sup_page->virtual_user_address);

  if (kpage == NULL)
    {
      PANIC(t->process_name, 200,  "load_page", "palloc_get_page() returned null");
    }

  /* Load this page. */
  if (file_read(file, kpage, sup_page->read_bytes) != (int) sup_page->read_bytes)
    {
      frame_free_frame(kpage);
      PANIC(t->process_name, 200,  "load_page", "file_read() failed");
    }
  memset(kpage + sup_page->read_bytes, 0, sup_page->zero_bytes);

  /* Add the page to the process's address space. */
  if (!install_page(sup_page->virtual_user_address, kpage, sup_page->writable))
    {
      frame_free_frame(kpage);
      PANIC(t->process_name, 200, "load_page", "install_page() failed");
    }

  sup_page->kpage = kpage;
  sup_page->loaded = true;
}
