#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "exception.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "hash.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "vm/page.h"

#define NUMBER_SYS_HANDLERS 20

static void syscall_handler (struct intr_frame *);

/* The values in the stack are 32 bits*/
typedef uint32_t (*sys_handler) (uint32_t, uint32_t, uint32_t);

/* Project 2 */
static uint32_t sys_halt (void);
static uint32_t sys_exit (int status);
static uint32_t sys_exec (const char *file);
static uint32_t sys_wait (tid_t child_tid);
static uint32_t sys_create (const char *file, unsigned initial_size);
static uint32_t sys_remove (const char *file);
static uint32_t sys_open (const char *file);
static uint32_t sys_filesize (int fd);
static uint32_t sys_read (int fd, void *buffer, unsigned length);
static uint32_t sys_write (int fd, const void *buffer, unsigned length);
static uint32_t sys_seek (int fd, unsigned position);
static uint32_t sys_tell (int fd);
static uint32_t sys_close (int fd);

/* Project 3 and optionally project 4. */
static uint32_t sys_mmap (int fd, const void *addr);
static uint32_t sys_munmap (int mapid);

/* Project 4 only. */
static uint32_t sys_chdir (const char *dir);
static uint32_t sys_mkdir (const char *dir);
static uint32_t sys_readdir (int fd, char *name);
static uint32_t sys_isdir (int fd);
static uint32_t sys_inumber (int fd);

/* Array of sys_handlers */
static sys_handler sys_handlers [NUMBER_SYS_HANDLERS];

/* Function to validate the parameters. */
static bool is_file_descriptor_valid(int fd);
static bool is_buffer_mapped(const void *buffer, uint32_t length);
static bool string_is_bounded_safe (const char *str, int num_bytes);

static struct lock sys_lock;

/* Helper functions for mmap and ummap. */
static bool memory_overlap(const void *addr, uint32_t read_bytes, const struct thread *t);
static void add_mmapings(const void *addr, uint32_t read_bytes, const struct thread *t);
static void add_mmap_info(const void *addr, const struct file *mmap_file, const struct thread *t);

void
syscall_init (void) 
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Initializes the system lock. */
  lock_init(&sys_lock);

  /* Initalizing the sys handlers with the appropriate function. */
  /* Project 2 */
  sys_handlers[SYS_HALT] = (sys_handler) sys_halt;
  sys_handlers[SYS_EXIT] = (sys_handler) sys_exit;
  sys_handlers[SYS_EXEC] = (sys_handler) sys_exec;
  sys_handlers[SYS_WAIT] = (sys_handler) sys_wait;
  sys_handlers[SYS_CREATE] = (sys_handler) sys_create;
  sys_handlers[SYS_REMOVE] = (sys_handler) sys_remove;
  sys_handlers[SYS_OPEN] = (sys_handler) sys_open;
  sys_handlers[SYS_FILESIZE] = (sys_handler) sys_filesize;
  sys_handlers[SYS_READ] = (sys_handler) sys_read;
  sys_handlers[SYS_WRITE] = (sys_handler) sys_write;
  sys_handlers[SYS_SEEK] = (sys_handler) sys_seek;
  sys_handlers[SYS_TELL] = (sys_handler) sys_tell;
  sys_handlers[SYS_CLOSE] = (sys_handler) sys_close;

  /* Project 3 */
  sys_handlers[SYS_MMAP] = (sys_handler) sys_mmap;
  sys_handlers[SYS_MUNMAP] = (sys_handler) sys_munmap;

  /* Project 4 */
  sys_handlers[SYS_CHDIR] = (sys_handler) sys_chdir;
  sys_handlers[SYS_MKDIR] = (sys_handler) sys_mkdir;
  sys_handlers[SYS_READDIR] = (sys_handler) sys_readdir;
  sys_handlers[SYS_ISDIR] = (sys_handler) sys_isdir;
  sys_handlers[SYS_INUMBER] = (sys_handler) sys_inumber;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *stack_pointer = f->esp;

  /*
   * Note:
   *
   * Since the processor only saves the stack pointer when an exception causes a switch
   * from user to kernel mode, reading esp out of the struct intr_frame passed to page_fault()
   * would yield an undefined value, not the user stack pointer. You will need to arrange
   * another way, such as saving esp into struct thread on the initial transition from user
   * to kernel mode.
   **/
  thread_current()->esp = stack_pointer;

  /* Validating that the stack pointer points to a valid address for the 3 parameters and
   * the system call number. */
  if (!is_valid_user_access_vaddr(stack_pointer) ||
      !is_valid_user_access_vaddr(stack_pointer + 1) ||
      !is_valid_user_access_vaddr(stack_pointer + 2) ||
      !is_valid_user_access_vaddr(stack_pointer + 3))
    {
      sys_exit(-1);
    }

  /* The top of the stack contains the sys call */
  uint32_t sys_call_number = *stack_pointer;

  if (!(sys_call_number >= SYS_HALT || sys_call_number <= SYS_INUMBER))
    {
      thread_exit ();
    }

  sys_handler handler = sys_handlers[sys_call_number];

  /* Passing the parameters to the handler. Some handlers don't need the three parameters,
   * so they will be saved in the stack either way.
   * Note:
   *   This solution works because all the parameters are 32 bits. It needs to be
   *   tested for 8 bits parameters.
   */
  uint32_t result = handler(*(stack_pointer + 1), *(stack_pointer + 2), *(stack_pointer + 3));

  /* Storing the result value in the register EAX. */
  f->eax = result;
}

uint32_t sys_halt (void)
{
  shutdown_power_off();

  return 0;
}

uint32_t sys_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  thread_exit ();

  return 0;
}

uint32_t sys_exec (const char *file)
{

  if (!is_valid_user_access_vaddr(file))
    {
      /* *file pointer is invalid. */
      sys_exit(-1);
    }

  if (!string_is_bounded_safe((char *) file, PGSIZE))
    {
      /* The name of the file is longer than NAME_MAX. */
      return -1;
    }

  return process_execute (file);
}

uint32_t sys_wait (tid_t child_tid)
{
  return process_wait(child_tid);
}

/* First checks that a given string is mapped over NUM_BYTES, then checks
that the string terminates within NUM_BYTES. Returns true if both conditions
are satisfied, false if the string doesn't terminate properly, and results in
termination of this thread if the string points to unmapped memory. */
static bool
string_is_bounded_safe (const char *str, int num_bytes)
{
  int i;
  for (i = 0; i < num_bytes; i++)
    {
      if (*(str + i) == 0)
        return true;
    }

  return false;
}

static bool
is_buffer_mapped(const void *buffer, uint32_t length) {
  if (is_valid_user_access_vaddr(buffer) && is_valid_user_access_vaddr((const void *) ((uint32_t) buffer + length)))
    return true;

  return false;
}

uint32_t
sys_create(const char *file, unsigned initial_size)
{
  if (file == NULL || !is_valid_user_access_vaddr(file))
    {
      /* *file pointer is invalid. */
      sys_exit(-1);
    }

  if (!string_is_bounded_safe (file, NAME_MAX))
    {
      /* The name of the file is longer than NAME_MAX. */
      return false;
    }

  bool result = false;
  lock_acquire(&sys_lock);
  result = filesys_create(file, initial_size);
  lock_release(&sys_lock);

  return result;
}

uint32_t
sys_remove(const char *file)
{
  if (!is_valid_user_access_vaddr(file))
    {
      sys_exit(-1);
    }

  if (!string_is_bounded_safe (file, NAME_MAX))
    {
      /* The name of the file is longer than NAME_MAX. */
      return false;
    }

  bool result = false;

  lock_acquire(&sys_lock);

  result = filesys_remove(file);

  lock_release(&sys_lock);

  return result;
}

uint32_t
sys_open(const char *file)
{
  if (!is_valid_user_access_vaddr(file))
    {
      sys_exit(-1);
    }

  if (!string_is_bounded_safe (file, NAME_MAX))
    {
      /* The name of the file is longer than NAME_MAX. */
      return -1;
    }

  int fd = -1;

  struct thread *current_thread = thread_current();
  lock_acquire(&sys_lock);

  /* Get a file Descriptor for the current thread. */
  /* File descriptors 0 and 1 are reserved for STDIN_FILENO and STDOUT_FILENO. */
  for (fd = STARTING_RANGE_FILE_DESCRIPTORS; fd < MAX_FILE_DESCRIPTORS; fd++)
    {
      if (current_thread->file_descriptors[fd] == NULL)
        break;
    }

  if (fd > MAX_FILE_DESCRIPTORS)
    {
      fd = -1; /* There are not file descriptors available. */
      goto done_open;
    }

  struct file *current_file = filesys_open(file);

  if (current_file == NULL)
    {
      fd = -1; /* The file couldn't be opened. */
      goto done_open;
    }

  /* Registering the file descriptor in the table. */
  current_thread->file_descriptors[fd] = current_file;

  done_open:
    lock_release(&sys_lock);
    return fd;
}

/* It verifies if the file descriptor is in the valid range. */
static bool
is_file_descriptor_valid(int fd)
{
  if (fd >= STARTING_RANGE_FILE_DESCRIPTORS && fd < MAX_FILE_DESCRIPTORS)
    return true;

  return false;
}

uint32_t
sys_filesize(int fd)
{
  off_t length = -1;
  if (is_file_descriptor_valid(fd))
    {
      lock_acquire(&sys_lock);
      struct file *current_file = thread_current()->file_descriptors[fd];

      if (current_file != NULL)
         length = file_length(current_file);

      lock_release(&sys_lock);
    }

  return length;
}

uint32_t
sys_read(int fd, void *buffer, unsigned length)
{
  if(!is_valid_user_access_vaddr(buffer) || !is_buffer_mapped(buffer, length))
    {
      sys_exit(-1);
    }

  off_t read = -1;
  lock_acquire(&sys_lock);
  if (fd == STDIN_FILENO)
    {
      read = input_getc();
      goto done_read;
    }

  if (is_file_descriptor_valid(fd))
    {
      struct file *current_file = thread_current()->file_descriptors[fd];
      if (current_file != NULL)
        {
          read = file_read(current_file, buffer, length);
        }
    }

  done_read:
    lock_release(&sys_lock);
    return read;
}

uint32_t
sys_write(int fd, const void *buffer, unsigned length)
{
  off_t write = -1;

  if (!is_valid_user_access_vaddr(buffer) || !is_buffer_mapped(buffer, length))
    {
      sys_exit(-1);
    }

  lock_acquire(&sys_lock);
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, length);
      write = length;
      goto done_write;
    }

  if (is_file_descriptor_valid(fd))
    {
      struct file *current_file = thread_current()->file_descriptors[fd];
      if (current_file != NULL)
        write = file_write(current_file, buffer, length);
    }

  done_write:
    lock_release(&sys_lock);
    return write;
}

uint32_t
sys_seek(int fd, unsigned position)
{
  if (is_file_descriptor_valid(fd))
    {
      lock_acquire(&sys_lock);

      struct file *current_file = thread_current()->file_descriptors[fd];
      if (current_file != NULL)
        file_seek(current_file, position);

      lock_release(&sys_lock);
    }

  return -1;
}

uint32_t
sys_tell(int fd)
{
  off_t tell_pointer = -1;

  if (is_file_descriptor_valid(fd))
    {
      lock_acquire(&sys_lock);

      struct file *current_file = thread_current()->file_descriptors[fd];
      if (current_file != NULL)
        tell_pointer = file_tell(current_file);

      lock_release(&sys_lock);
    }

  return tell_pointer;
}

uint32_t
sys_close(int fd)
{
  if (is_file_descriptor_valid(fd))
    {
      struct thread *current_thread = thread_current();
      lock_acquire(&sys_lock);

      struct file *current_file = current_thread->file_descriptors[fd];
      current_thread->file_descriptors[fd] = NULL;
      if (current_file != NULL)
        file_close(current_file);

      lock_release(&sys_lock);
    }

  return -1;
}

/* Project 3 and optionally project 4. */
/*
 * Memory Mapped Files
 *
 * If successful, this function returns a “mapping ID” that uniquely identifies the mapping
 * within the process. On failure, it must return -1, which otherwise should not be
 * a valid mapping id, and the process’s mappings must be unchanged.
 *
 * A call to mmap may fail if the file open as fd has a length of zero bytes. It must fail
 * if addr is not page-aligned or if the range of pages mapped overlaps any existing set
 * of mapped pages, including the stack or pages mapped at executable load time. It
 * must also fail if addr is 0, because some Pintos code assumes virtual page 0 is not
 * mapped. Finally, file descriptors 0 and 1, representing console input and output, are
 * not mappable.
 */
uint32_t
sys_mmap (int fd, const void *addr)
{
  if (!is_file_descriptor_valid(fd) || (pg_ofs(addr) != 0) ||
      !is_valid_user_access_vaddr (addr) || is_user_stack_vaddr(addr)
      || sys_filesize(fd) <= 0)
    {
      return -1;
    }

  uint32_t mapid = -1;
  struct thread *t = thread_current();

  lock_acquire(&sys_lock);

  struct file *current_file = t->file_descriptors[fd];

  if (current_file == NULL)
    {
      goto done_mmap;
    }

  /* Reopen the file so there are two references to the same file.*/
  struct file *mmap_file = file_reopen(current_file);
  if (mmap_file == NULL)
    {
      goto done_mmap;
    }

  const off_t mmap_length = file_length(mmap_file);

  /* Get the supplemental table and see if the memory is mapped or not. */
  if (memory_overlap(addr, mmap_length, t))
    {
      file_close(mmap_file);
      goto done_mmap;
    }

  /* Adds the memory mappings in the supplemental table. */
  add_mmapings(addr, mmap_length, t);

  /* Save the mapid and the file in the mmap hash table. */
  add_mmap_info(addr, mmap_file, t);

  /* Mapid is equals to the starting virtual address where the file will be mapped.*/
  mapid = (uint32_t) addr;

  done_mmap:
    lock_release(&sys_lock);
    return mapid;
}

uint32_t sys_munmap (int mapid)
{
  struct thread *t = thread_current();

  lock_acquire(&sys_lock);

  struct mmap_info *mmap = mmap_info_lookup(&t->mmap_ids, mapid);
  if (mmap == NULL)
    {
      goto done_munmap;
    }

  /* Dump the information to the file. */
  dump_and_release_mmap(mmap, t);
  hash_delete(&t->mmap_ids, &mmap->hash_elem);
  free(mmap);

  done_munmap:
    lock_release(&sys_lock);
    return 0;
}

/* Project 4 only. */
uint32_t sys_chdir (const char *dir)
{
  return 0;
}

uint32_t sys_mkdir (const char *dir)
{
  return 0;
}

uint32_t sys_readdir (int fd, char *name)
{
  return 0;
}


uint32_t sys_isdir (int fd)
{
  return 0;
}

uint32_t sys_inumber (int fd)
{
  return 0;
}

/* It scans the supplemental table to see if all the consecutive pages that it
 * requires are not used. It returns true if the pages are not used, otherwise false. */
static bool
memory_overlap(const void *addr, uint32_t read_bytes, const struct thread *t)
{
  /* Get the supplemental table and see if the memory is mapped or not. */
  uint8_t *upage = addr;
  struct supplemental_page *sup_page;
  bool memory_overlap = false;
  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;

      sup_page = supplemental_page_lookup(&t->supplemental_pages, pg_no (upage));
      if (sup_page != NULL)
        {
          memory_overlap = true;
          break;
        }

      read_bytes -= page_read_bytes;
      upage += PGSIZE;
    }

  return memory_overlap;
}

/*
 * It creates the supplemental pages for the memory mappings and add them
 * to the supplemental table. It also calculate the offsets and how many
 * bytes are required to read from the file.
 */
static void
add_mmapings(const void *addr, uint32_t read_bytes, const struct thread *t)
{
  uint8_t *upage = (uint8_t *) addr;
  off_t offset = 0;

  /* If the necessary memory doesn't overlap, create the entries in the supplemental table. */
  while (read_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Creating the supplemental page table to store extra page information. */
      struct supplemental_page *sup_page = malloc(
          sizeof(struct supplemental_page));
      sup_page->type = MMAP;
      sup_page->read_bytes = page_read_bytes;
      sup_page->zero_bytes = page_zero_bytes;
      sup_page->mapid = (uint32_t) addr;
      sup_page->virtual_page_number = pg_no(upage);
      sup_page->virtual_user_address = (uintptr_t) upage;
      sup_page->offset = offset;
      sup_page->writable = true;
      sup_page->loaded = false;
      sup_page->swapped = false;

      offset += page_read_bytes;

      hash_insert(&t->supplemental_pages, &sup_page->hash_elem);

      /* Advance. */
      read_bytes -= page_read_bytes;
      upage += PGSIZE;
    }
}

/* It creates a memory map info and sets the mapping info and the pointer to the
 * memory map file. It also inserts the memory map in the memory map info table.
 */
static void
add_mmap_info(const void *addr, const struct file *mmap_file, const struct thread *t)
{
  struct mmap_info *mmap_info = malloc(
           sizeof(struct mmap_info));
  mmap_info->mapid = (uintptr_t) addr;
  mmap_info->mmap_file = mmap_file;
  hash_insert(&t->mmap_ids, &mmap_info->hash_elem);
}
