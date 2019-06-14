#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "exception.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

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
static uint32_t sys_mmap (int fd, void *addr);
static uint32_t sys_munmap (mapid_t);

/* Project 4 only. */
static uint32_t sys_chdir (const char *dir);
static uint32_t sys_mkdir (const char *dir);
static uint32_t sys_readdir (int fd, char *name);
static uint32_t sys_isdir (int fd);
static uint32_t sys_inumber (int fd);

/* Array of sys_handlers */
static sys_handler sys_handlers [NUMBER_SYS_HANDLERS];

/* Function to validate the parameters. */
static bool is_valid_pointer(const void *pointer);
static bool is_file_descriptor_valid(int fd);
static bool is_buffer_mapped(void *buffer, uint32_t length);
static bool string_is_bounded_safe (char *str, int num_bytes);

static struct lock sys_lock;

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

  /* Validating that the stack pointer points to a valid address for the 3 parameters and
   * the system call number. */
  if (!is_valid_pointer(stack_pointer) ||
      !is_valid_pointer(stack_pointer + 1) ||
      !is_valid_pointer(stack_pointer + 2) ||
      !is_valid_pointer(stack_pointer + 3))
    {
      sys_exit(-1);
    }

  /* The top of the stack contains the sys call */
  uint32_t sys_call_number = *stack_pointer;

  if (sys_call_number < SYS_HALT || sys_call_number > SYS_INUMBER)
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

  if (!is_valid_pointer(file))
    {
      /* *file pointer is invalid. */
      sys_exit(-1);
    }

  if (!string_is_bounded_safe(file, PGSIZE))
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

/* It checks that the string has a valid address and that is not in the kernel code.*/
static bool
is_valid_pointer(const void *pointer) {
  if (pointer == NULL)
    return false;

  struct thread *t = thread_current ();
  if (!is_user_vaddr(pointer) || pagedir_get_page (t->pagedir, pointer) == NULL)
    return false;

  return true;
}

/* First checks that a given string is mapped over NUM_BYTES, then checks
that the string terminates within NUM_BYTES. Returns true if both conditions
are satisfied, false if the string doesn't terminate properly, and results in
termination of this thread if the string points to unmapped memory. */
static bool
string_is_bounded_safe (char *str, int num_bytes)
{
  int i;
  for (i = 0; i < num_bytes; i++)
    {
      if (*(str + i) == NULL)
        return true;
    }

  return false;
}

static bool
is_buffer_mapped(void *buffer, uint32_t length) {

  // TODO Use a for in order to check the intermediate pages.
  if (is_valid_pointer(buffer) && is_valid_pointer((uint32_t) buffer + length))
    return true;

  return false;
}

uint32_t
sys_create(const char *file, unsigned initial_size)
{
  if (!is_valid_pointer(file))
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
  if (!is_valid_pointer(file))
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
  if (!is_valid_pointer(file))
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
  if(!is_valid_pointer(buffer) || !is_buffer_mapped(buffer, length))
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
        read = file_read(current_file, buffer, length);
    }

  done_read:
    lock_release(&sys_lock);
    return read;
}

uint32_t
sys_write(int fd, const void *buffer, unsigned length)
{
  off_t write = -1;

  if (!is_valid_pointer(buffer) || !is_buffer_mapped(buffer, length))
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
uint32_t sys_mmap (int fd, void *addr)
{
  return 0;
}

uint32_t sys_munmap (mapid_t)
{
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

