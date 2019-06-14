#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* struct to keep the command line parameters.*/
struct command_param
{
  char *parameter;
  struct list_elem elem;
};

/* List of process-monitoring structs. */
struct list processes_list;

/* Functions to manipulate the command line parameters. */
static void tokenize_command_line(char *command_line, struct list *ptr_list);
static void release_memory_elem_list (struct list *ptr_list);

/* Functions to set up the stack with the command line parameters. */
static uint32_t set_parameters_stack(struct list *ptr_list, uint32_t address_parameters[],  size_t num_parameters);
static void set_word_align(uint32_t stack_address);
static void set_increase_stack_pointer(void **esp, uint32_t value);

/* Function to manipulate user memory. */
static int get_user (const uint32_t *uaddr);
static bool put_user (uint32_t *udst, uint8_t byte);

/* Functions to synchronize the process creation, loading and waiting.*/
static void init_process_monitor (struct process_monitor *pm, tid_t tid);
static struct process_monitor *get_process_monitor (tid_t tid);
static void remove_dead_children (tid_t parent_tid);

void
process_init()
{
  list_init (&processes_list);
}

/* Initialize the process monitor and put it in the processes list. */
static void
init_process_monitor (struct process_monitor *pm, tid_t tid)
{
  pm->tid = tid;
  pm->parent_tid = thread_current ()->tid;
  pm->is_loaded_successfully = false;
  pm->is_alive = false;
  pm->executable = NULL;
  lock_init(&pm->process_lock);
  cond_init(&pm->child_alive);

  list_push_front(&processes_list, &pm->elem);
}

/* Retrieves the process_monitor struct for the given tid if one exists. */
static struct process_monitor *
get_process_monitor (tid_t tid)
{
  // TODO INSTEAD OF USING A LINKED LIST WE CAN USE A HASH MAP.
  struct list_elem *temp;
  struct process_monitor *pm;

  for (temp = list_begin (&processes_list); temp != list_end (&processes_list);
       temp = list_next (temp))
    {
      pm = list_entry (temp, struct process_monitor, elem);
      if (pm->tid == tid)
        {
          return pm;
        }
    }

  return NULL;
}

/* Remove the dead children that belongs to the given parent tid and free
 * the allocated memory. */
static void
remove_dead_children (tid_t parent_tid)
{
  struct list_elem *temp;
  struct process_monitor *pm;

  for (temp = list_begin (&processes_list); temp != list_end (&processes_list); )
    {
      pm = list_entry (temp, struct process_monitor, elem);
      if (pm->parent_tid == parent_tid && !pm->is_alive)
        {
          /* Remove the element from the list and free the allocated memory*/
          temp = list_remove(temp);
          free(pm);
          continue;
        }

      temp = list_next (temp);
    }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct  thread *parent = thread_current();
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parent getting the monitor lock for this thread */
  lock_acquire(&parent->load_lock);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
    {
      palloc_free_page (fn_copy);
    }
  else
    {
      /* Setting the tid in the process monitor data structure. */
      struct process_monitor *pm = malloc (sizeof (struct process_monitor));
      init_process_monitor(pm, tid);

      /* Parent waiting for the child to finish loading. */
      cond_wait(&parent->process_loaded, &parent->load_lock);

      /* Check if it was loaded successfully  */
      if (!pm->is_loaded_successfully)
        {
          tid = TID_ERROR;
        }
    }

  /* Parent releasing the monitor lock for this thread */
  lock_release(&parent->load_lock);

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current();

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* Child trying to adquire the parent's lock */
  lock_acquire(&cur->parent->load_lock);

  struct process_monitor *pm = get_process_monitor(cur->tid);
  /* Sets the monitor in the current thread. */
  cur->monitor = pm;

  pm->is_loaded_successfully = success;
  pm->is_alive = success;

  if (!success)
    {
      thread_current ()->exit_status = -1;
    }

  /* Signal the parent that is already loaded. */
  cond_signal(&cur->parent->process_loaded, &cur->parent->load_lock);

  /* Child releasing the lock so the parent can continue. */
  lock_release(&cur->parent->load_lock);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  /* Find the thread child and check if it's dead or alive */
  struct process_monitor *pm = get_process_monitor(child_tid);

  if (pm == NULL)
    return -1;

  struct thread *cur = thread_current();

  if (pm->parent_tid != cur->tid)
    return -1;

  /* Parent acquiring the child lock to enter the monitor. */
  lock_acquire(&pm->process_lock);

  if (pm->is_alive)
    {
      /* Parent waiting for the signal. */
      cond_wait(&pm->child_alive, &pm->process_lock);
    }

  int exit_status = pm->exit_status;

  /* A process may wait for any given child at most once.
   * It returns -1 the second time. */
  pm->exit_status = -1;

  /* Parent releasing the child lock.*/
  lock_release(&pm->process_lock);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct process_monitor *pm = cur->monitor;

  lock_acquire(&pm->process_lock);

  printf ("%s: exit(%d)\n", cur->process_name, cur->exit_status);

  pm->is_alive =  false;
  pm->exit_status = cur->exit_status;

  /* Closing the executable. */
  file_close (pm->executable);

  cond_signal(&pm->child_alive, &pm->process_lock);

  /* Releasing resources - file descriptors. */
  // TODO Optimaze the closing of the files by decreasing the counter.
  int i;
  for (i = STARTING_RANGE_FILE_DESCRIPTORS; i < MAX_FILE_DESCRIPTORS; i++)
    file_close (cur->file_descriptors[i]);

  /* If parent is dead, the monitor is not needed anymore. */
  struct process_monitor *parent_monitor = get_process_monitor(cur->parent_tid);
  if (parent_monitor != NULL && !parent_monitor->is_alive)
    {
      /* Remove the monitor for the current thread. */
      list_remove(&parent_monitor->elem);
      free(parent_monitor);
    }

  remove_dead_children (cur->tid);

  lock_release(&pm->process_lock);

  // TODO if the parent is dead and there is not children alive, remove the pm.
  // TODO We can do it by return a value for remove_dead_children indicating that there are not
  // TODO more children.

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, struct list *ptr_list);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Tokenize the command line. It takes the command line and when it
 finds a white space it replaces by \0.

 Example:

    Input: echo p1 p2
    Output: echo\0p1\0\p2\0

 After this, it puts the parameters in the list.
*/
static void
tokenize_command_line(char *command_line, struct list *ptr_list)
{
  char *token, *save_ptr;
  for (token = strtok_r (command_line, " ", &save_ptr);
      token != NULL; token = strtok_r (NULL, " ", &save_ptr))
    {
      /* The requested memory has to be released when the element or list is not needed anymore */
      struct command_param *param = (struct command_param *) malloc(sizeof(struct command_param));
      param->parameter = token;
      list_push_front(ptr_list, &param->elem);
    }
}

/* It releases the memory that was allocated for the elements of the list. */
static void
release_memory_elem_list (struct list *ptr_list)
{
  struct list_elem *e;
  while (!list_empty (ptr_list))
    {
      e = list_pop_front (ptr_list);
      struct command_param *ptr_param = list_entry(e, struct command_param, elem);
      free(ptr_param);
    }
}

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  struct list parameter_list;

  /* Initialize parameter list. */
  list_init(&parameter_list);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  // TODO This validation is not enough because the data can be PGSIZE plus the data in the stack.
  /* Verify that the command line is not greater than the Page Size. */
  if (strlen(file_name) > PGSIZE)
    goto done;

  /* Tokenize file_name and set the parameters in the list.*/
   tokenize_command_line(file_name, &parameter_list);
   /* At this point, file_name is tokenized and the pointer to the first element is a
      pointer to the file name and not to its parameters. */

   /* Name the process with the file name. */
   strlcpy (t->process_name, file_name, strlen (file_name) + 1);

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Denying to write to this file. */
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, &parameter_list))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

  struct process_monitor *pm = get_process_monitor(t->tid);
  pm->executable = file;

  done:
    /* Releasing memory from the list.*/
    release_memory_elem_list(&parameter_list);
    /* If the loading was not successful, close the file. */
    if (!success)
      file_close (file);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Sets the command line parameters at the top of the stack. Start setting the last parameter,
   then the before the last parameter and so on. It also saves the address where these parameters
   start.

   It returns the address in the stack where the firt parameter is.
 */
static uint32_t
set_parameters_stack(struct list *ptr_list, uint32_t address_parameters[],  size_t num_parameters)
{
  /* Start writing just below PHYS_BASE (0xbfffffff). */
  uint32_t stack_address = (uint32_t) PHYS_BASE;

  int param_index = 0;

  /* Setting the parameters in the stack. */
  struct list_elem *e;
  for (e = list_begin(ptr_list); e != list_end(ptr_list); e = list_next(e))
    {
      struct command_param *ptr_param = list_entry(e, struct command_param, elem);
      char *param = ptr_param->parameter;

      int j;
      /* Taking into account '\0'. */
      for (j = strlen(param); j >= 0; j--)
        {
          stack_address--; /* Going for upper memory to lower memory. */
          put_user(stack_address, param[j]);
        }
      /* Save the pointers to the parameters */
      address_parameters[param_index] = stack_address;
      param_index++;
    }

  return stack_address;
}

/* Sets the word-align in the stack so the stack pointer always points to 4 multiples. */
static void
set_word_align(uint32_t stack_address)
{
  /* Setting word-align so the stack pointer points to 4 multiples. */
  int num_chars = (uint32_t) PHYS_BASE - stack_address;
  while (num_chars % STACK_SIZE_BYTES != 0)
    {
      stack_address--;
      put_user(stack_address, 0);
      num_chars++;
    }
}

/* Sets and increase the stack pointer. */
static void
set_increase_stack_pointer(void **esp, uint32_t value)
{
   *esp = (void *) (*esp - 4);
   uint32_t *current_address = *esp;
   *current_address = value;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, struct list *ptr_list)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        {
          size_t num_parameters = list_size(ptr_list);
          uint32_t address_parameters[num_parameters];

          /* Setting the parameters in the stack. */
          uint32_t stack_address = set_parameters_stack(ptr_list, address_parameters, num_parameters);

          /* Setting word-align so the stack pointer points to 4 multiples. */
          set_word_align(stack_address);

          /* Initializing the stack pointer with the current stack address. */
          *esp = (void *) stack_address;

          /* Setting the last parameter arg[n] = \0 */
          set_increase_stack_pointer(esp, 0);

          /* Setting the addresses of the command line parameters in the stack. */
          int i;
          for (i = 0; i < num_parameters; i++)
            set_increase_stack_pointer(esp, address_parameters[i]);

          /* Setting the address of the first parameter (name of the program). */
          set_increase_stack_pointer(esp, (uint32_t) *esp);

          /* Setting the number of parameters. */
          set_increase_stack_pointer(esp, num_parameters);

          /* Setting the return address. */
          set_increase_stack_pointer(esp, 0);
        }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segment fault
   occurred. */
static int
get_user (const uint32_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segment fault occurred. */
static bool
put_user (uint32_t *udst, uint8_t byte)
{

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
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
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
