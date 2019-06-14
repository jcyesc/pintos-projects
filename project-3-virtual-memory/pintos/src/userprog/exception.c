#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "hash.h"
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *f);
static void page_fault (struct intr_frame *);
static bool is_valid_fault_address(void *fault_addr, void *esp, struct thread *t);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f UNUSED)
{
  /* Indicate the process has failed. */
  thread_current ()->exit_status = -1;
  thread_exit ();
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* The address is not a valid virtual user address or the address doesn't have
   * permissions to be written because it might be the code segment. */
 if (!is_valid_user_access_vaddr(fault_addr) || (write && !not_present))
   {
      /* Indicate the process has failed. */
      kill (f);
   }

   /* Loading the page. */
  struct thread *t = thread_current();
  struct supplemental_page *sup_page = supplemental_page_lookup(&t->supplemental_pages, pg_no (fault_addr));

  /* There is not entry in the supplemental page and this could be stack grow. */
  if (sup_page == NULL)
   {
      /* It grows the stack. */
      if (is_valid_fault_address(fault_addr, f->esp, t) && is_user_stack_vaddr(fault_addr))
        {
          /* Creating the supplemental page table to store extra page information. */
          struct supplemental_page *sup_page = malloc(
              sizeof(struct supplemental_page));
          sup_page->type = STACK;
          sup_page->virtual_page_number = pg_no(fault_addr);
          sup_page->virtual_user_address = (uint32_t) fault_addr & ~PGMASK; /* Make sure that the offset is ZERO. */
          sup_page->writable = true;
          sup_page->loaded = false;
          sup_page->swapped = false;

          hash_insert(&t->supplemental_pages, &sup_page->hash_elem);
          load_stack_page(t, sup_page);
          return;
        }

      /* Exits the process if it's not a valid grow or a valid stack address. */
      kill(f);
   }
  else
    {
      /* It loads the executable or mmap file. */
      load_page(t, sup_page);
    }
}


/*
 * Validates that the fault address is:
 *
 * - Fault address could be 32 bytes below the stack pointer due to the PUSHA instruction.
 * - Or Fault address must be above the stack pointer
 * - Or if there was a system call, the esp is in the thread struct and the fault address
 *   must be above the stack pointer.
 *
 * Note:
 *
 * Since the processor only saves the stack pointer when an exception causes a switch
 * from user to kernel mode, reading esp out of the struct intr_frame passed to page_fault()
 * would yield an undefined value, not the user stack pointer. You will need to arrange
 * another way, such as saving esp into struct thread on the initial transition from user
 * to kernel mode.
 *
 */
static bool
is_valid_fault_address(void *fault_addr, void *esp, struct thread *t)
{
  return esp - 32 <= fault_addr || fault_addr >= esp || fault_addr >= t->esp;
}

