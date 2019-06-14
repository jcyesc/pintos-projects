#include "threads/thread.h"
#include "threads/fixed-point.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "../devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#include "tests/threads/tests.h"

/* Random value for struct thread's `magic' member.
 Used to detect stack overflow.  See the big comment at the top
 of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
 that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
 when they are first scheduled and removed when they exit. */
static struct list all_list;

/* List of processes in THREAD_SLEEPING state. Threads are added to this list
 when they are put to sleep and removed when they are woken up. */
static struct list sleeping_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Lock used when manipulating sleeping threads list */
static struct lock sleeping_list_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
{
  void *eip; /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux; /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks; /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks; /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* Fixed point representation of the 4.4BSD scheduler load average. */
static fixed_point_t load_avg;

static void
kernel_thread(thread_func *, void *aux);

static void
idle(void *aux UNUSED);
static struct thread *
running_thread(void);
static struct thread *
next_thread_to_run(void);
static void
init_thread(struct thread *, const char *name, int priority);
static bool
is_thread(struct thread *) UNUSED;
static void *
alloc_frame(struct thread *, size_t size);
static void
schedule(void);
void
thread_schedule_tail(struct thread *prev);
static tid_t
allocate_tid(void);

/* Initializes the threading system by transforming the code
 that's currently running into a thread.  This can't work in
 general and it is possible in this case only because loader.S
 was careful to put the bottom of the stack at a page boundary.

 Also initializes the run queue and the tid lock.

 After calling this function, be sure to initialize the page
 allocator before trying to create any threads with
 thread_create().

 It is not safe to call thread_current() until this function
 finishes. */
void
thread_init(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  lock_init(&sleeping_list_lock);
  list_init(&ready_list);
  list_init(&sleeping_list);
  list_init(&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();

  /* Set initial load average to 0 */
  load_avg = fix_int(0);
}

/* Starts preemptive thread scheduling by enabling interrupts.
 Also creates the idle thread. */
void
thread_start(void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  // msg("----------- IDLE THREAD CREATE --------------");
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  // msg("----------- IDLE SEMA DOWN BEFORE --------------");
  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);

  // msg("----------- IDLE SEMA DOWN AFTER --------------");
}

/* Less comparator passed to list_sort  */
bool
sleep_until_less(const struct list_elem *a, const struct list_elem *b,
    void *aux UNUSED)
{
  return list_entry(a, struct thread, sleep_elem)->sleep_until
      < list_entry(b, struct thread, sleep_elem)->sleep_until;
}

void
thread_sleep(int64_t sleep_until)
{
  struct thread *t = thread_current();

  /* Set sleep time on current thread */
  t->sleep_until = sleep_until;

  /* Add to sleeping list */
  lock_acquire(&sleeping_list_lock);
  list_insert_ordered(&sleeping_list, &t->sleep_elem, &sleep_until_less, NULL);
  lock_release(&sleeping_list_lock);

  /* Block thread with semaphore */
  sema_init(&t->sleep_sem, 0);
  sema_down(&t->sleep_sem);
}

void
wake_sleeping_threads(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  struct list_elem *cur_elem;
  struct thread *cur_thread;

  for (cur_elem = list_begin(&sleeping_list);
      cur_elem != list_end(&sleeping_list); cur_elem = list_next(cur_elem))
    {
      cur_thread = list_entry (cur_elem, struct thread, sleep_elem);

      if (timer_elapsed(cur_thread->sleep_until) >= 0)
        {
          /* Thread done sleeping, so remove from sleeping threads list */
          list_remove(&cur_thread->sleep_elem);

          /* Unblock thread by releasing semaphore */
          sema_up(&cur_thread->sleep_sem);
        }
      else
        {
          /* Current and remaining threads expire in the future and do not need
           to be woken up */
          break;
        }
    }
}

/* Called by the timer interrupt handler at each timer tick.
 Thus, this function runs in an external interrupt context. */
void
thread_tick(void)
{
  struct thread *t = thread_current();

  // msg("THREAD TICK %s", t->name);

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
  user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();

  if (t != idle_thread)
    t->recent_cpu = fix_add(t->recent_cpu, fix_int(1));

  wake_sleeping_threads();

  if (thread_mlfqs)
    {
      if (timer_ticks() % TIMER_FREQ == 0)
        {
          thread_calculate_recent_cpu();
          thread_calculate_load_avg();
        }

      if (timer_ticks() % 4 == 0)
        {
          thread_calculate_priority();

          struct thread *highest_t =
              list_entry (list_begin (&ready_list), struct thread, elem);

          if (!list_empty(&ready_list) && highest_t->priority > t->priority)
            intr_yield_on_return();
        }
    }
}

/* Prints thread statistics. */
void
thread_print_stats(void)
{
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
      idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
 PRIORITY, which executes FUNCTION passing AUX as the argument,
 and adds it to the ready queue.  Returns the thread identifier
 for the new thread, or TID_ERROR if creation fails.

 If thread_start() has been called, then the new thread may be
 scheduled before thread_create() returns.  It could even exit
 before thread_create() returns.  Contrariwise, the original
 thread may run for any amount of time before the new thread is
 scheduled.  Use a semaphore or some other form of
 synchronization if you need to ensure ordering.

 The code provided sets the new thread's `priority' member to
 PRIORITY, but no actual priority scheduling is implemented.
 Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create(const char *name, int priority, thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void
  (*)(void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock(t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
 again until awoken by thread_unblock().

 This function must be called with interrupts turned off.  It
 is usually a better idea to use one of the synchronization
 primitives in synch.h. */
void
thread_block(void)
{
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
 This is an error if T is not blocked.  (Use thread_yield() to
 make the running thread ready.)

 This function does not preempt the running thread.  This can
 be important: if the caller had disabled interrupts itself,
 it may expect that it can atomically unblock a thread and
 update other data. */
void
thread_unblock(struct thread *t)
{
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  list_insert_ordered(&ready_list, &t->elem, &thread_priority_less, NULL);
  t->status = THREAD_READY;

  // msg("THREAD_UNBLOCK() CALLER -> %s", thread_current()->name);
  // msg("THREAD_UNBLOCK() UNBLOCKING -> %s", t->name);

  /* Ensure we are not in an interrupt context because intr_handler()
   must be allowed to finish executing. */
  if (!intr_context() && thread_current() != idle_thread
      && t->priority > thread_current()->priority)
    {
      // msg("THREAD_UNBLOCK() YIELDING -> %s", thread_current()->name);
      thread_yield();
    }

  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
  return thread_current()->name;
}

/* Returns the running thread.
 This is running_thread() plus a couple of sanity checks.
 See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
   If either of these assertions fire, then your thread may
   have overflowed its stack.  Each thread has less than 4 kB
   of stack, so a few big automatic arrays or moderate
   recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid(void)
{
  return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
 returns to the caller. */
void
thread_exit(void)
{
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
   and schedule another process.  That process will destroy us
   when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
 may be scheduled again immediately at the scheduler's whim. */
void
thread_yield(void)
{
  struct thread *cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());
  // msg("THREAD YIELD () %s", cur->name);
  old_level = intr_disable();
  if (cur != idle_thread)
    list_insert_ordered(&ready_list, &cur->elem, &thread_priority_less, NULL);
  cur->status = THREAD_READY;

  schedule();
  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
 This function must be called with interrupts off. */
void
thread_foreach(thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func(t, aux);
    }
}

/* Thread priority comparator function */
bool
thread_priority_less(const struct list_elem *a, const struct list_elem *b,
    void *aux UNUSED)
{
  struct thread *ta, *tb;

  ASSERT(a != NULL && b != NULL);

  ta = list_entry (a, struct thread, elem);
  tb = list_entry (b, struct thread, elem);

  return (ta->priority > tb->priority);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority(int new_priority)
{
  ASSERT(!intr_context());

  struct thread *t = thread_current();

  if (t->priority == t->base_priority || t->priority < new_priority)
    t->priority = new_priority;
  t->base_priority = new_priority;

  enum intr_level old_level;
  old_level = intr_disable();
  /* Yield if new priority is lower than another ready thread's priority */
  if (!list_empty(&ready_list)
      && new_priority
          < list_entry (list_begin (&ready_list), struct thread, elem)->priority)
    {
      thread_yield();
    }
  intr_set_level(old_level);
}

/* Donates priority from one thread to a lock and/or its holder. */
void
thread_donate_priority(struct thread *t, struct lock *lock)
{
  if (t->priority > lock->holder->priority)
    {
      lock->priority = t->priority;
      apply_donation(t->priority, lock->holder);
    }
  else if (lock->holder->base_priority == lock->priority)
    lock->priority = t->priority;
}

/* Updates the priority of the thread donated to. Recursively updates the
 priority of all threads holding locks that the donatee thread needs. */
void
apply_donation(int new_priority, struct thread *t)
{
  struct lock *lock;

  if (t->status == THREAD_READY)
    {
      enum intr_level old_level;
      old_level = intr_disable();

      t->priority = new_priority;
      list_remove(&t->elem);
      list_insert_ordered(&ready_list, &t->elem, &thread_priority_less, NULL);

      intr_set_level(old_level);
    }
  else
    {
      lock = t->blocked_on_lock;
      if (lock != NULL)
        lock->priority = new_priority;
      t->priority = new_priority;

      /* This thread is blocked on another lock, so donate recursively to
       that lock's holder. */
      if (lock != NULL)
        thread_donate_priority(t, lock);
    }
}

/* Handles the release of a lock by removing the lock from the holder's
 lock_list and then updates the priority of the holder. The holder's new
 priority must be set to the priority of the highest-priority lock it still
 holds or the holder's base_priority if it holds no other donated to locks. */
void
thread_release_lock(struct lock *lock)
{
  struct thread *t = thread_current();
  int i;
  int high = 0;

  /* Iterate through the thread's lock_list until the lock is found. Then
   remove the lock and decrement lock_count. */
  for (i = 0; i < t->lock_count; i++)
    {
      if (t->lock_list[i] == lock)
        {
          t->lock_list[i] =
              (--(t->lock_count) == 0) ? NULL : t->lock_list[t->lock_count];
          t->lock_list[t->lock_count] = NULL;
          break;
        }
    }

  /* Now find the lock with the highest priority to determine the priority
   the thread should revert to. */
  if (t->lock_count > 0)
    {
      for (i = 0; i < t->lock_count; i++)
        {
          high =
              (t->lock_list[i]->priority > t->lock_list[high]->priority) ?
                  i : high;
        }
    }

  /* Reset lock priority */
  lock->priority = PRI_MIN;

  t->priority =
      (t->lock_count > 0) ? t->lock_list[high]->priority : t->base_priority;
}

/* Calculates priority of all threads for the 4.4BSD scheduler. This function
traverses the all_list and calls thread_calculate_single_priority() for each
thread. After all thread priorities are recalculated, we sort ready_list by
the new priorities. */
void
thread_calculate_priority(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  struct list_elem *e;
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);

      thread_calculate_single_priority(t);
    }

  list_sort(&ready_list, &thread_priority_less, NULL);
}

/* Calculates the priority of a single thread for the 4.4BSD scheduler. This
function uses the formula:
priority = PRI_MAX - (recent_cpu / 4) - (nice * 2). */
void
thread_calculate_single_priority(struct thread *t)
{
  if (t == idle_thread)
    return;

  fixed_point_t first_part = fix_div(t->recent_cpu, fix_int(4));

  fixed_point_t second_part = fix_mul(fix_int(t->thread_nice), fix_int(2));

  fixed_point_t third_part = fix_sub(fix_int(PRI_MAX), first_part);

  int priority = fix_round(fix_sub(third_part, second_part));

  if (priority < PRI_MIN)
    priority = PRI_MIN;
  else if (priority > PRI_MAX)
    priority = PRI_MAX;

  t->priority = priority;
}

/* Calculates the load_avg for the 4.4BSD scheduler. This function uses the
formula: load_avg = (59/60)*load_avg + (1/60)*ready_threads, where
ready_threads is the number of threads either running or waiting to run. */
void
thread_calculate_load_avg(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  int ready_threads = list_size(&ready_list);
  if (thread_current() != idle_thread)
    ready_threads++;

  fixed_point_t first_part = fix_mul(fix_div(fix_int(59), fix_int(60)),
      load_avg);

  fixed_point_t second_part = fix_mul(fix_div(fix_int(1), fix_int(60)),
      fix_int(ready_threads));

  load_avg = fix_add(first_part, second_part);
}

/* Calculates each thread's recent_cpu for 4.4BSD scheduler. This function
uses the formula:
recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice. */
void
thread_calculate_recent_cpu(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  struct list_elem *e;
  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);

      if (t == idle_thread)
        continue;

      fixed_point_t first_part = fix_mul(fix_int(2), load_avg);

      fixed_point_t second_part = fix_add(
          fix_mul(fix_int(2), load_avg), fix_int(1));

      fixed_point_t third_part = fix_div(first_part, second_part);

      fixed_point_t fourth_part = fix_mul(third_part, t->recent_cpu);

      t->recent_cpu = fix_add(fourth_part,
          fix_int(t->thread_nice));
    }
}

/* Returns the current thread's priority. */
int
thread_get_priority(void)
{
  return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice(int nice)
{
  ASSERT(nice >= NICE_MIN && nice <= NICE_MAX);

  struct thread *t = thread_current();

  t->thread_nice = nice;

  /* Recalculate thread's priority and yield to another thread if necessary. */
  thread_calculate_single_priority(t);
  thread_set_priority(t->priority);
}

/* Returns the current thread's nice value. */
int
thread_get_nice(void)
{
  return thread_current()->thread_nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg(void)
{
  return fix_round(fix_scale(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu(void)
{
  return fix_round(fix_scale(thread_current()->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

 The idle thread is initially put on the ready list by
 thread_start().  It will be scheduled once initially, at which
 point it initializes idle_thread, "up"s the semaphore passed
 to it to enable thread_start() to continue, and immediately
 blocks.  After that, the idle thread never appears in the
 ready list.  It is returned by next_thread_to_run() as a
 special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);
  // msg("AFTER IDLE SEMA UP");


  for (;;)
    {
      // msg("IDLE() INTERRUPT DISABLE");
      /* Let someone else run. */
      intr_disable();
      thread_block();
      // msg("IDLE() AFTER THREAD BLOCK");

      /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread(void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
   down to the start of a page.  Because `struct thread' is
   always at the beginning of a page and the stack pointer is
   somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread(struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
 NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = t->base_priority = priority;
  t->lock_count = 0;
  t->magic = THREAD_MAGIC;

  if (thread_mlfqs)
    {
      if (t == initial_thread)
        {
          t->recent_cpu = fix_int(0);
          t->thread_nice = NICE_DEFAULT;
        }
      else
        {
          t->recent_cpu = thread_current()->recent_cpu;
          t->thread_nice = thread_current()->thread_nice;
        }

      thread_calculate_single_priority(t);
    }

  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);
  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
 returns a pointer to the frame's base. */
static void *
alloc_frame(struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
 return a thread from the run queue, unless the run queue is
 empty.  (If the running thread can continue running, then it
 will be in the run queue.)  If the run queue is empty, return
 idle_thread. */
static struct thread *
next_thread_to_run(void)
{
  if (list_empty(&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
 tables, and, if the previous thread is dying, destroying it.

 At this function's invocation, we just switched from thread
 PREV, the new thread is already running, and interrupts are
 still disabled.  This function is normally invoked by
 thread_schedule() as its final action before returning, but
 the first time a thread is scheduled it is called by
 switch_entry() (see switch.S).

 It's not safe to call printf() until the thread switch is
 complete.  In practice that means that printf()s should be
 added at the end of the function.

 After this function and its caller returns, the thread switch
 is complete. */
void
thread_schedule_tail(struct thread *prev)
{
  struct thread *cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
   thread.  This must happen late so that thread_exit() doesn't
   pull out the rug under itself.  (We don't free
   initial_thread because its memory was not obtained via
   palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT(prev != cur);
      palloc_free_page(prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
 the running process's state must have been changed from
 running to some other state.  This function finds another
 thread to run and switches to it.

 It's not safe to call printf() until thread_schedule_tail()
 has completed. */
static void
schedule(void)
{
  struct thread *cur = running_thread();
  struct thread *next = next_thread_to_run();
  struct thread *prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  //msg("Scheduler CURRENT %s NEXT %s", cur->name, next->name);

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
 Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
