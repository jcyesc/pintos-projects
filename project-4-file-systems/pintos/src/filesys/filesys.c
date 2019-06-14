#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "list.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* It keeps the name of a path element.*/
struct path_elem
{
  char *name;
  struct list_elem elem;
};

/* Functions to tokenize the parameters. */
static void tokenize_path (char *path, struct list *path_list);
static void release_path_elem_list (struct list *ptr_list);
static struct dir *get_current_work_dir(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  cache_block_init();
  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_block_close();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, uint32_t type)
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                      && inode_create (inode_sector, initial_size, type)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}



/* Tokenizes the given path. It takes the path and when it
 finds '/' it replaces with \0.

 Example:

    Input: /dir1/dir2/file
    Output: dir1\0dir2\0file\0

 After this, it puts the path elements in the list.
*/
static void
tokenize_path(char *path, struct list *path_list)
{
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr);
      token != NULL; token = strtok_r (NULL, "/", &save_ptr))
    {
      /* The requested memory has to be released when the element or list is not needed anymore */
      struct path_elem *pe = (struct path_elem *) malloc(sizeof(struct path_elem));
      pe->name = token;
      list_push_back(path_list, &pe->elem);
    }
}

/* It releases the memory that was allocated for the elements of the list. */
static void
release_path_elem_list (struct list *ptr_list)
{
  struct list_elem *e;
  while (!list_empty (ptr_list))
    {
      e = list_pop_front (ptr_list);
      struct path_elem *ptr_param = list_entry(e, struct path_elem, elem);
      free(ptr_param);
    }
}

static struct dir*
get_current_work_dir(void) {
  struct dir *work_dir = thread_get_work_dir();
  if (work_dir == NULL)
    {
      /* Set the current work directory for this thread to ROOT. */
      struct dir *root = dir_open_root();
      /* This thread has the responsability to close this directory. */
      thread_set_work_dir(root);
      work_dir = root;
    }
  return work_dir;
}

bool
filesys_change_work_dir(const char *name)
{
  ASSERT(strlen(name) > 0);

  bool success = false;

  if (strlen(name) == 1 && name[0] == '/')
    {
      thread_close_work_dir();
      thread_set_work_dir(dir_open_root());
      success = true;
      return success;
    }

  char path[strlen(name) + 1];
  strlcpy(path, name, strlen(name) + 1);

  /* Creating the list of path elements. */
  struct list path_list;
  list_init(&path_list);
  tokenize_path(path, &path_list);

  struct list_elem *temp;
  struct path_elem *pe;

  bool is_absolute = path[0] == '/' ? true : false;

  /* Setting the current directory. */
  struct dir *work_dir;
  if (is_absolute)
    work_dir = dir_open_root();
  else
    work_dir = dir_reopen(get_current_work_dir());

  struct dir *cur_dir = work_dir;

  size_t size = list_size(&path_list);
  size_t process_dir = 0;

  for (temp = list_begin(&path_list); temp != list_end(&path_list); temp = list_next(temp))
    {
      process_dir++;
      pe = list_entry (temp, struct path_elem, elem);
      struct inode *inode;
      /* Check if the directory exist. */
      if (dir_lookup(cur_dir, pe->name, &inode))
        {
          dir_close(cur_dir);
          cur_dir = dir_open(inode);

          if (process_dir == size)
            {
              thread_close_work_dir();
              thread_set_work_dir(dir_reopen(cur_dir));
              success = true;
            }
        }
    }

  //dir_close(work_dir);

  /* Releasing the memory from the elements of the list. */
  release_path_elem_list(&path_list);

  return success;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create_2 (const char *name, off_t initial_size, uint32_t type)
{
  ASSERT (strlen(name) > 0);

  bool success = false;

  char path[strlen(name) + 1];
  strlcpy(path, name, strlen(name) + 1);

  /* Creating the list of path elements. */
  struct list path_list;
  list_init(&path_list);
  tokenize_path(path, &path_list);

  bool is_absolute = path[0] == '/' ? true : false;

  /* Setting the current directory. */
  struct dir *work_dir;
  if (is_absolute)
    work_dir = dir_open_root();
  else
    work_dir = dir_reopen(get_current_work_dir());


  struct dir *cur_dir = work_dir;

  size_t size = list_size(&path_list);
  size_t process_dir = 0;

  struct list_elem *temp;
  struct path_elem *pe;
  for (temp = list_begin (&path_list); temp != list_end (&path_list); temp = list_next (temp))
    {
      process_dir++;
      pe = list_entry (temp, struct path_elem, elem);

     if (process_dir != size)
       {
         struct inode *inode;
         /* Check if the directory exist. */
         if (dir_lookup(cur_dir, pe->name, &inode))
           {
             dir_close(cur_dir);
             cur_dir = dir_open(inode);
             continue;
           }
         break;
       }
     else
       {

         if (inode_is_removed(dir_get_inode(cur_dir))) {
              dir_close(cur_dir);
              break;
         }

         ASSERT (strlen (pe->name) > 0);
         ASSERT (strcmp(pe->name, ".") && strcmp(pe->name, ".."));

         /* Create the file or directory. */
         if (type == FILE_INODE)
           {
             block_sector_t inode_sector = 0;
             char *name = malloc(strlen(pe->name) + 1);
             memcpy(name, pe->name, strlen(pe->name) + 1);
             success = (cur_dir != NULL
                             && free_map_allocate (1, &inode_sector)
                                 && inode_create (inode_sector, initial_size, type)
                             && dir_add (cur_dir, name, inode_sector));
             free(name);
             if (!success && inode_sector != 0)
               free_map_release (inode_sector, 1);
           }
         else
           {
             /* It's a directory. */
             block_sector_t inode_sector = 0;
             char *name = malloc(strlen(pe->name) + 1);
             memcpy(name, pe->name, strlen(pe->name) + 1);
             success = (cur_dir != NULL
                             && free_map_allocate (1, &inode_sector)
                                 && dir_create(inode_sector, initial_size)
                             && dir_add (cur_dir, name, inode_sector));
             free(name);
             // Adding the . and .. directories
             if (success)
               {

                 char *punto = malloc(strlen(".") + 1);
                 memcpy(punto, ".", strlen(".") + 1);

                 char *dos = malloc(strlen("..") + 1);
                 memcpy(dos, "..", strlen("..") + 1);


                 struct inode *parent_inode = dir_get_inode(cur_dir);
                 block_sector_t parent_sector = inode_get_inumber(parent_inode);
                 struct dir *new_dir = dir_open(inode_open(inode_sector));
                 success = dir_add (new_dir, punto, inode_sector) &&
                     dir_add(new_dir, dos, parent_sector);

                 free (punto);
                 free (dos);
               }

             if (!success && inode_sector != 0)
               free_map_release (inode_sector, 1);
           }

         dir_close(cur_dir);
         break;
       }
    }

  /* Releasing the memory from the elements of the list. */
  release_path_elem_list(&path_list);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open2 (const char *name)
{
  ASSERT(strlen(name) > 0);

  if (strlen(name) == 1 && name[0] == '/')
    return inode_open(ROOT_DIR_SECTOR);

  char path[strlen(name) + 1];
  strlcpy(path, name, strlen(name) + 1);

  /* Creating the list of path elements. */
  struct list path_list;
  list_init(&path_list);
  tokenize_path(path, &path_list);

  struct list_elem *temp;
  struct path_elem *pe;

  bool is_absolute = path[0] == '/' ? true : false;

  /* Setting the current directory. */
  struct dir *work_dir;
  if (is_absolute)
    work_dir = dir_open_root();
  else
    work_dir = dir_reopen(get_current_work_dir());

  struct dir *cur_dir = work_dir;

  size_t size = list_size(&path_list);
  size_t process_dir = 0;

  struct inode *sys_file = NULL;
  for (temp = list_begin(&path_list); temp != list_end(&path_list); temp =
      list_next(temp))
    {
      process_dir++;
      pe = list_entry (temp, struct path_elem, elem);
      struct inode *inode;
      /* Check if the directory exist. */
      if (dir_lookup(cur_dir, pe->name, &inode))
        {

          if (process_dir == size)
            {
              if (inode_is_removed(dir_get_inode(cur_dir))) {
                  dir_close(cur_dir);
                  break;
              }

              dir_close(cur_dir);
              sys_file = inode;
              break;
            }

          dir_close(cur_dir);
          cur_dir = dir_open(inode);
        }
      else
        {
          dir_close(cur_dir);
          break;
        }
    }

  /* Releasing the memory from the elements of the list. */
  release_path_elem_list(&path_list);

  return sys_file;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 

  return success;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove2 (const char *name)
{
  ASSERT(strlen(name) > 0);
  bool success = false;

   char path[strlen(name) + 1];
   strlcpy(path, name, strlen(name) + 1);

   /* Creating the list of path elements. */
   struct list path_list;
   list_init(&path_list);
   tokenize_path(path, &path_list);

   struct list_elem *temp;
   struct path_elem *pe;

   bool is_absolute = path[0] == '/' ? true : false;

   /* Setting the current directory. */
   struct dir *work_dir;
   if (is_absolute)
     work_dir = dir_open_root();
   else
     work_dir = dir_reopen(get_current_work_dir());

   struct dir *cur_dir = work_dir;

   size_t size = list_size(&path_list);
   size_t process_dir = 0;

   struct file *file = NULL;
   for (temp = list_begin(&path_list); temp != list_end(&path_list); temp = list_next(temp))
     {
       process_dir++;
       pe = list_entry (temp, struct path_elem, elem);
       struct inode *inode;

       /* Check if the directory exist. */
       if (dir_lookup(cur_dir, pe->name, &inode))
         {
           if (process_dir == size)
             {
               success = dir_remove (cur_dir, pe->name);
               dir_close(cur_dir);
               break;
             }

           dir_close(cur_dir);
           cur_dir = dir_open(inode);
         } else {
           dir_close(cur_dir);
           break;
         }
     }

   /* Releasing the memory from the elements of the list. */
   release_path_elem_list(&path_list);

  return success;
}



/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");

  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");

  struct dir *root = dir_open_root();
  bool success = dir_add (root, ".", ROOT_DIR_SECTOR) &&
      dir_add(root, "..", ROOT_DIR_SECTOR);

  if (!success)
    PANIC(". and .. directories couldn't be created in the root directory.");


  free_map_close ();
  printf ("done.\n");
}
