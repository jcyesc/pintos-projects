#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_POINTERS 123

#define POINTERS_PER_BLOCK 128

/* There are 123 direct blocks pointers in the inode_disk pointing to blocks of 512 bytes*/
#define DIRECT_BLOCKS_SIZE 123 * 512

/* There is 1 indirect block in the inode_disk pointing to a block of 128 direct blocks pointers. */
#define INDIRECT_BLOCKS_SIZE POINTERS_PER_BLOCK * 512


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    uint32_t type;                        /* Inode type (file or directory)*/
    off_t length;                         /* File size in bytes. */
    uint32_t magic;                       /* Magic number. */
    uint32_t direct_blocks[123];          /* Points to blocks of data (62,976 bytes). */
    uint32_t indirect_block;              /* Points to block of pointers that points to blocks of data (65,536 bytes). */
    uint32_t double_indirect_block;       /* Points to block of pointers that point to block of pointers to blocks of data (8,388,608 bytes).*/
  };

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
    uint32_t indirect_blocks[POINTERS_PER_BLOCK];
    struct lock inode_lock;
  };


/* Initializes all the elements of the array to zero. */
static void initialize_array_to_zeros(uint32_t array[], uint32_t size);
static void inode_set_contiguous_sectors(struct inode_disk *disk_inode,
    uint32_t indirect_blocks[], uint32_t sectors, uint32_t start);
static void inode_release_block(block_sector_t sector);
static bool set_data_sector(struct inode *inode, off_t pos, block_sector_t sector);
static bool inode_extend_file(struct inode *inode, off_t new_size);
static bool inode_extend_sparse_file(struct inode *inode, off_t offset);
static void update_inode_disk(struct inode *inode, off_t new_size);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
  ASSERT(inode != NULL);

//  if (pos < inode->data.length)
//    {
      if (pos < DIRECT_BLOCKS_SIZE)
        {
          /* Direct blocks. */
          uint32_t sector_index = pos / BLOCK_SECTOR_SIZE;

//          printf("DIRECT INDEX [%u] POS %u\n", sector_index, pos);
          return inode->data.direct_blocks[sector_index];
        }
      else if (pos < (INDIRECT_BLOCKS_SIZE + DIRECT_BLOCKS_SIZE))
        {
          /* Indirect blocks */
          uint32_t relative_pos = pos - DIRECT_BLOCKS_SIZE;
          uint32_t sector_index = relative_pos / BLOCK_SECTOR_SIZE;
          block_sector_t sector = inode->indirect_blocks[sector_index];
//          printf("INDIRECT INDEX [%u] SECTOR %u  POS %u, RELATIVE %u\n", sector_index, sector, pos, relative_pos);
          return sector;
        }
//    }


  printf("DOUBLE INDIRECT\n");
  ASSERT(false);

  return -1;

}

/* It installs the given sector in the sector blocks. (direct, indirect or double indirect)*/
static bool
set_data_sector(struct inode *inode, off_t pos, block_sector_t sector)
{
  ASSERT(inode != NULL);

//  if (pos < inode->data.length)
//    {
      if (pos < DIRECT_BLOCKS_SIZE)
        {
          /* Direct blocks. */
          uint32_t sector_index = pos / BLOCK_SECTOR_SIZE;
//          printf("2 Allocating in direct block index [%u], sector [%u]\n", sector_index, sector);
          inode->data.direct_blocks[sector_index] = sector;

          // Setting to zero the new block sector.
          cache_block_write_zeros(sector);
          return true;
        }
      else if (pos < (INDIRECT_BLOCKS_SIZE + DIRECT_BLOCKS_SIZE))
        {
          /* Indirect blocks */
          uint32_t relative_pos = pos - DIRECT_BLOCKS_SIZE;
          uint32_t sector_index = relative_pos / BLOCK_SECTOR_SIZE;

          inode->indirect_blocks[sector_index] = sector;

          // Setting to zero the new block sector.
          cache_block_write_zeros(sector);
//          printf("3 Allocating in indirect block index [%u], sector [%u]\n", sector_index, sector);
          return true;
        }
//    }


  printf("DOUBLE INDIRECT\n");
  ASSERT(false);


  return false;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* It sets the contiguous sector numbers in the direct, indirect and double indirect blocks at the creation
 * of the inode. */
static void
inode_set_contiguous_sectors(struct inode_disk *disk_inode,
    uint32_t indirect_blocks[], uint32_t sectors, uint32_t start)
{
  /* Initializing DIRECT blocks. */
  uint32_t index;
  for (index = 0; index < sectors && index < DIRECT_POINTERS; index++)
    disk_inode->direct_blocks[index] = start + index;

  start += index;
  sectors -= index;

  /* If there are more sectors per assign, continue assigning the number of sectors to the
   * INDIRECT blocks. */
  if (sectors > 0)
    {
      for (index = 0; index < sectors && index < POINTERS_PER_BLOCK; index++)
        indirect_blocks[index] = start + index;
      start += index;
      sectors -= index;
    }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t type)
{
  // printf("inode_create() Sector [%u] Length [%d].........\n", sector, length);
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->type = type;

      size_t metadata_sectors = 1;

      uint32_t start;
      if (free_map_allocate (sectors + metadata_sectors, &start))
        {
          uint32_t metada_start = start;
          start = start + metadata_sectors;
          /* The first sectors will contain the metadata. */
          disk_inode->indirect_block = metada_start++;

          /* Indirect blocks. */
          uint32_t indirect_blocks[POINTERS_PER_BLOCK];
          initialize_array_to_zeros(indirect_blocks, POINTERS_PER_BLOCK);

          if (sectors > 0)
            {
              inode_set_contiguous_sectors(disk_inode, indirect_blocks, sectors, start);
            }

          cache_block_write (sector, disk_inode);
          cache_block_write (disk_inode->indirect_block, indirect_blocks);

          success = true;
        }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);

  cache_block_read (inode->sector, &inode->data);
  cache_block_read(inode->data.indirect_block, inode->indirect_blocks);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          /* Releasing data blocks pointed by the direct block. */
          int i;
          for (i = 0; i < DIRECT_POINTERS; i++)
            inode_release_block(inode->data.direct_blocks[i]);

          /* Releasing data blocks pointed by the indirect block. */
          for (i = 0; i < POINTERS_PER_BLOCK; i++)
            inode_release_block (inode->indirect_blocks[i]);

          /* Releasing indirect block. */
          free_map_release (inode->data.indirect_block, 1);

          /* Releasing inode disk. */
          free_map_release (inode->sector, 1);
        }

      free (inode); 
    }
}

static void
inode_release_block(block_sector_t sector)
{
  if (sector != 0)
    free_map_release(sector, 1);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open.
   It follows the Unix semantics about deleting files.
   */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      if (sector_idx == 0)
        {
          lock_acquire(&inode->inode_lock);
          if (sector_idx == 0)
            {
              inode_extend_sparse_file(inode, offset);
              sector_idx = byte_to_sector (inode, offset);
              ASSERT(sector_idx != 0);

            }
          lock_release(&inode->inode_lock);
        }


      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_block_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          cache_block_read_bytes (sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  lock_acquire(&inode->inode_lock);
  off_t new_length = 0;
  if (offset > inode->data.length)
      new_length = inode->data.length + (offset - inode->data.length) + size;
  else
      new_length = offset + size;

  if (new_length > inode->data.length)
    {
      if(!inode_extend_file(inode, new_length))
        {
          return 0;
        }
    }
  lock_release(&inode->inode_lock);

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      if (sector_idx == 0)
        {
          lock_acquire(&inode->inode_lock);
          if (sector_idx == 0)
            {
              inode_extend_sparse_file(inode, offset);
              sector_idx = byte_to_sector(inode, offset);
              ASSERT(sector_idx != 0);
            }
          lock_release(&inode->inode_lock);
        }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_block_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            {
              cache_block_write_bytes(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);
            }
          else
            {
              cache_block_write_zeros (sector_idx);
              cache_block_write_bytes(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);
            }
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

      // for( ; ;);
  return bytes_written;
}

static bool
inode_extend_sparse_file(struct inode *inode, off_t offset)
{
  bool success = false;

  // Grow the file
  uint32_t new_sector = 0;
  if (free_map_allocate(1, &new_sector))
    {
      if (!set_data_sector(inode, offset, new_sector))
        {
          free_map_release(new_sector, 1);
          goto end_sparse;
        }
    }
  else
    {
      goto end_sparse;
    }

  cache_block_write(inode->data.double_indirect_block, inode->indirect_blocks);
  cache_block_write(inode->sector, &inode->data);

  end_sparse:
    return true;
}



static bool
inode_extend_file(struct inode *inode, off_t new_size)
{
  bool success = false;
  size_t current_sectors = bytes_to_sectors (inode->data.length);
  size_t needed_sectors = bytes_to_sectors (new_size);
  size_t sectors_to_create = needed_sectors - current_sectors;

//  printf("EXTEND FILE CURRENT SECTORS [%d] NEED_SECTORS [%d]\n", current_sectors, needed_sectors);
//  printf("Old size [%u] New size[%d]\n", inode->data.length, new_size);

  if (sectors_to_create == 0)
    {
      update_inode_disk(inode, new_size);
      success = true;
      goto end_extend;
    }

  off_t offset = current_sectors * BLOCK_SECTOR_SIZE;
  size_t i;
  for (i = 0; i < sectors_to_create; i++)
    {
      // Grow the file
      uint32_t new_sector = 0;
      if (free_map_allocate (1, &new_sector))
        {
          if(!set_data_sector(inode, offset, new_sector))
            {
              free_map_release(new_sector, 1);
              goto end_extend;
            }
        }
      else
        {
          goto end_extend;
        }
    }

  update_inode_disk(inode, new_size);
  success = true;

  end_extend:
    return success;
}

static void update_inode_disk(struct inode *inode, off_t new_size)
{
  inode->data.length = new_size;
  cache_block_write(inode->data.indirect_block, inode->indirect_blocks);
  cache_block_write(inode->sector, &inode->data);
}


/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

uint32_t
inode_type(struct inode *inode)
{
  return inode->data.type;
}

int
inode_number_openers(struct inode *inode)
{
  return inode->open_cnt;
}

/* Initializes all the elements of the array to zero.
 */
static void
initialize_array_to_zeros(uint32_t array[], uint32_t size)
{
  int i;
  for (i = 0; i < size; i++)
    array[i] = 0;
}

bool inode_is_removed(struct inode *inode)
{
  return inode->removed;
}
