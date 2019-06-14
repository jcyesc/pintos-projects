#include "filesys/cache.h"

#include <debug.h>
#include <string.h>
#include "devices/block.h"
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/synch.h"

/* This file defines a cache for 64 sectors.
 */

#define SIZE_CACHE_BLOCKS 64

struct cache_block
{
  block_sector_t sector;
  bool is_free; /* Indicates if this cache block is in used or not. */
  bool is_dirty; /* Indicates if the data has been overwritten or not. */
  int64_t timestamp; /* Number of ticks that have elapsed since the OS booted. */
  struct lock cache_block_lock;
  struct condition read_ok;
  struct condition write_ok;
  uint8_t data[BLOCK_SECTOR_SIZE];             /* Inode content. */
};

/* Cache blocks. */
struct cache_block cache_blocks[SIZE_CACHE_BLOCKS];

/* This condition variable indicates if the cache has been initialized so if the function
 * cache_block_write_dirty_blocks() is invoked before the initialization, it doesn't get executed.*/
static bool is_cache_initialized = false;

static void clean_cache_block(struct cache_block *cb);

static struct cache_block * find_cache_block(block_sector_t sector);

static void read_ahead(block_sector_t sector);

static uint32_t * find_index_cache_block_to_evict(void);

void cache_block_init(void)
{
  is_cache_initialized = true;

  int i;
  for (i = 0; i < SIZE_CACHE_BLOCKS; i++)
    {
      clean_cache_block(&cache_blocks[i]);
      lock_init(&cache_blocks[i].cache_block_lock);
      cond_init(&cache_blocks[i].read_ok);
      cond_init(&cache_blocks[i].write_ok);
    }
}

static void clean_cache_block(struct cache_block *cb)
{
  cb->sector = 0;
  cb->is_free = true;
  cb->is_dirty = false;
  cb->timestamp = 0;
}

/* It reads the given sector. Before loading this sector, it validates that it's not beyond
 * the boundary.*/
// TODO RED AHEAD is not always N + 1, check the inode functionality.
// Find if the sector belongs to an inode, an load the first file.
static void read_ahead(block_sector_t sector)
{
  if (!is_valid_sector(fs_device, sector))
    return;

  struct cache_block *cb = find_cache_block(sector); /* is sector in the buffer cache? */
  /* The sector is already loaded. */
  if (cb != NULL)
    return;

  uint32_t index = find_index_cache_block_to_evict();

  ASSERT (index <= SIZE_CACHE_BLOCKS);

  cb = &cache_blocks[index];

  lock_acquire(&cb->cache_block_lock);

  /* If the sector is dirty, dumb the data and start writing in it. */
  if (!cb->is_free && cb->is_dirty)
    {
      /* Write the data in the hard disk. */
      block_write(fs_device, cb->sector, cb->data);
    }

  /* Setting the data for this new block. */
  cb->is_free = false;
  cb->sector= sector;
  cb->is_dirty = false;
  cb->timestamp = timer_ticks();

  block_read(fs_device, sector, cb->data);

  lock_release(&cb->cache_block_lock);
}

/* Returns the cache_block that contains the given sector, otherwise NULL. */
struct cache_block * find_cache_block(block_sector_t sector)
{
  int i;
  for (i = 0; i < SIZE_CACHE_BLOCKS; i++)
    {
      if (!cache_blocks[i].is_free && cache_blocks[i].sector == sector)
        return &cache_blocks[i];
    }

  return NULL;
}

/* Finds a cache block to evict. The eviction policy is LRU (Less Recent Used). */
static uint32_t * find_index_cache_block_to_evict(void)
{
  int64_t timestamp = INT64_MAX;
  int index = 0;
  int i;
   for (i = 0; i < SIZE_CACHE_BLOCKS; i++)
     {
       if (!cache_blocks[i].is_free && cache_blocks[i].timestamp < timestamp)
         {
           index = i;
           timestamp = cache_blocks[i].timestamp;
         }
     }

  return index;
}

/* Reads from the cache if the block is in the cache, otherwise it loads the block.
 *
 * @param sector the sector where we want to read.
 * @param *buffer the buffer where the data will be placed. It has to be 512 bytes.
 * */
void cache_block_read (block_sector_t sector, void *buffer)
{
  cache_block_read_bytes (sector, buffer, 0, BLOCK_SECTOR_SIZE);
}

/* Reads from the cache if the block is in the cache, otherwise it loads the block.
 *
 * @param sector the sector where we want to read.
 * @param *buffer the buffer where the data will be placed. It has to be 512 bytes or less.
 * @param offset the offset where the  data will be read.
 * @param size number of bytes to read. It has to be 512 or less.
 * */
void cache_block_read_bytes (block_sector_t sector, void *buffer, off_t offset, uint32_t size)
{
  ASSERT(size > 0 && size <= BLOCK_SECTOR_SIZE);

  struct cache_block *cb = find_cache_block(sector); /* is sector in the buffer cache? */
  if (cb != NULL)
    {
      bool copy = false;
      lock_acquire(&cb->cache_block_lock);

      /* Check if the block continues having the sector that is required. */
      if (!cb->is_free && cb->sector == sector)
        {
          cb->timestamp = timer_ticks();
          memcpy (buffer, cb->data + offset, size);
          copy = true;
        }

      lock_release(&cb->cache_block_lock);

      if (copy)
        return;
    }

  uint32_t index = find_index_cache_block_to_evict();

  ASSERT (index <= SIZE_CACHE_BLOCKS);

  cb = &cache_blocks[index];

  lock_acquire(&cb->cache_block_lock);

  /* If the sector is dirty, dumb the data and start writing in it. */
  if (!cb->is_free && cb->is_dirty)
    {
      /* Write the data in the hard disk. */
      block_write(fs_device, cb->sector, cb->data);
    }

  /* Setting the data for this new block. */
  cb->is_free = false;
  cb->sector= sector;
  cb->is_dirty = false;
  cb->timestamp = timer_ticks();

  block_read(fs_device, sector, cb->data);

  memcpy (buffer, cb->data + offset, size);

  lock_release(&cb->cache_block_lock);

  /* Reading ahead the next sector. */
  read_ahead(++sector);
}

/* Writes to the cache if the block is in the cache, otherwise it loads the block and then
 * write on it.
 *
 * @param sector the sector where we want to write.
 * @param *buffer the buffer where the data will be placed. It has to be 512 bytes.
 * */
void cache_block_write (block_sector_t sector, const void *buffer)
{
  cache_block_write_bytes(sector, buffer, 0, BLOCK_SECTOR_SIZE);
}

/* Writes to the cache if the block is in the cache, otherwise it loads the block.
 *
 * @param sector the sector where we want to write.
 * @param *buffer the buffer where the data will be placed. It has to be 512 bytes.
 * @param offset the offset from the start  of the sector to where the data will be written.
 * @param bytes number of bytest that will be written.
 * */
void cache_block_write_bytes (block_sector_t sector, const void *buffer_, off_t offset, uint32_t bytes)
{
  ASSERT(bytes > 0 && bytes <= BLOCK_SECTOR_SIZE);

  const uint8_t *buffer = buffer_;
  struct cache_block *cb = find_cache_block(sector); /* is sector in the buffer cache? */

  if (cb != NULL)
    {
      bool write = false;
      lock_acquire(&cb->cache_block_lock);

      /* Check if the block continues having the sector that is required. */
      if (!cb->is_free && cb->sector == sector)
        {
          cb->timestamp = timer_ticks();
          cb->is_dirty = true;
          memcpy(cb->data + offset, buffer, bytes);
          write = true;
        }

      lock_release(&cb->cache_block_lock);

      if (write)
        return;
    }

  // Find a frame to evict, and write the data on it.
  uint32_t index = find_index_cache_block_to_evict();

  ASSERT(index <= SIZE_CACHE_BLOCKS);

  cb = &cache_blocks[index];

  lock_acquire(&cb->cache_block_lock);

  /* If the sector is dirty, dumb the data and start writing in it. */
  if (!cb->is_free && cb->is_dirty)
    {
      /* Write the data in the hard disk. */
      block_write(fs_device, cb->sector, cb->data);
    }

  /* Setting the data for this new block. */
  cb->is_free = false;
  cb->sector = sector;
  cb->is_dirty = true;
  cb->timestamp = timer_ticks();

  block_read(fs_device, sector, cb->data);

  memcpy(cb->data + offset, buffer, bytes);

  lock_release(&cb->cache_block_lock);
}

/* Writes ZEROS in the given sector.
 *
 * @param sector the sector where we want to write..
 * */
void cache_block_write_zeros (block_sector_t sector)
{
  struct cache_block *cb = find_cache_block(sector); /* is sector in the buffer cache? */

  if (cb != NULL)
    {
      bool write = false;
      lock_acquire(&cb->cache_block_lock);

      /* Check if the block continues having the sector that is required. */
      if (!cb->is_free && cb->sector == sector)
        {
          cb->timestamp = timer_ticks();
          cb->is_dirty = true;
          memset(cb->data, 0, BLOCK_SECTOR_SIZE);
          write = true;
        }

      lock_release(&cb->cache_block_lock);

      if (write)
        return;
    }

  // Find a frame to evict, and write the data on it.
  uint32_t index = find_index_cache_block_to_evict();

  ASSERT(index <= SIZE_CACHE_BLOCKS);

  cb = &cache_blocks[index];

  lock_acquire(&cb->cache_block_lock);

  if (!cb->is_free && cb->is_dirty)
    {
      /* Write the data in the hard disk. */
      block_write(fs_device, cb->sector, cb->data);
    }

  /* Setting the data for this new block. */
  cb->is_free = false;
  cb->sector = sector;
  cb->is_dirty = true;
  cb->timestamp = timer_ticks();

  block_read(fs_device, sector, cb->data);

  memset(cb->data, 0, BLOCK_SECTOR_SIZE);

  lock_release(&cb->cache_block_lock);
}


/* Writes the dirty cache blocks to the file system. This
 * function is called periodically to dump all the dirty sectors to disk.
 *
 * This should be done with the interrupt disables.
 *
 * */
void cache_block_write_dirty_blocks(void)
{
  if (!is_cache_initialized)
    return;

  int i;
  for (i = 0; i < SIZE_CACHE_BLOCKS; i++)
    {
      /* If the block is in used and is dirty, dump the data to disk. */
      if (!cache_blocks[i].is_free && cache_blocks[i].is_dirty)
        {
          block_write(fs_device, cache_blocks[i].sector, &cache_blocks[i].data);
          cache_blocks[i].is_dirty = false;
        }
    }
}

void cache_block_close(void)
{
  cache_block_write_dirty_blocks();
}
