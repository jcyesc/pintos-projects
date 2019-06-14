
#include "devices/block.h"
#include "filesys/filesys.h"

/* Initializes the cache system. */
void cache_block_init(void);

/* Reads from the cache if the block is in the cache, otherwise it loads the block. */
void cache_block_read (block_sector_t sector, void *buffer);

/* Reads from the cache if the block is in the cache, otherwise it loads the block. */
void cache_block_read_bytes (block_sector_t sector, void *buffer, off_t offset, uint32_t size);

/* Writes to the cache if the block is in the cache, otherwise it loads the block. */
void cache_block_write (block_sector_t sector, const void *buffer);

/* Writes to the cache if the block is in the cache, otherwise it loads the block. */
void cache_block_write_bytes (block_sector_t sector, const void *buffer_, off_t offset, uint32_t bytes);

/* Writes the dirty cache blocks to disk. */
void cache_block_write_dirty_blocks(void);

/* Write only ZEROS in the cache block. */
void cache_block_write_zeros (block_sector_t sector);

/* Releases the resources and dump all the dirty blocks to disk. */
void cache_block_close(void);
