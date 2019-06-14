#ifndef __VM_SWAP_H
#define __VM_SWAP_H

#include "vm/frame.h"
#include "devices/block.h"

/* Inits the swap partition. */
void swap_init (void);

/* Allocates the necessary sectors to store a frame and returns the initial sector. */
block_sector_t swap_alloc (void);

/* Writes the frame in the consecutive sectors that start in the given sector.  */
void swap_write (block_sector_t starting_sector, uint8_t *kpage);

/* Reads the information in the starting sector and copies it to kpage. */
void swap_read (block_sector_t starting_sector, uint8_t *kpage);

/* Frees the sectors that were used to store a frame. */
void swap_free (block_sector_t starting_sector);

/* Destroys the swap data structures. */
void swap_destroy (void);

#endif /* vm/swap.h */
