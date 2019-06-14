/* offset.c - test offset macro
 *
 * OFFSET
 *
 * This program uses the offsetoff macro to get the address of the
 * struct given one element of the struct.
 *
 *
 */

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

/* List element. */
struct list_elem 
  {
    struct list_elem *prev;     /* Previous list element. */
    struct list_elem *next;     /* Next list element. */
  };

struct mynode {
    int x;
    int y;
    struct list_elem elem;
};

/*
#define NULL ((void *) 0)
*/
#define offsetof1(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)

/* Returns the address of the struct that contains the given element. It uses
 * offset to achieve that.
 */
#define list_entry(LIST_ELEM, STRUCT, MEMBER)           \
        ((STRUCT *) ((uint8_t *) &(LIST_ELEM)->next     \
                     - offsetof1 (STRUCT, MEMBER.next)))

/* Returns the address of the struct that contains the given element. It uses
 * offset to achieve that.
 */
#define list_entry2(LIST_ELEM, STRUCT, MEMBER)          \
        ((STRUCT *) ((uint8_t *) LIST_ELEM              \
                     - offsetof1 (STRUCT, MEMBER)))

int main(int argc, char **argv)
{
    struct mynode node;
    struct mynode *np, *p1, *p2;

    np = &node;

    node.x = 3;
    node.y = 11;
    
    p1 = list_entry(&np->elem, struct mynode, elem);
    p2 = list_entry2(&np->elem, struct mynode, elem);

    printf("Pointer    : %08X\n", (void *) np);
    printf("list_entry : %08X\n", (void *) p1);
    printf("list_entry2: %08X\n", (void *) p2);

    // UNDERSTANDING LIST ENTRY
    // This is saying, suppose that there is something in address zero and
        // use arithmetic of pointers to get the address of the elements.
    struct mynode *ptr = ((struct mynode *) ((uint8_t *) &np->elem
        - ((size_t) &((struct mynode *) 0)->elem))); // Minus offset

    // is it really necessary the (uint8_t *) cast.
    // ptr = (struct mynode *) &np->elem;
    ptr = (struct mynode *) (uint8_t *) &np->elem;

    printf("list_entry3: %08X\n", (void *) ptr);

    return 0;
}
