#ifndef BOBHASH_H_
#define BOBHASH_H_

#include <inttypes.h>

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

uint32_t BOB_Hash(uint8_t *databuffer, uint16_t databufferlength, uint32_t tinitval);


#endif /*BOBHASH_H_*/

